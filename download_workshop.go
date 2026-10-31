package steam

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/BirknerAlex/go-steam/internal/cdn"
	"github.com/BirknerAlex/go-steam/internal/cm"
	"github.com/BirknerAlex/go-steam/internal/workshop"
)

// DownloadWorkshopItem downloads a Steam Workshop item into req.TargetDir.
// An authenticated session is required; workshop items are never anonymous.
func (c *Client) DownloadWorkshopItem(ctx context.Context, req WorkshopDownloadRequest) (<-chan Progress, error) {
	if req.TargetDir == "" {
		return nil, fmt.Errorf("steam: TargetDir is required")
	}
	if c.authSession == nil {
		return nil, fmt.Errorf("steam: workshop downloads require an authenticated session (set Username/Password)")
	}

	ch := make(chan Progress, 16)
	go func() {
		defer close(ch)
		if err := c.downloadWorkshopItem(ctx, req, ch); err != nil {
			ch <- Progress{Err: err}
		}
	}()
	return ch, nil
}

func (c *Client) downloadWorkshopItem(ctx context.Context, req WorkshopDownloadRequest, ch chan<- Progress) error {
	send := func(p Progress) {
		select {
		case ch <- p:
		case <-ctx.Done():
		}
	}

	// 1. Resolve workshop item metadata.
	send(Progress{Phase: PhaseResolving})
	item, err := workshop.GetItemInfo(ctx, req.ItemID)
	if err != nil {
		return fmt.Errorf("workshop: resolve item %d: %w", req.ItemID, err)
	}

	// 1b. Legacy items predate workshop depots: Steam keeps them as a single file
	// and hands it over from a plain URL, so there is no depot or manifest to ask
	// for. Games such as Left 4 Dead 2 publish every item this way.
	if item.FileURL != "" {
		slog.Debug("workshop: single-file item", "item", req.ItemID, "url", item.FileURL)
		return c.downloadWorkshopFile(ctx, req, item, send)
	}

	// 2. Workshop items always use an authenticated session.
	sess := c.authSession

	// 3. Resolve the actual workshop depot from app info.
	// The WebAPI always returns consumer_app_id for the depot ID, but the real
	// workshop depot is listed under "workshopdepot" in the app's PICS data.
	send(Progress{Phase: PhaseManifest})
	appInfo, err := sess.GetAppInfo(ctx, item.AppID)
	if err != nil {
		return fmt.Errorf("workshop: app %d info for item %d: %w", item.AppID, req.ItemID, err)
	}
	// Old apps such as Left 4 Dead 2 list no workshopdepot in their PICS data.
	// The item's depot then falls back to the consumer app id, which is a guess
	// worth reporting rather than silently trusting.
	guessedDepot := appInfo.WorkshopDepot == 0
	if !guessedDepot {
		item.DepotID = appInfo.WorkshopDepot
	}
	slog.Debug("workshop: resolved depot", "item", req.ItemID, "app", item.AppID,
		"depot", item.DepotID, "manifest", item.ManifestGID, "workshop_depot", appInfo.WorkshopDepot)

	// 4. Fetch depot keys and the manifest. A workshop item can sit in the app's
	// workshop depot or, for games that never list one, in the consumer app's own
	// depot, so every candidate is tried rather than guessed at.
	keyProvider := cm.NewDepotKeyProvider(c.cache, sess)
	depots := make([]uint32, 0, 3)
	seen := make(map[uint32]bool, 3)
	for _, candidate := range []uint32{item.DepotID, appInfo.WorkshopDepot, item.AppID} {
		if candidate != 0 && !seen[candidate] {
			seen[candidate] = true
			depots = append(depots, candidate)
		}
	}

	// 5. Download manifest (with manifest request code for modern CDN auth).
	if err := c.manifestSem.Acquire(ctx, 1); err != nil {
		return err
	}
	server, err := c.cdnClient.GetServer()
	if err != nil {
		c.manifestSem.Release(1)
		return err
	}
	tp := newTokenProvider(c, sess, item.AppID)

	var manifest *cdn.Manifest
	var chosenDepotKey []byte
	var lastErr error
	for _, depotID := range depots {
		if ctx.Err() != nil {
			c.manifestSem.Release(1)
			return ctx.Err()
		}
		depotKey, keyErr := keyProvider.GetDepotKey(ctx, item.AppID, depotID)
		if keyErr != nil {
			lastErr = fmt.Errorf("depot %d key: %w", depotID, keyErr)
			slog.Debug("workshop: depot key failed", "depot", depotID, "err", keyErr)
			continue
		}
		// A missing request code is not fatal: some CDN cells want it, others
		// refuse a manifest that carries one, so both forms are tried. The code
		// request itself can be lost on a busy connection, and a second attempt
		// often returns the code the first one missed.
		requestCode, codeErr := sess.GetManifestRequestCode(ctx, item.AppID, depotID, item.ManifestGID, "public")
		if codeErr == nil && requestCode == 0 {
			requestCode, codeErr = sess.GetManifestRequestCode(ctx, item.AppID, depotID, item.ManifestGID, "public")
		}
		if codeErr != nil {
			lastErr = fmt.Errorf("depot %d manifest request code: %w", depotID, codeErr)
			slog.Debug("workshop: no manifest request code", "depot", depotID, "err", codeErr)
		}
		slog.Debug("workshop: manifest request code", "depot", depotID, "code", requestCode, "err", codeErr)
		codes := make([]uint64, 0, 2)
		if requestCode > 0 {
			codes = append(codes, requestCode)
		}
		codes = append(codes, 0)

		for _, code := range codes {
			fetched, fetchErr := c.fetchWorkshopManifest(ctx, tp, server, depotID, item, depotKey, code)
			// A manifest that parses but lists nothing is not a success: the depot
			// answered, but not with this item's files. Keep looking rather than
			// reporting a finished download that installs nothing.
			if fetchErr == nil && len(fetched.Files) == 0 {
				fetchErr = fmt.Errorf("manifest listed no files")
			}
			if fetchErr == nil {
				manifest = fetched
				chosenDepotKey = depotKey
				item.DepotID = depotID
				slog.Debug("workshop: manifest fetched", "item", req.ItemID, "depot", depotID,
					"code", code, "files", len(fetched.Files), "candidates", len(depots))
				break
			}
			lastErr = fmt.Errorf("depot %d manifest (request code %d): %w", depotID, code, fetchErr)
			slog.Debug("workshop: manifest attempt failed", "depot", depotID, "code", code, "err", fetchErr)
			if ctx.Err() != nil {
				break
			}
		}
		if manifest != nil {
			break
		}
	}
	c.manifestSem.Release(1)
	if manifest == nil {
		// Items that never had a depot manifest are kept in Steam's cloud storage
		// instead. Ask where the file is and fetch it straight from there.
		file, cloudErr := sess.GetUGCFile(ctx, item.AppID, item.ManifestGID)
		if cloudErr == nil && file.URL != "" {
			slog.Debug("workshop: cloud file", "item", req.ItemID,
				"filename", file.Filename, "bytes", file.FileSize)
			item.FileURL = file.URL
			if file.Filename != "" {
				item.FileName = file.Filename
			}
			return c.downloadWorkshopFile(ctx, req, item, send)
		}
		switch {
		case cloudErr != nil:
			lastErr = fmt.Errorf("cloud file: %w", cloudErr)
		case file != nil:
			lastErr = fmt.Errorf("Steam has no download URL for this item")
		}
		if guessedDepot {
			return fmt.Errorf("workshop: manifest for item %d: Steam lists no workshop depot for app %d, so depots %v were tried and each refused it: %w",
				req.ItemID, item.AppID, depots, lastErr)
		}
		return fmt.Errorf("workshop: manifest for item %d (depots %v): %w", req.ItemID, depots, lastErr)
	}

	// 5. Diff against target directory.
	send(Progress{Phase: PhaseDiffing})
	type chunkWork struct {
		file  cdn.ManifestFile
		chunk cdn.ChunkInfo
	}
	var chunks []chunkWork
	var totalBytes int64
	for _, f := range manifest.Files {
		if f.IsSymlink {
			createSymlink(req.TargetDir, f)
			continue
		}
		preallocateFile(req.TargetDir, f.Path, f.Size, f.Flags)
		for _, chunk := range f.Chunks {
			if chunkOnDisk(req.TargetDir, f.Path, chunk) {
				continue
			}
			chunks = append(chunks, chunkWork{file: f, chunk: chunk})
			totalBytes += int64(chunk.UncompressedSize)
		}
	}

	// 6. Download chunks.
	totalChunks := len(chunks)
	send(Progress{
		Phase:       PhaseDownloading,
		TotalBytes:  totalBytes,
		TotalChunks: totalChunks,
	})

	doneChunks := 0
	errCh := make(chan error, totalChunks+1)
	sem := make(chan struct{}, int(c.cfg.MaxParallelChunks))

	for _, cw := range chunks {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sem <- struct{}{}:
		}
		go func(cw chunkWork) {
			defer func() { <-sem }()

			srv, err := c.cdnClient.GetServer()
			if err != nil {
				errCh <- err
				return
			}
			tok, _ := tp.GetToken(ctx, item.DepotID, srv.Host)
			data, err := cdn.DownloadChunk(ctx, c.cdnClient.HTTP(), srv, item.DepotID, cw.chunk, chosenDepotKey, tok)
			if cdn.IsUnauthorized(err) {
				// Drop the stale token before re-requesting, otherwise GetToken
				// returns the same cached value and the retry is a no-op.
				tp.InvalidateToken(item.DepotID, srv.Host)
				tok, _ = tp.GetToken(ctx, item.DepotID, srv.Host)
				data, err = cdn.DownloadChunk(ctx, c.cdnClient.HTTP(), srv, item.DepotID, cw.chunk, chosenDepotKey, tok)
			}
			if cdn.IsCorrupt(err) {
				c.cdnClient.Penalise(srv)
				if srv, err = c.cdnClient.GetServer(); err == nil {
					tok, _ = tp.GetToken(ctx, item.DepotID, srv.Host)
					data, err = cdn.DownloadChunk(ctx, c.cdnClient.HTTP(), srv, item.DepotID, cw.chunk, chosenDepotKey, tok)
				}
			}
			if err != nil {
				c.cdnClient.Penalise(srv)
				errCh <- err
				return
			}
			errCh <- writeChunk(req.TargetDir, cw.file.Path, cw.chunk.Offset, data)
		}(cw)
	}

	for range chunks {
		if err := <-errCh; err != nil {
			return err
		}
		doneChunks++
		send(Progress{
			Phase:       PhaseDownloading,
			TotalBytes:  totalBytes,
			TotalChunks: totalChunks,
			DoneChunks:  doneChunks,
		})
	}

	send(Progress{Phase: PhaseComplete})
	return nil
}

// fetchWorkshopManifest makes one manifest request, fetching a CDN token for the
// depot in question first. A token error is reported rather than sent on as an
// empty token, which would come back as an authorization failure further down.
func (c *Client) fetchWorkshopManifest(
	ctx context.Context,
	tp *tokenProviderWrapper,
	server *cdn.Server,
	depotID uint32,
	item *workshop.Item,
	depotKey []byte,
	requestCode uint64,
) (*cdn.Manifest, error) {
	token, err := tp.GetToken(ctx, depotID, server.Host)
	if err != nil {
		return nil, fmt.Errorf("CDN token: %w", err)
	}
	return cdn.DownloadManifest(ctx, c.cdnClient.HTTP(), server, depotID, item.ManifestGID, depotKey, token, requestCode)
}



// downloadWorkshopFile fetches a single-file Workshop item. These items live in
// Steam's UGC storage rather than a depot, so the whole item arrives as one
// download and lands in TargetDir under the name it was published with.
func (c *Client) downloadWorkshopFile(ctx context.Context, req WorkshopDownloadRequest,
	item *workshop.Item, send func(Progress)) error {
	name := safeWorkshopFileName(item.FileName)
	if name == "" {
		name = fmt.Sprintf("%d.vpk", item.ItemID)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, item.FileURL, nil)
	if err != nil {
		return fmt.Errorf("workshop: file request for item %d: %w", req.ItemID, err)
	}
	resp, err := c.cdnClient.HTTP().Do(request)
	if err != nil {
		return fmt.Errorf("workshop: file download for item %d: %w", req.ItemID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("workshop: item %d file HTTP %d from %s",
			req.ItemID, resp.StatusCode, item.FileURL)
	}

	total := resp.ContentLength
	if total <= 0 {
		total = item.FileSize
	}

	path := filepath.Join(req.TargetDir, name)
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("workshop: item %d file %s: %w", req.ItemID, name, err)
	}
	defer file.Close()

	send(Progress{Phase: PhaseDownloading, TotalBytes: total, CurrentFile: name})

	buf := make([]byte, 256*1024)
	var done int64
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := file.Write(buf[:n]); writeErr != nil {
				return fmt.Errorf("workshop: item %d file %s: %w", req.ItemID, name, writeErr)
			}
			done += int64(n)
			send(Progress{Phase: PhaseDownloading, TotalBytes: total,
				DoneBytes: done, CurrentFile: name})
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return fmt.Errorf("workshop: item %d file %s: %w", req.ItemID, name, readErr)
		}
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("workshop: item %d file %s: %w", req.ItemID, name, err)
	}
	slog.Debug("workshop: single-file item written", "item", req.ItemID, "file", name, "bytes", done)
	send(Progress{Phase: PhaseComplete})
	return nil
}

// safeWorkshopFileName keeps a published name from escaping the target folder.
func safeWorkshopFileName(name string) string {
	name = strings.TrimSpace(strings.ReplaceAll(name, "\\", "/"))
	name = filepath.Base(name)
	if name == "." || name == ".." || name == "/" {
		return ""
	}
	return name
}
