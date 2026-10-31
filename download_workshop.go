package steam

import (
	"context"
	"fmt"
	"log/slog"

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

	// 4. Fetch depot key.
	keyProvider := cm.NewDepotKeyProvider(c.cache, sess)
	depotKey, err := keyProvider.GetDepotKey(ctx, item.AppID, item.DepotID)
	if err != nil {
		return fmt.Errorf("workshop: depot key for item %d: %w", req.ItemID, err)
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
	requestCode, err := sess.GetManifestRequestCode(ctx, item.AppID, item.DepotID, item.ManifestGID, "public")
	if err != nil {
		c.manifestSem.Release(1)
		return fmt.Errorf("workshop: manifest request code for item %d (app %d, depot %d, manifest %d): %w",
			req.ItemID, item.AppID, item.DepotID, item.ManifestGID, err)
	}
	token, err := tp.GetToken(ctx, item.DepotID, server.Host)
	if err != nil {
		c.manifestSem.Release(1)
		return fmt.Errorf("workshop: CDN token for item %d (depot %d, %s): %w",
			req.ItemID, item.DepotID, server.Host, err)
	}
	slog.Debug("workshop: manifest request", "item", req.ItemID, "depot", item.DepotID,
		"code", requestCode, "token", token != "")

	manifest, err := cdn.DownloadManifest(ctx, c.cdnClient.HTTP(), server, item.DepotID, item.ManifestGID, depotKey, token, requestCode)
	c.manifestSem.Release(1)
	if err != nil {
		if guessedDepot {
			return fmt.Errorf("workshop: manifest for item %d: Steam lists no workshop depot for app %d, so the item was requested from depot %d, which refused it: %w",
				req.ItemID, item.AppID, item.DepotID, err)
		}
		return fmt.Errorf("workshop: manifest for item %d: %w", req.ItemID, err)
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
			data, err := cdn.DownloadChunk(ctx, c.cdnClient.HTTP(), srv, item.DepotID, cw.chunk, depotKey, tok)
			if cdn.IsUnauthorized(err) {
				// Drop the stale token before re-requesting, otherwise GetToken
				// returns the same cached value and the retry is a no-op.
				tp.InvalidateToken(item.DepotID, srv.Host)
				tok, _ = tp.GetToken(ctx, item.DepotID, srv.Host)
				data, err = cdn.DownloadChunk(ctx, c.cdnClient.HTTP(), srv, item.DepotID, cw.chunk, depotKey, tok)
			}
			if cdn.IsCorrupt(err) {
				c.cdnClient.Penalise(srv)
				if srv, err = c.cdnClient.GetServer(); err == nil {
					tok, _ = tp.GetToken(ctx, item.DepotID, srv.Host)
					data, err = cdn.DownloadChunk(ctx, c.cdnClient.HTTP(), srv, item.DepotID, cw.chunk, depotKey, tok)
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
