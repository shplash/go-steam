package steam

import (
	"context"
	"crypto/sha1" //nolint:gosec // SHA1 is mandated by the Steam protocol for chunk verification
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"github.com/BirknerAlex/go-steam/internal/cdn"
	"github.com/BirknerAlex/go-steam/internal/cm"
)

// DownloadApp downloads (or updates) the content of a Steam app.
// It returns a channel of Progress events; the channel is closed when
// the download completes or fails.
//
// The caller must drain the channel.  Cancelling ctx stops the download and
// closes the channel.
func (c *Client) DownloadApp(ctx context.Context, req AppDownloadRequest) (<-chan Progress, error) {
	if req.TargetDir == "" {
		return nil, fmt.Errorf("steam: TargetDir is required")
	}
	if req.Branch == "" {
		req.Branch = "public"
	}
	if err := validateOSFilter(req); err != nil {
		return nil, err
	}

	ch := make(chan Progress, 16)
	go func() {
		defer close(ch)
		if err := c.downloadApp(ctx, req, ch); err != nil {
			ch <- Progress{Err: err}
		}
	}()
	return ch, nil
}

func (c *Client) downloadApp(ctx context.Context, req AppDownloadRequest, ch chan<- Progress) error {
	send := func(p Progress) {
		select {
		case ch <- p:
		case <-ctx.Done():
		}
	}

	// 1. Fetch app info from PICS.
	// Use the authenticated session when available: PICS access tokens are only
	// granted to sessions that hold a license for the app, so the anonymous
	// session receives no manifests for paid/private apps.
	send(Progress{Phase: PhaseResolving})
	infoSess := c.anonSession
	if c.authSession != nil {
		infoSess = c.authSession
	}
	appInfo, err := infoSess.GetAppInfo(ctx, req.AppID)
	if err != nil {
		return fmt.Errorf("download app: get app info: %w", err)
	}

	// 2. Select depots to download.
	depots := selectDepots(appInfo, req, c.authSession != nil)
	if len(depots) == 0 {
		return fmt.Errorf("download app: no eligible depots for app %d", req.AppID)
	}

	// 3. Determine session (anonymous vs authenticated).
	sess, err := c.sessionForDepots(depots)
	if err != nil {
		return err
	}

	// 4. Resolve manifest GIDs and fetch depot keys.
	type depotWork struct {
		info        *cm.DepotInfo
		manifestGID uint64
		depotKey    []byte
	}

	send(Progress{Phase: PhaseManifest})
	keyProvider := cm.NewDepotKeyProvider(c.cache, sess)

	// Resolve per-branch decryption keys for password-protected branches.  Only
	// non-public branches carry encrypted manifest GIDs; the public branch is
	// always plaintext, so skip the round-trip there.
	var branchKeys map[string][]byte
	if req.BranchPassword != "" && req.Branch != "public" {
		branchKeys, err = sess.CheckAppBetaPassword(ctx, req.AppID, req.BranchPassword)
		if err != nil {
			return fmt.Errorf("download app: branch password for %q: %w", req.Branch, err)
		}
	}

	var works []depotWork
	for _, d := range depots {
		gid, err := resolveManifestGID(d, req.Branch, branchKeys)
		if err != nil {
			continue // depot has no manifest for this branch; skip
		}
		key, err := keyProvider.GetDepotKey(ctx, req.AppID, d.DepotID)
		if err != nil {
			if errors.Is(err, cm.ErrDepotKeyDenied) {
				continue // not accessible with current credentials; skip
			}
			return fmt.Errorf("download app: depot key %d: %w", d.DepotID, err)
		}
		works = append(works, depotWork{info: d, manifestGID: gid, depotKey: key})
	}
	if len(works) == 0 {
		return fmt.Errorf("download app: no depots with manifests for app %d branch %q", req.AppID, req.Branch)
	}

	// 5. Download and parse manifests.
	send(Progress{Phase: PhaseManifest})
	var manifests []*cdn.Manifest
	for _, w := range works {
		if err := c.manifestSem.Acquire(ctx, 1); err != nil {
			return err
		}
		server, err := c.cdnClient.GetServer()
		if err != nil {
			c.manifestSem.Release(1)
			return err
		}
		// Get a manifest request code (modern Steam CDN auth; may return 0 for anonymous).
		requestCode, _ := sess.GetManifestRequestCode(ctx, req.AppID, w.info.DepotID, w.manifestGID, req.Branch)
		token, _ := newTokenProvider(c, sess, req.AppID).GetToken(ctx, w.info.DepotID, server.Host)
		m, err := cdn.DownloadManifest(ctx, c.cdnClient.HTTP(), server, w.info.DepotID, w.manifestGID, w.depotKey, token, requestCode)
		c.manifestSem.Release(1)
		if err != nil {
			return fmt.Errorf("download app: manifest depot %d: %w", w.info.DepotID, err)
		}
		manifests = append(manifests, m)
	}

	// 6. Diff: build chunk work list.
	send(Progress{Phase: PhaseDiffing})
	type chunkWork struct {
		depotWork depotWork
		file      cdn.ManifestFile
		chunk     cdn.ChunkInfo
	}
	var chunks []chunkWork
	var totalBytes, totalChunks int64
	for i, m := range manifests {
		for _, f := range m.Files {
			if f.IsSymlink {
				if !req.ValidateOnly {
					createSymlink(req.TargetDir, f)
				}
				continue
			}
			for _, chunk := range f.Chunks {
				if chunkOnDisk(req.TargetDir, f.Path, chunk) {
					continue // already on disk and SHA1-verified
				}
				if req.ValidateOnly {
					continue // validate mode: report only, don't download missing/corrupt chunks
				}
				chunks = append(chunks, chunkWork{
					depotWork: works[i],
					file:      f,
					chunk:     chunk,
				})
				totalBytes += int64(chunk.UncompressedSize)
				totalChunks++
			}
		}
	}

	// 7. Download chunks concurrently.
	slog.Debug("download: work list built", "chunks", len(chunks), "total_bytes", totalBytes)
	send(Progress{
		Phase:       PhaseDownloading,
		TotalBytes:  totalBytes,
		TotalChunks: int(totalChunks),
	})

	var doneBytes int64
	var doneChunks int

	// Pre-allocate files.
	if !req.ValidateOnly {
		for _, m := range manifests {
			for _, f := range m.Files {
				if !f.IsSymlink {
					preallocateFile(req.TargetDir, f.Path, f.Size, f.Flags)
				}
			}
		}
	}

	// Download with bounded parallelism.
	//
	// The spawner runs in its own goroutine so the collector can run concurrently
	// and update progress as chunks complete (not only after all are spawned).
	// A child context lets us cancel in-flight downloads on the first error.
	type chunkResult struct {
		bytes int64
		err   error
	}
	resultCh := make(chan chunkResult, 256)
	dlCtx, cancelDL := context.WithCancel(ctx)
	defer cancelDL()

	sem := make(chan struct{}, int(c.cfg.MaxParallelChunks))
	// Single shared token provider so the negative/positive cache is effective
	// across all concurrent chunk goroutines.
	tp := newTokenProvider(c, sess, req.AppID)

	go func() {
		for _, cw := range chunks {
			select {
			case <-dlCtx.Done():
				return
			case sem <- struct{}{}:
			}
			go func(cw chunkWork) {
				defer func() { <-sem }()

				server, err := c.cdnClient.GetServer()
				if err != nil {
					select {
					case resultCh <- chunkResult{err: err}:
					case <-dlCtx.Done():
					}
					return
				}
				token, _ := tp.GetToken(dlCtx, cw.depotWork.info.DepotID, server.Host)

				data, err := cdn.DownloadChunk(dlCtx, c.cdnClient.HTTP(), server, cw.depotWork.info.DepotID,
					cw.chunk, cw.depotWork.depotKey, token)
				if cdn.IsUnauthorized(err) {
					tp.InvalidateToken(cw.depotWork.info.DepotID, server.Host)
					token, _ = tp.GetToken(dlCtx, cw.depotWork.info.DepotID, server.Host)
					data, err = cdn.DownloadChunk(dlCtx, c.cdnClient.HTTP(), server, cw.depotWork.info.DepotID,
						cw.chunk, cw.depotWork.depotKey, token)
				}
				if cdn.IsCorrupt(err) {
					// Penalise the server that sent corrupt data and retry from a fresh one.
					c.cdnClient.Penalise(server)
					server, err = c.cdnClient.GetServer()
					if err == nil {
						token, _ = tp.GetToken(dlCtx, cw.depotWork.info.DepotID, server.Host)
						data, err = cdn.DownloadChunk(dlCtx, c.cdnClient.HTTP(), server, cw.depotWork.info.DepotID,
							cw.chunk, cw.depotWork.depotKey, token)
					}
				}
				if err != nil {
					c.cdnClient.Penalise(server)
					select {
					case resultCh <- chunkResult{err: fmt.Errorf("chunk %s: %w", hex.EncodeToString(cw.chunk.SHA1[:4]), err)}:
					case <-dlCtx.Done():
					}
					return
				}

				if !req.ValidateOnly {
					if err := writeChunk(req.TargetDir, cw.file.Path, cw.chunk.Offset, data); err != nil {
						select {
						case resultCh <- chunkResult{err: err}:
						case <-dlCtx.Done():
						}
						return
					}
				}
				select {
				case resultCh <- chunkResult{bytes: int64(cw.chunk.UncompressedSize)}:
				case <-dlCtx.Done():
				}
			}(cw)
		}
	}()

	// Collect results and report progress as chunks complete.
	for i := 0; i < len(chunks); i++ {
		var result chunkResult
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result = <-resultCh:
		}
		if result.err != nil {
			return result.err
		}
		doneChunks++
		doneBytes += result.bytes
		select {
		case ch <- Progress{
			Phase:       PhaseDownloading,
			TotalBytes:  totalBytes,
			DoneBytes:   doneBytes,
			TotalChunks: int(totalChunks),
			DoneChunks:  doneChunks,
		}:
		default:
		}
	}

	// Restore the executable bit on the platform's launch script/binary.
	// Depot manifests frequently don't set the per-file Executable flag on the
	// actual game/server binary (observed even on the primary launch script),
	// so fall back to PICS "config.launch", which reliably names the file
	// Steam itself would run for this platform.
	if !req.ValidateOnly {
		restoreLaunchExecutableBits(req.TargetDir, appInfo.LaunchEntries, effectiveOSFilter(req))
	}

	send(Progress{Phase: PhaseComplete})
	return nil
}

// ---- helpers ----------------------------------------------------------------

func selectDepots(appInfo *cm.AppInfo, req AppDownloadRequest, hasAuth bool) []*cm.DepotInfo {
	osFilter := effectiveOSFilter(req)

	var result []*cm.DepotInfo
	for _, d := range appInfo.Depots {
		if len(req.DepotIDs) > 0 && !containsUint32(req.DepotIDs, d.DepotID) {
			continue
		}
		if !hasAuth && !d.AllowAnonymous {
			continue
		}
		if osFilter != "" && d.OSList != "" && !strings.Contains(d.OSList, osFilter) {
			continue
		}
		result = append(result, d)
	}
	return result
}

// steamOSForGOOS maps a Go runtime.GOOS value to the OS name Steam uses in
// depot "oslist" metadata ("windows", "macos", "linux"). Unknown values
// return "" so callers fall back to no OS filtering.
func steamOSForGOOS(goos string) string {
	switch goos {
	case "windows":
		return "windows"
	case "darwin":
		return "macos"
	case "linux":
		return "linux"
	default:
		return ""
	}
}

// effectiveOSFilter resolves req.OS to the Steam OS name actually used for
// depot and launch-entry matching: the explicit value if set, otherwise the
// platform this process is running on (see steamOSForGOOS). Downloading
// depots for every OS at once (the old default) mixes platform-specific
// binaries under the same paths, corrupting the install -- e.g. Linux and
// Windows depots both writing files that collide or that the wrong
// platform's binary tries to load.
//
// Callers on the DownloadApp path can assume the result is one of Steam's
// three supported platforms: DownloadApp calls validateOSFilter up front and
// fails before starting any depot selection or download if it isn't.
func effectiveOSFilter(req AppDownloadRequest) string {
	return resolveOSFilter(req.OS, runtime.GOOS)
}

// validSteamOS lists the platform names Steam's depot ("oslist") and launch
// ("config.launch") metadata use. There is no fourth option: unlike GOOS,
// Steam depots only ever target these three.
var validSteamOS = map[string]bool{"windows": true, "linux": true, "macos": true}

// resolveOSFilter resolves an OS filter: the explicit value if set, otherwise
// the Steam OS name for goos (see steamOSForGOOS). goos is threaded through
// as a parameter (rather than reading runtime.GOOS directly) so the resolution
// and validation logic can be exercised for platforms other than the one
// running the tests.
func resolveOSFilter(reqOS, goos string) string {
	if reqOS != "" {
		return reqOS
	}
	return steamOSForGOOS(goos)
}

// validateOSFilterFor validates the OS filter that would be resolved for
// (reqOS, goos), without touching runtime.GOOS -- used by validateOSFilter
// (with goos=runtime.GOOS) and directly by tests for platforms other than
// whatever GOOS the tests happen to run under.
func validateOSFilterFor(reqOS, goos string) error {
	if validSteamOS[resolveOSFilter(reqOS, goos)] {
		return nil
	}
	if reqOS == "" {
		return fmt.Errorf("steam: cannot auto-detect a Steam-supported OS filter for runtime platform %q; set AppDownloadRequest.OS explicitly to \"windows\", \"linux\", or \"macos\"", goos)
	}
	return fmt.Errorf("steam: invalid AppDownloadRequest.OS %q; must be \"windows\", \"linux\", or \"macos\"", reqOS)
}

// validateOSFilter rejects an AppDownloadRequest whose OS filter -- explicit
// or auto-detected from runtime.GOOS -- doesn't resolve to one of Steam's
// three supported platforms. Without this, an empty OS on an unsupported
// GOOS (e.g. freebsd) would silently fall back to "no OS filtering" and
// download every platform's depots into the same target dir.
func validateOSFilter(req AppDownloadRequest) error {
	return validateOSFilterFor(req.OS, runtime.GOOS)
}

// restoreLaunchExecutableBits sets the executable bit on the files PICS
// "config.launch" names as this platform's launch executable(s). Depot
// manifests frequently omit the per-file Executable flag on the actual
// game/server binary or launch script, so this is a more reliable source of
// which file needs +x. Missing files (e.g. a launch entry for a platform
// that wasn't downloaded) are silently skipped. No-op for Windows, which has
// no concept of a unix executable bit.
func restoreLaunchExecutableBits(targetDir string, entries []cm.LaunchEntry, osFilter string) {
	if osFilter == "windows" || runtime.GOOS == "windows" {
		return
	}
	for _, le := range entries {
		if le.OSList != "" && osFilter != "" && !strings.Contains(le.OSList, osFilter) {
			continue
		}
		absPath := filepath.Join(targetDir, filepath.FromSlash(le.Executable))
		info, err := os.Stat(absPath)
		if err != nil || info.IsDir() {
			continue
		}
		_ = os.Chmod(absPath, info.Mode()|0o111)
	}
}

// resolveManifestGID determines the manifest GID for a depot on the requested
// branch.  Plaintext branches are looked up directly; password-protected
// branches carry an encrypted GID blob that is decrypted with the per-branch key
// from CheckAppBetaPassword (passed in via branchKeys).
func resolveManifestGID(d *cm.DepotInfo, branch string, branchKeys map[string][]byte) (uint64, error) {
	if gid, ok := d.ManifestGIDs[branch]; ok {
		return gid, nil
	}
	// Password-protected branch: decrypt the encrypted GID blob with the
	// per-branch key.  Surface a clear error if the key is missing (no/invalid
	// password) rather than silently falling back to the public branch.
	if blob, ok := d.EncryptedManifestGIDs[branch]; ok {
		key, ok := branchKeys[branch]
		if !ok {
			return 0, fmt.Errorf("branch %q is password-protected: missing or invalid branch password", branch)
		}
		gid, err := cm.DecryptManifestGID(blob, key)
		if err != nil {
			return 0, fmt.Errorf("branch %q: %w", branch, err)
		}
		return gid, nil
	}
	if gid, ok := d.ManifestGIDs["public"]; ok {
		return gid, nil
	}
	return 0, fmt.Errorf("no manifest for branch %q", branch)
}

// chunkOnDisk returns true when the chunk's bytes are already present on disk
// and pass SHA1 verification.
func chunkOnDisk(targetDir, filePath string, chunk cdn.ChunkInfo) bool {
	absPath := filepath.Join(targetDir, filepath.FromSlash(filePath))
	f, err := os.Open(absPath)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, chunk.UncompressedSize)
	if _, err := io.ReadFull(io.NewSectionReader(f, chunk.Offset, int64(chunk.UncompressedSize)), buf); err != nil {
		return false
	}
	//nolint:gosec
	h := sha1.New()
	h.Write(buf)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum) == hex.EncodeToString(chunk.SHA1)
}

func preallocateFile(targetDir, relPath string, size int64, flags uint32) {
	absPath := filepath.Join(targetDir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return
	}
	perm := os.FileMode(0o644)
	if flags&0x20 != 0 { // EDepotFileFlag.Executable = 32
		perm = 0o755
	}
	f, err := os.OpenFile(absPath, os.O_CREATE|os.O_WRONLY, perm)
	if err != nil {
		return
	}
	defer f.Close()
	if stat, err := f.Stat(); err == nil && stat.Size() < size {
		_ = f.Truncate(size)
	}
	// Apply permissions even if file already existed from a prior run.
	_ = os.Chmod(absPath, perm)
}

func writeChunk(targetDir, relPath string, offset int64, data []byte) error {
	absPath := filepath.Join(targetDir, filepath.FromSlash(relPath))
	f, err := os.OpenFile(absPath, os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("write chunk: open %s: %w", relPath, err)
	}
	defer f.Close()
	if _, err := f.WriteAt(data, offset); err != nil {
		return fmt.Errorf("write chunk: write %s: %w", relPath, err)
	}
	return nil
}

func createSymlink(targetDir string, f cdn.ManifestFile) {
	absPath := filepath.Join(targetDir, filepath.FromSlash(f.Path))
	_ = os.MkdirAll(filepath.Dir(absPath), 0o755)
	_ = os.Remove(absPath)
	_ = os.Symlink(f.SymlinkTarget, absPath)
}

func containsUint32(s []uint32, v uint32) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func defaultCachePath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".cache", "go-steam")
	}
	return filepath.Join(os.TempDir(), "go-steam-cache")
}

// newTokenProvider creates a CDN token provider wrapping the CM session.
// The returned wrapper holds a single cdn.TokenProvider so the negative/positive
// token cache is shared across all callers (important for performance with many
// concurrent chunk goroutines).
func newTokenProvider(c *Client, sess *cm.Session, appID uint32) *tokenProviderWrapper {
	return &tokenProviderWrapper{
		inner: cdn.NewTokenProvider(c.cache, sess, appID),
	}
}

type tokenProviderWrapper struct {
	inner *cdn.TokenProvider
}

func (t *tokenProviderWrapper) GetToken(ctx context.Context, depotID uint32, host string) (string, error) {
	return t.inner.GetToken(ctx, depotID, host)
}

func (t *tokenProviderWrapper) TokenUnavailable(depotID uint32, host string) error {
	return t.inner.TokenUnavailable(depotID, host)
}

func (t *tokenProviderWrapper) InvalidateToken(depotID uint32, host string) {
	t.inner.InvalidateToken(depotID, host)
}

// _ ensures cm.Session implements the cdn.CMSession interface at compile time.
var _ cdn.CMSession = (*cm.Session)(nil)

