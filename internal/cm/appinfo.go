package cm

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BirknerAlex/go-steam/internal/proto"
)

// DepotInfo holds the manifest metadata for one depot extracted from PICS app info.
type DepotInfo struct {
	DepotID        uint32
	AllowAnonymous bool
	// OSList is the comma-separated list of target OS names from the depot config (e.g. "linux", "windows,linux").
	// Empty means the depot is OS-agnostic.
	OSList string
	// ManifestGIDs maps branch name → manifest GID (for public depots).
	ManifestGIDs map[string]uint64
	// EncryptedManifestGIDs maps branch name → the hex-encoded encrypted manifest
	// GID blob (password-protected branches).  The blob is AES-256-ECB encrypted
	// with the per-branch key returned by CheckAppBetaPassword; once decrypted its
	// first 8 bytes are the little-endian manifest GID.  See DecryptManifestGID.
	EncryptedManifestGIDs map[string]string
}

// LaunchEntry describes one entry from PICS "config.launch" -- the
// executable Steam itself would run for a given platform. Depot manifests
// frequently omit the per-file Executable flag (EDepotFileFlag 0x20) even on
// the actual server/game binary, so this is the more reliable source for
// which file needs the executable bit set after download.
type LaunchEntry struct {
	// Executable is the path (relative to the install dir) of the binary or
	// script Steam launches, e.g. "PalServer.sh".
	Executable string
	// OSList is the comma-separated target OS list from this launch entry's
	// own "config.oslist" (e.g. "linux"). Empty means unrestricted.
	OSList string
}

// AppInfo holds the PICS product info for a Steam app.
type AppInfo struct {
	AppID         uint32
	Type          string // "game", "tool", "server", etc.
	Depots        map[uint32]*DepotInfo
	WorkshopDepot uint32 // depot used for workshop content; 0 if not set
	// BranchNames lists the app's branches from PICS ("public", "42.19", …) so a
	// beta-branch workshop item can be looked for under the branch that holds it.
	BranchNames []string
	// LaunchEntries lists the app's PICS "config.launch" entries, if any.
	LaunchEntries []LaunchEntry
	fetched       time.Time
}

// AppInfoCache caches PICS responses in memory with a short TTL.
type AppInfoCache struct {
	mu    sync.RWMutex
	items map[uint32]*AppInfo
}

var globalAppInfoCache = &AppInfoCache{items: make(map[uint32]*AppInfo)}

const appInfoTTL = 5 * time.Minute

func (c *AppInfoCache) get(appID uint32) *AppInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	info, ok := c.items[appID]
	if !ok || time.Since(info.fetched) > appInfoTTL {
		return nil
	}
	return info
}

func (c *AppInfoCache) set(info *AppInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	info.fetched = time.Now()
	c.items[info.AppID] = info
}

// GetAppInfo fetches and returns PICS product info for the given app ID.
// Results are cached in memory for 5 minutes.
func (s *Session) GetAppInfo(ctx context.Context, appID uint32) (*AppInfo, error) {
	if cached := globalAppInfoCache.get(appID); cached != nil {
		return cached, nil
	}

	// First fetch an access token so we can query private apps if needed.
	token, err := s.getAccessToken(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("appinfo: access token: %w", err)
	}
	s.log.Debug("PICS access token", "app", appID, "token", token)

	req := proto.CMsgClientPICSProductInfoRequest{
		Apps: []proto.PICSAppInfo{
			{Appid: appID, AccessToken: token},
		},
	}
	body := req.Marshal()

	jobID, err := s.dispatch.Send(ctx, proto.EMsgClientPICSProductInfoRequest, body)
	if err != nil {
		return nil, fmt.Errorf("appinfo: send: %w", err)
	}

	// PICS may send multiple response packets if ResponsePending is set.
	var allApps []proto.PICSAppResult
	for {
		pkt, err := s.dispatch.Await(ctx, jobID)
		if err != nil {
			return nil, fmt.Errorf("appinfo: await: %w", err)
		}
		var resp proto.CMsgClientPICSProductInfoResponse
		if err := resp.Unmarshal(pkt.Body); err != nil {
			return nil, fmt.Errorf("appinfo: unmarshal: %w", err)
		}
		allApps = append(allApps, resp.Apps...)
		if !resp.ResponsePending {
			break
		}
		// re-register for the next packet with the same job ID
		// (the dispatcher delivers subsequent packets under the same target job ID)
	}

	for _, app := range allApps {
		if app.Appid == appID {
			s.log.Debug("PICS app result", "app", appID, "missing_token", app.MissingToken, "buffer_len", len(app.Buffer))
			info, err := parseAppInfo(s.log, app)
			if err != nil {
				return nil, fmt.Errorf("appinfo: parse VDF: %w", err)
			}
			globalAppInfoCache.set(info)
			return info, nil
		}
	}
	return nil, fmt.Errorf("appinfo: app %d not found in PICS response", appID)
}

// getAccessToken fetches a PICS access token for appID (needed for non-public apps).
func (s *Session) getAccessToken(ctx context.Context, appID uint32) (uint64, error) {
	req := proto.CMsgClientPICSAccessTokenRequest{AppIDs: []uint32{appID}}
	body := req.Marshal()

	jobID, err := s.dispatch.Send(ctx, proto.EMsgClientPICSAccessTokenRequest, body)
	if err != nil {
		return 0, err
	}
	pkt, err := s.dispatch.Await(ctx, jobID)
	if err != nil {
		return 0, err
	}
	var resp proto.CMsgClientPICSAccessTokenResponse
	if err := resp.Unmarshal(pkt.Body); err != nil {
		return 0, err
	}
	for _, t := range resp.AppAccessTokens {
		if t.AppID == appID {
			return t.AccessToken, nil
		}
	}
	for _, id := range resp.AppDeniedTokens {
		if id == appID {
			s.log.Debug("PICS access token denied", "app", appID)
			return 0, nil
		}
	}
	return 0, nil // no token needed (public app)
}

// parseAppInfo parses the VDF-encoded Buffer from a PICS result into AppInfo.
// The PICS buffer is a text KeyValues document (Valve VDF format).
func parseAppInfo(log *slog.Logger, r proto.PICSAppResult) (*AppInfo, error) {
	info := &AppInfo{
		AppID:  r.Appid,
		Depots: make(map[uint32]*DepotInfo),
	}
	if len(r.Buffer) == 0 {
		return info, nil
	}

	kv, err := parseTextKV(r.Buffer)
	if err != nil {
		log.Debug("PICS VDF parse error", "app", r.Appid, "err", err)
		return info, nil // non-fatal; partial parse is still useful
	}

	// The text VDF top-level key is "appinfo"; drill into it.
	var appKV map[string]any
	for _, v := range kv {
		if m, ok := v.(map[string]any); ok {
			appKV = m
			break
		}
	}
	if appKV == nil {
		prefix := r.Buffer
		if len(prefix) > 64 {
			prefix = prefix[:64]
		}
		log.Debug("PICS VDF: no top-level map", "app", r.Appid, "prefix", fmt.Sprintf("%q", string(prefix)))
		return info, nil
	}

	if config, ok := appKV["config"].(map[string]any); ok {
		info.LaunchEntries = parseLaunchSection(config["launch"])
	}

	if common, ok := appKV["common"]; ok {
		if obj, ok := common.(map[string]any); ok {
			if t, ok := obj["type"].(string); ok {
				info.Type = t
			}
		}
	}

	if depots, ok := appKV["depots"]; ok {
		if dmap, ok := depots.(map[string]any); ok {
			if ws, ok := dmap["workshopdepot"].(string); ok {
				if id, err := strconv.ParseUint(ws, 10, 32); err == nil {
					info.WorkshopDepot = uint32(id)
				}
			}
			if branches, ok := dmap["branches"].(map[string]any); ok {
				for name := range branches {
					info.BranchNames = append(info.BranchNames, name)
				}
				sort.Strings(info.BranchNames)
			}
			for key, val := range dmap {
				var depotID uint32
				if _, err := fmt.Sscanf(key, "%d", &depotID); err != nil {
					continue
				}
				dinfo := &DepotInfo{
					DepotID:               depotID,
					ManifestGIDs:          make(map[string]uint64),
					EncryptedManifestGIDs: make(map[string]string),
				}
				if obj, ok := val.(map[string]any); ok {
					if _, ok := obj["dlcappid"]; !ok {
						dinfo.AllowAnonymous = true
					}
					if config, ok := obj["config"]; ok {
						if cfg, ok := config.(map[string]any); ok {
							if osList, ok := cfg["oslist"].(string); ok {
								dinfo.OSList = osList
							}
						}
					}
					parseManifestSection(obj["manifests"], dinfo.ManifestGIDs)
					parseEncryptedManifestSection(obj["encryptedmanifests"], dinfo.EncryptedManifestGIDs)
				}
				log.Debug("PICS depot", "app", r.Appid, "depot", depotID, "oslist", dinfo.OSList, "allow_anon", dinfo.AllowAnonymous, "manifests", dinfo.ManifestGIDs)
				info.Depots[depotID] = dinfo
			}
		}
	} else {
		log.Debug("PICS VDF: no depots section", "app", r.Appid, "top_keys", fmt.Sprintf("%v", kvKeys(appKV)))
	}

	return info, nil
}

func kvKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// parseLaunchSection parses "config.launch" -- a map of numeric index →
// launch entry (executable, arguments, per-entry "config.oslist", ...).
// Entries are returned sorted by index for deterministic output.
func parseLaunchSection(section any) []LaunchEntry {
	lobj, ok := section.(map[string]any)
	if !ok {
		return nil
	}
	indices := make([]string, 0, len(lobj))
	for idx := range lobj {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		ni, erri := strconv.Atoi(indices[i])
		nj, errj := strconv.Atoi(indices[j])
		if erri == nil && errj == nil {
			return ni < nj
		}
		return indices[i] < indices[j]
	})

	var entries []LaunchEntry
	for _, idx := range indices {
		entry, ok := lobj[idx].(map[string]any)
		if !ok {
			continue
		}
		exe, _ := entry["executable"].(string)
		if exe == "" {
			continue
		}
		var osList string
		if cfg, ok := entry["config"].(map[string]any); ok {
			osList, _ = cfg["oslist"].(string)
		}
		entries = append(entries, LaunchEntry{Executable: exe, OSList: osList})
	}
	return entries
}

// parseManifestSection fills gids from a "manifests" or "encryptedmanifests" value.
// Handles two formats:
//
//	New: "branch" { "gid" "1234" ... }
//	Old: "branch" "1234"
func parseManifestSection(section any, gids map[string]uint64) {
	mobj, ok := section.(map[string]any)
	if !ok {
		return
	}
	for branch, val := range mobj {
		switch v := val.(type) {
		case map[string]any:
			if gid, ok := extractUint64(v["gid"]); ok {
				gids[branch] = gid
			}
		case string:
			if gid, err := strconv.ParseUint(v, 10, 64); err == nil {
				gids[branch] = gid
			}
		}
	}
}

// parseEncryptedManifestSection fills blobs from an "encryptedmanifests" value.
// Unlike plaintext manifests, the per-branch "gid" here is a hex-encoded,
// AES-encrypted blob (not a numeric GID), so it is kept verbatim as a string.
//
//	"branch" { "gid" "<hex blob>" ... }
func parseEncryptedManifestSection(section any, blobs map[string]string) {
	mobj, ok := section.(map[string]any)
	if !ok {
		return
	}
	for branch, val := range mobj {
		obj, ok := val.(map[string]any)
		if !ok {
			continue
		}
		if gid, ok := obj["gid"].(string); ok && gid != "" {
			blobs[branch] = gid
		}
	}
}

// extractUint64 returns the uint64 value from v, handling both uint64 (binary VDF)
// and string (text VDF) representations.
func extractUint64(v any) (uint64, bool) {
	switch x := v.(type) {
	case uint64:
		return x, true
	case string:
		n, err := strconv.ParseUint(x, 10, 64)
		return n, err == nil
	}
	return 0, false
}

// ---- text VDF parser --------------------------------------------------------
//
// The PICS product info buffer uses Valve's text KeyValues format:
//
//	"key" "value"
//	"key"
//	{
//	    "nested_key" "nested_value"
//	}
//
// All values are quoted strings. Objects are delimited by { and }.

func parseTextKV(data []byte) (map[string]any, error) {
	s := string(data)
	result, _, err := parseTextKVInner(s, 0, false)
	return result, err
}

// parseTextKVInner parses key-value pairs starting at pos.
// If insideBrace is true it stops and consumes the closing '}'.
func parseTextKVInner(s string, pos int, insideBrace bool) (map[string]any, int, error) {
	result := make(map[string]any)
	for {
		pos = skipVDFWhitespace(s, pos)
		if pos >= len(s) {
			break
		}
		if insideBrace && s[pos] == '}' {
			pos++
			break
		}
		if s[pos] != '"' {
			// unexpected character — skip to avoid aborting the whole parse
			pos++
			continue
		}

		key, n, err := readVDFString(s, pos)
		if err != nil {
			return result, pos, err
		}
		pos = n

		pos = skipVDFWhitespace(s, pos)
		if pos >= len(s) {
			break
		}

		switch s[pos] {
		case '"':
			val, n, err := readVDFString(s, pos)
			if err != nil {
				return result, pos, err
			}
			result[key] = val
			pos = n
		case '{':
			pos++ // consume '{'
			sub, n, err := parseTextKVInner(s, pos, true)
			result[key] = sub
			pos = n
			if err != nil {
				return result, pos, err
			}
		default:
			pos++ // skip unexpected character
		}
	}
	return result, pos, nil
}

func skipVDFWhitespace(s string, pos int) int {
	for pos < len(s) {
		c := s[pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			pos++
		} else if strings.HasPrefix(s[pos:], "//") {
			for pos < len(s) && s[pos] != '\n' {
				pos++
			}
		} else {
			break
		}
	}
	return pos
}

func readVDFString(s string, pos int) (string, int, error) {
	if pos >= len(s) || s[pos] != '"' {
		return "", pos, fmt.Errorf("kvt: expected '\"' at %d", pos)
	}
	pos++
	var buf strings.Builder
	for pos < len(s) {
		c := s[pos]
		switch {
		case c == '\\' && pos+1 < len(s):
			pos++
			switch s[pos] {
			case '"':
				buf.WriteByte('"')
			case '\\':
				buf.WriteByte('\\')
			case 'n':
				buf.WriteByte('\n')
			case 't':
				buf.WriteByte('\t')
			default:
				buf.WriteByte(s[pos])
			}
			pos++
		case c == '"':
			pos++
			return buf.String(), pos, nil
		default:
			buf.WriteByte(c)
			pos++
		}
	}
	return "", pos, fmt.Errorf("kvt: unterminated string at %d", pos)
}
