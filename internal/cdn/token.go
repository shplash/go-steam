package cdn

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/BirknerAlex/go-steam/internal/proto"
	"github.com/BirknerAlex/go-steam/internal/store"
)

// CMSession is the subset of cm.Session used by the token provider.
// Defined here to avoid an import cycle.
type CMSession interface {
	Send(ctx context.Context, msg proto.EMsg, body []byte) (uint64, error)
	SendServiceMethod(ctx context.Context, methodName string, body []byte) (uint64, error)
	Await(ctx context.Context, jobID uint64) (*proto.Packet, error)
}

// TokenProvider fetches and caches CDN auth tokens for (host, depotID) pairs.
type TokenProvider struct {
	cache   *store.LocalCache
	session CMSession
	appID   uint32

	mu       sync.Mutex
	inflight map[string]*tokenFlight
	failures map[string]time.Time // negative cache: last failure time per key
}

type tokenFlight struct {
	done  chan struct{}
	token string
	err   error
}

// NewTokenProvider creates a token provider.
func NewTokenProvider(cache *store.LocalCache, session CMSession, appID uint32) *TokenProvider {
	return &TokenProvider{
		cache:    cache,
		session:  session,
		appID:    appID,
		inflight: make(map[string]*tokenFlight),
		failures: make(map[string]time.Time),
	}
}

// GetToken returns a valid CDN auth token for the given host and depot.
// Results are cached on disk (with a 5-minute safety window before expiry).
// Concurrent requests for the same (host, depotID) pair share one CM request.
// Failed requests are negatively cached for 5 minutes to avoid hammering the CM.
func (p *TokenProvider) GetToken(ctx context.Context, depotID uint32, host string) (string, error) {
	// 1. Disk cache hit.
	if p.cache != nil {
		if t, err := p.cache.LoadToken(host, depotID); err == nil && t != nil {
			return t.Token, nil
		}
	}

	key := fmt.Sprintf("%s/%d", host, depotID)

	// 2. Negative cache: skip the CM call if we know it fails for this combo.
	p.mu.Lock()
	if failedAt, bad := p.failures[key]; bad && time.Since(failedAt) < 5*time.Minute {
		p.mu.Unlock()
		return "", nil // anonymous access — no token, not an error
	}

	// 3. Singleflight: share one in-flight CM request per (host, depot).
	if f, ok := p.inflight[key]; ok {
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-f.done:
			return f.token, f.err
		}
	}
	f := &tokenFlight{done: make(chan struct{})}
	p.inflight[key] = f
	p.mu.Unlock()

	token, expiry, err := p.fetchToken(ctx, depotID, host)
	f.token, f.err = token, err
	close(f.done)

	p.mu.Lock()
	delete(p.inflight, key)
	if err != nil {
		p.failures[key] = time.Now() // negative cache
	}
	p.mu.Unlock()

	if err != nil {
		return "", nil // token unavailable (anonymous) — not fatal
	}

	if p.cache != nil {
		_ = p.cache.SaveToken(store.CachedToken{
			Host:    host,
			DepotID: depotID,
			Token:   token,
			Expiry:  expiry,
		})
	}
	return token, nil
}

// InvalidateToken clears the negative cache for the given (host, depotID) so the
// next GetToken call will re-attempt the CM request (used after a 401 retry).
func (p *TokenProvider) InvalidateToken(depotID uint32, host string) {
	key := fmt.Sprintf("%s/%d", host, depotID)
	p.mu.Lock()
	delete(p.failures, key)
	p.mu.Unlock()
}

// TokenUnavailable reports whether the last token request for this host and
// depot failed. GetToken treats that as anonymous access, so callers that then
// see a refusal can say why.
func (p *TokenProvider) TokenUnavailable(depotID uint32, host string) error {
	key := fmt.Sprintf("%s/%d", host, depotID)
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, bad := p.failures[key]; bad {
		return fmt.Errorf("CDN token unavailable for depot %d on %s", depotID, host)
	}
	return nil
}

func (p *TokenProvider) fetchToken(ctx context.Context, depotID uint32, host string) (string, time.Time, error) {
	req := proto.CContentServerDirectory_GetCDNAuthToken_Request{
		DepotID:  depotID,
		HostName: host,
		AppID:    p.appID,
	}
	body := req.Marshal()

	jobID, err := p.session.SendServiceMethod(ctx, "ContentServerDirectory.GetCDNAuthToken#1", body)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("cdn token: send: %w", err)
	}
	pkt, err := p.session.Await(ctx, jobID)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("cdn token: await: %w", err)
	}

	if proto.EResult(pkt.Header.Eresult) != proto.EResultOK && pkt.Header.Eresult != 0 {
		return "", time.Time{}, fmt.Errorf("cdn token: EResult %d", pkt.Header.Eresult)
	}

	var resp proto.CContentServerDirectory_GetCDNAuthToken_Response
	if err := resp.Unmarshal(pkt.Body); err != nil {
		return "", time.Time{}, fmt.Errorf("cdn token: unmarshal: %w", err)
	}

	expiry := time.Unix(int64(resp.ExpirationTime), 0)
	return resp.Token, expiry, nil
}
