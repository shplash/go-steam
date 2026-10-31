// Package workshop resolves Steam Workshop item metadata via the Web API.
package workshop

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Item holds the resolved metadata for a published Workshop file.
type Item struct {
	// ItemID is the PublishedFileID.
	ItemID uint64
	// AppID is the consumer application (game) that the item belongs to.
	AppID uint32
	// ManifestGID is hcontent_file from the WebAPI — the manifest GID used to
	// fetch content from the CDN.
	ManifestGID uint64
	// DepotID is the depot used for this workshop item.
	// For most games depotID == appID but this is not guaranteed.
	DepotID uint32
	// Title is the human-readable item name.
	Title string
	// FileSize is the total size in bytes as reported by the WebAPI.
	FileSize int64
	// FileName is the name the item was published under.
	FileName string
	// FileURL is set for legacy single-file items, which Steam serves from its
	// UGC storage as one download instead of a depot manifest.
	FileURL string
	// Updated is when the item was last published/updated.
	Updated time.Time
}

type publishedFileDetails struct {
	Result          int    `json:"result"`
	PublishedFileID string `json:"publishedfileid"`
	ConsumerAppID   int    `json:"consumer_app_id"`
	HContentFile    string `json:"hcontent_file"`
	Title           string `json:"title"`
	FileSize        string `json:"file_size"`
	FileName        string `json:"filename"`
	FileURL         string `json:"file_url"`
	TimeUpdated     int64  `json:"time_updated"`
}

type getPublishedFileResponse struct {
	Response struct {
		Result      int                    `json:"result"`
		ResultCount int                    `json:"resultcount"`
		Details     []publishedFileDetails `json:"publishedfiledetails"`
	} `json:"response"`
}

// publishedFileDetailsURL is the WebAPI endpoint for resolving workshop items.
// It is a package variable so tests can point it at a local server.
var publishedFileDetailsURL = "https://api.steampowered.com/ISteamRemoteStorage/GetPublishedFileDetails/v1/"

// GetItemInfo fetches metadata for a Workshop item from the Steam Web API.
// No API key is required for publicly-listed items.
func GetItemInfo(ctx context.Context, itemID uint64) (*Item, error) {
	apiURL := publishedFileDetailsURL

	form := url.Values{
		"itemcount":           {"1"},
		"publishedfileids[0]": {strconv.FormatUint(itemID, 10)},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("workshop: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("workshop: WebAPI request: %w", err)
	}
	defer resp.Body.Close()

	var result getPublishedFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("workshop: decode response: %w", err)
	}

	if result.Response.Result != 1 {
		return nil, fmt.Errorf("workshop: API result %d", result.Response.Result)
	}
	if len(result.Response.Details) == 0 {
		return nil, fmt.Errorf("workshop: item %d not found", itemID)
	}

	d := result.Response.Details[0]
	if d.Result != 1 {
		return nil, fmt.Errorf("workshop: item %d result %d", itemID, d.Result)
	}

	manifestGID, _ := strconv.ParseUint(d.HContentFile, 10, 64)
	fileSize, _ := strconv.ParseInt(d.FileSize, 10, 64)

	appID := uint32(d.ConsumerAppID)
	item := &Item{
		ItemID:      itemID,
		AppID:       appID,
		ManifestGID: manifestGID,
		DepotID:     appID, // Workshop items use the app's depot by convention
		Title:       d.Title,
		FileSize:    fileSize,
		FileName:    d.FileName,
		FileURL:     d.FileURL,
		Updated:     time.Unix(d.TimeUpdated, 0),
	}
	return item, nil
}
