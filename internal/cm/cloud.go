package cm

import (
	"context"
	"fmt"

	"github.com/BirknerAlex/go-steam/internal/proto"
)

// UGCFile is what Steam's cloud service reports about a stored file. URL is
// where the file can be fetched from; it is empty when Steam will not serve it.
type UGCFile struct {
	AppID    uint32
	UGCID    uint64
	Filename string
	FileSize uint32
	URL      string
}

// GetUGCFile asks Steam where a cloud-stored file lives. Workshop items that
// predate workshop depots are kept this way: there is no depot manifest to
// fetch, only a file and the URL to fetch it from.
func (s *Session) GetUGCFile(ctx context.Context, appID uint32, ugcID uint64) (*UGCFile, error) {
	req := proto.CCloud_GetFileDetails_Request{UGCID: ugcID, AppID: appID}
	jobID, err := s.SendServiceMethod(ctx, "Cloud.GetFileDetails#1", req.Marshal())
	if err != nil {
		return nil, fmt.Errorf("cloud file: send: %w", err)
	}
	pkt, err := s.Await(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("cloud file: await: %w", err)
	}
	if proto.EResult(pkt.Header.Eresult) != proto.EResultOK && pkt.Header.Eresult != 0 {
		return nil, fmt.Errorf("cloud file: EResult %d", pkt.Header.Eresult)
	}

	var resp proto.CCloud_GetFileDetails_Response
	if err := resp.Unmarshal(pkt.Body); err != nil {
		return nil, fmt.Errorf("cloud file: unmarshal: %w", err)
	}
	return &UGCFile{
		AppID:    resp.Details.AppID,
		UGCID:    resp.Details.UGCID,
		Filename: resp.Details.Filename,
		FileSize: resp.Details.FileSize,
		URL:      resp.Details.URL,
	}, nil
}
