package proto

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

// CCloud_GetFileDetails_Request asks Steam's cloud service about a stored file.
// Used with the service method "Cloud.GetFileDetails#1".
// Field numbers from SteamTracking/Protobufs steam/steammessages_cloud.steamclient.proto.
type CCloud_GetFileDetails_Request struct {
	UGCID uint64 // field 1
	AppID uint32 // field 2
}

func (m *CCloud_GetFileDetails_Request) Marshal() []byte {
	var b []byte
	if m.UGCID != 0 {
		b = appendTag(b, 1, protowire.VarintType)
		b = protowire.AppendVarint(b, m.UGCID)
	}
	if m.AppID != 0 {
		b = appendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(m.AppID))
	}
	return b
}

// CCloud_UserFile is the file record carried by a cloud file response.
type CCloud_UserFile struct {
	AppID     uint32 // field 1
	UGCID     uint64 // field 2
	Filename  string // field 3
	Timestamp uint64 // field 4
	FileSize  uint32 // field 5
	URL       string // field 6
}

func (m *CCloud_UserFile) Unmarshal(data []byte) error {
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return fmt.Errorf("proto: bad tag in CCloud_UserFile")
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return fmt.Errorf("proto: bad varint")
			}
			m.AppID = uint32(v)
			data = data[n:]
		case num == 2 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return fmt.Errorf("proto: bad varint")
			}
			m.UGCID = v
			data = data[n:]
		case num == 3 && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(data)
			if n < 0 {
				return fmt.Errorf("proto: bad string")
			}
			m.Filename = v
			data = data[n:]
		case num == 4 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return fmt.Errorf("proto: bad varint")
			}
			m.Timestamp = v
			data = data[n:]
		case num == 5 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return fmt.Errorf("proto: bad varint")
			}
			m.FileSize = uint32(v)
			data = data[n:]
		case num == 6 && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(data)
			if n < 0 {
				return fmt.Errorf("proto: bad string")
			}
			m.URL = v
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return fmt.Errorf("proto: unknown field")
			}
			data = data[n:]
		}
	}
	return nil
}

// CCloud_GetFileDetails_Response carries the cloud file record and the host a
// range check would go to.
type CCloud_GetFileDetails_Response struct {
	Details       CCloud_UserFile // field 1
	RangecheckHost string         // field 2
}

func (m *CCloud_GetFileDetails_Response) Unmarshal(data []byte) error {
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return fmt.Errorf("proto: bad tag in CCloud_GetFileDetails_Response")
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return fmt.Errorf("proto: bad bytes")
			}
			if err := m.Details.Unmarshal(v); err != nil {
				return err
			}
			data = data[n:]
		case num == 2 && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(data)
			if n < 0 {
				return fmt.Errorf("proto: bad string")
			}
			m.RangecheckHost = v
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return fmt.Errorf("proto: unknown field")
			}
			data = data[n:]
		}
	}
	return nil
}
