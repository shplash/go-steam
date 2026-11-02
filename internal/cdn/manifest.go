package cdn

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ulikunitz/xz/lzma"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/BirknerAlex/go-steam/internal/proto"
)

// Manifest is a parsed depot manifest.
type Manifest struct {
	DepotID     uint32
	ManifestGID uint64
	CreatedAt   time.Time
	Files       []ManifestFile
}

// ManifestFile describes one file in a depot.
type ManifestFile struct {
	Path   string
	Size   int64
	Flags  uint32
	SHA1   []byte
	Chunks []ChunkInfo
	// IsSymlink is true when Flags has the SymLink bit set (0x40).
	IsSymlink     bool
	SymlinkTarget string
}

// ChunkInfo describes one content chunk within a file.
type ChunkInfo struct {
	SHA1             []byte // also the chunk ID used in CDN URLs
	Offset           int64  // byte offset within the decompressed file
	CompressedSize   uint32
	UncompressedSize uint32
}

// EDepotFileFlag values from SteamKit2 EDepotFileFlag enum.
const (
	fileExecutable = uint32(0x20) // EDepotFileFlag.Executable = 32
	fileDir        = uint32(0x40) // EDepotFileFlag.Directory  = 64
)

// DownloadManifest fetches and decrypts the manifest for the given depot.
// manifestRequestCode is appended to the URL path when non-zero (modern Steam CDN auth).
// token is an optional CDN auth token sent as a URL query parameter (legacy; usually empty).
func DownloadManifest(
	ctx context.Context,
	httpClient *http.Client,
	server *Server,
	depotID uint32,
	manifestGID uint64,
	depotKey []byte,
	token string,
	manifestRequestCode uint64,
) (*Manifest, error) {
	var url string
	if manifestRequestCode > 0 {
		url = fmt.Sprintf("https://%s/depot/%d/manifest/%d/5/%d", server.Host, depotID, manifestGID, manifestRequestCode)
	} else {
		url = fmt.Sprintf("https://%s/depot/%d/manifest/%d/5", server.Host, depotID, manifestGID)
	}
	if token != "" {
		url += "?" + token
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("manifest: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest: HTTP %d for depot %d manifest %d", resp.StatusCode, depotID, manifestGID)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("manifest: read body: %w", err)
	}

	// The manifest response is a protobuf ContentManifest with three sections:
	// payload, metadata, signature.  The payload is AES-CBC encrypted with the
	// depot key and then LZMA-compressed.
	//
	// Wire format (each section):
	//   uint32 LE: size of (proto-encoded) message
	//   [size bytes]: proto-encoded section
	//
	// We parse each section and combine into the final Manifest.
	m, err := decodeManifest(raw, depotKey, depotID, manifestGID)
	if err != nil {
		return nil, err
	}
	// A manifest with nothing in it means the body was not a shape we can read,
	// so say how it started: that is the only way to identify the format.
	if len(m.Files) == 0 {
		prefix := raw
		if len(prefix) > 32 {
			prefix = prefix[:32]
		}
		return nil, fmt.Errorf("manifest: no files (%d bytes, starts %x)", len(raw), prefix)
	}
	return m, nil
}

func decodeManifest(raw, depotKey []byte, depotID uint32, gid uint64) (*Manifest, error) {
	slog.Debug("decodeManifest", "depot", depotID, "gid", gid, "raw_len", len(raw), "has_key", len(depotKey) == 32)

	var payload proto.ContentManifestPayload
	var metadata proto.ContentManifestMetadata

	// Steam3 binary manifest ("version 4") — magic 0x16349781. This is a flat
	// binary structure rather than the protobuf section format.
	if len(raw) >= 4 && binary.LittleEndian.Uint32(raw[:4]) == steam3ManifestMagic {
		slog.Debug("decodeManifest: steam3 v4 format detected")
		p, m, err := parseSteam3Manifest(raw)
		if err != nil {
			return nil, fmt.Errorf("manifest: %w", err)
		}
		payload, metadata = p, m
	} else if len(raw) >= 4 && binary.LittleEndian.Uint32(raw[:4]) == 0x04034B50 {
		// ZIP magic 0x04034B50 — newer Steam CDN manifest format. The archive can
		// hold more than one entry (payload, metadata, signature), so every entry
		// is read rather than just the first.
		slog.Debug("decodeManifest: ZIP format detected")
		zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			return nil, fmt.Errorf("manifest: open zip: %w", err)
		}
		if len(zr.File) == 0 {
			return nil, fmt.Errorf("manifest: empty zip archive for depot %d", depotID)
		}
		for _, file := range zr.File {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			body, readErr := io.ReadAll(rc)
			rc.Close()
			if readErr != nil {
				continue
			}
			slog.Debug("decodeManifest: zip entry", "name", file.Name, "size", len(body))
			payload, metadata = decodeManifestSections(body, depotKey, payload, metadata)
		}
	} else {
		payload, metadata = decodeManifestSections(raw, depotKey, payload, metadata)
	}

	// Some manifests use an encoding the section walk above does not recognise,
	// which leaves an otherwise valid response looking empty. Before giving up,
	// try the body (and each zip entry) as a plain payload protobuf.
	if len(payload.Mappings) == 0 {
		if recovered, ok := payloadFallback(raw, depotKey); ok {
			slog.Debug("decodeManifest: recovered payload from fallback", "depot", depotID, "files", len(recovered.Mappings))
			payload = recovered
		}
	}

	// Decrypt file names when the manifest says they are encrypted, and when they
	// simply look that way: a name that decrypts cleanly is a ciphertext name,
	// and leaving it alone would put every file in the mod's root under a blob.
	encrypted := metadata.FilenamesEncrypted
	if !encrypted && payloadLooksEncrypted(payload, depotKey) {
		encrypted = true
		slog.Debug("decodeManifest: filenames look encrypted", "depot", depotID)
	}
	if len(depotKey) == 32 {
		for i := range payload.Mappings {
			f := &payload.Mappings[i]
			// A name that is a ciphertext blob in its own right is decrypted
			// whatever the manifest's flag said: some manifests carry the flag
			// unset, and trusting the flag alone left whole items written out
			// under blobs.
			if !encrypted && !looksLikeCiphertext(f.Filename) {
				continue
			}
			if plain, err := decryptFilename(f.Filename, depotKey); err == nil && plain != "" {
				f.Filename = plain
			}
			if f.LinktargetPath != "" {
				if plain, err := decryptFilename(f.LinktargetPath, depotKey); err == nil {
					f.LinktargetPath = plain
				}
			}
		}
		if encrypted {
			// Steam stores encrypted manifests ordered by encrypted filename; once
			// the names are in the clear, re-sort alphabetically so the file order
			// matches the canonical (decrypted) manifest. Mirrors SteamKit2
			// DecryptFilenames, which sorts by filename using OrdinalIgnoreCase.
			sort.SliceStable(payload.Mappings, func(i, j int) bool {
				return strings.ToLower(payload.Mappings[i].Filename) < strings.ToLower(payload.Mappings[j].Filename)
			})
		}
	}

	// Names that are still ciphertext mean the depot key does not match this
	// manifest. Writing them out installs the item as thousands of blobs in one
	// folder, which reads as a broken mod rather than a download that failed, so
	// refuse it here where the reason is still known.
	if namesLookLikeCiphertext(payload.Mappings) {
		return nil, fmt.Errorf("manifest: depot %d file names did not decrypt; the depot key does not match this manifest", depotID)
	}

	slog.Debug("decodeManifest: result", "depot", depotID, "files", len(payload.Mappings), "filenames_encrypted", encrypted)

	// Build our Manifest from the parsed data.
	m := &Manifest{
		DepotID:     depotID,
		ManifestGID: gid,
	}
	if metadata.CreationTime > 0 {
		m.CreatedAt = time.Unix(int64(metadata.CreationTime), 0)
	}

	for _, f := range payload.Mappings {
		flags := f.Flags
		if flags&fileDir != 0 {
			continue // skip directories
		}
		isSymlink := f.LinktargetPath != ""
		mf := ManifestFile{
			Path:          normalizePath(f.Filename),
			Size:          int64(f.Size),
			Flags:         flags,
			SHA1:          f.ShaContent,
			IsSymlink:     isSymlink,
			SymlinkTarget: f.LinktargetPath,
		}
		for _, c := range f.Chunks {
			mf.Chunks = append(mf.Chunks, ChunkInfo{
				SHA1:             c.Sha,
				Offset:           int64(c.Offset),
				CompressedSize:   c.CbCompressed,
				UncompressedSize: c.CbOriginal,
			})
		}
		m.Files = append(m.Files, mf)
	}
	return m, nil
}

// steam3ManifestMagic identifies the Steam3 binary ("version 4") manifest format
// (Steam3Manifest.MAGIC in SteamKit2).
const steam3ManifestMagic = 0x16349781

// parseSteam3Manifest decodes the Steam3 binary manifest ("version 4") into the
// same payload/metadata structures the protobuf path produces, so the shared
// filename-decryption and Manifest-building logic can be reused.
//
// Layout (all little-endian), mirroring SteamKit2 Steam3Manifest.Deserialize:
//
//	magic(4)=0x16349781, version(4)=4, depotID(4), manifestGID(8),
//	creationTime(4), filenamesEncrypted(4), totalUncompressedSize(8),
//	totalCompressedSize(8), chunkCount(4), fileEntryCount(4),
//	fileMappingSize(4), encryptedCRC(4), decryptedCRC(4), flags(4)
//	then fileMappingSize bytes of file mappings, then a trailing magic marker.
func parseSteam3Manifest(raw []byte) (proto.ContentManifestPayload, proto.ContentManifestMetadata, error) {
	var payload proto.ContentManifestPayload
	var metadata proto.ContentManifestMetadata

	const headerSize = 4 + 64 // magic(4) + 13 fixed header fields(64) = 68
	le := binary.LittleEndian
	if len(raw) < headerSize+4 { // +4 for the trailing end-of-manifest marker
		return payload, metadata, fmt.Errorf("steam3 manifest too short (%d bytes)", len(raw))
	}
	if version := le.Uint32(raw[4:]); version != 4 {
		return payload, metadata, fmt.Errorf("unsupported steam3 manifest version %d", version)
	}

	metadata.DepotID = le.Uint32(raw[8:])
	metadata.GIDManifest = le.Uint64(raw[12:])
	metadata.CreationTime = le.Uint32(raw[20:])
	metadata.FilenamesEncrypted = le.Uint32(raw[24:]) != 0
	metadata.CbDiskOriginal = le.Uint64(raw[28:])
	metadata.CbDiskCompressed = le.Uint64(raw[36:])
	metadata.UniqueChunks = le.Uint32(raw[44:]) // ChunkCount
	// raw[48:] = fileEntryCount (unused; the mapping loop is size-bounded)
	fileMappingSize := le.Uint32(raw[52:])
	metadata.CrcEncrypted = le.Uint32(raw[56:])
	metadata.CrcClear = le.Uint32(raw[60:])
	// raw[64:] = flags (unused)

	start := headerSize
	end := start + int(fileMappingSize)
	if end > len(raw) {
		return payload, metadata, fmt.Errorf("steam3 file mapping size %d overflows buffer (%d bytes)", fileMappingSize, len(raw))
	}
	for pos := start; pos < end; {
		f, n, err := parseSteam3FileMapping(raw[pos:end])
		if err != nil {
			return payload, metadata, err
		}
		payload.Mappings = append(payload.Mappings, f)
		pos += n
	}
	return payload, metadata, nil
}

// parseSteam3FileMapping decodes one file entry from a Steam3 binary manifest and
// returns the number of bytes consumed.
//
//	filename(null-terminated UTF-8), totalSize(8), flags(4),
//	hashContent(20), hashFileName(20), numChunks(4),
//	then numChunks * { chunkGID(20), checksum(4), offset(8),
//	                   decompressedSize(4), compressedSize(4) }
func parseSteam3FileMapping(b []byte) (proto.ContentManifestFile, int, error) {
	var f proto.ContentManifestFile
	le := binary.LittleEndian

	z := bytes.IndexByte(b, 0)
	if z < 0 {
		return f, 0, fmt.Errorf("steam3 file name not null-terminated")
	}
	f.Filename = string(b[:z])
	pos := z + 1

	const fixed = 8 + 4 + 20 + 20 + 4 // totalSize..numChunks
	if pos+fixed > len(b) {
		return f, 0, fmt.Errorf("steam3 file mapping truncated")
	}
	f.Size = le.Uint64(b[pos:])
	pos += 8
	f.Flags = le.Uint32(b[pos:])
	pos += 4
	f.ShaContent = append([]byte(nil), b[pos:pos+20]...)
	pos += 20
	f.ShaFilename = append([]byte(nil), b[pos:pos+20]...)
	pos += 20
	numChunks := le.Uint32(b[pos:])
	pos += 4

	const chunkSize = 20 + 4 + 8 + 4 + 4 // 40 bytes
	for i := range numChunks {
		if pos+chunkSize > len(b) {
			return f, 0, fmt.Errorf("steam3 chunk %d/%d truncated", i, numChunks)
		}
		var c proto.ContentManifestChunk
		c.Sha = append([]byte(nil), b[pos:pos+20]...)
		pos += 20
		c.Crc = le.Uint32(b[pos:])
		pos += 4
		c.Offset = le.Uint64(b[pos:])
		pos += 8
		c.CbOriginal = le.Uint32(b[pos:]) // decompressed size
		pos += 4
		c.CbCompressed = le.Uint32(b[pos:]) // compressed size
		pos += 4
		f.Chunks = append(f.Chunks, c)
	}
	return f, pos, nil
}

// decryptManifestSection decrypts a manifest section using Steam's AES scheme:
//
//	wire = encryptedIV(16) + AES-CBC(ciphertext)
//	where encryptedIV = AES-ECB(key, rawIV)
//
// This matches CryptoHelper.SymmetricDecrypt in SteamKit2.
func decryptManifestSection(data, key []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("manifest: section too short to decrypt")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// ECB-decrypt the first 16 bytes to recover the raw IV.
	rawIV := make([]byte, aes.BlockSize)
	block.Decrypt(rawIV, data[:aes.BlockSize])

	ciphertext := data[aes.BlockSize:]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("manifest: ciphertext not block-aligned")
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, rawIV).CryptBlocks(plaintext, ciphertext)
	// Strip PKCS#7 padding.
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("manifest: empty plaintext after decrypt")
	}
	pad := int(plaintext[len(plaintext)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(plaintext) {
		return nil, fmt.Errorf("manifest: section padding is invalid")
	}
	return plaintext[:len(plaintext)-pad], nil
}

// lzmaDecompress decompresses LZMA-encoded data.
//
// Callers invoke this speculatively on bytes that aren't guaranteed to
// actually be LZMA (see decodeManifest and decompressVZip), so the first
// bytes can be arbitrary data that happens to parse as an LZMA header.
// That header embeds a dictionary window size which lzma.NewReader
// allocates up front with no sanity check beyond "< 4 GiB", so garbage
// input can trigger a multi-gigabyte allocation and OOM the process.
// ValidHeader rejects any dictCap that isn't a size a real LZMA encoder
// would produce.
func lzmaDecompress(data []byte) ([]byte, error) {
	if len(data) < lzma.HeaderLen || !lzma.ValidHeader(data[:lzma.HeaderLen]) {
		return nil, fmt.Errorf("lzma: not a valid LZMA header")
	}
	r, err := lzma.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// decryptFilename decrypts an AES-CBC encrypted filename.
// Steam stores encrypted filenames as base64-encoded ciphertext in the proto.
// The binary format is: encryptedIV(16) + AES-CBC(ciphertext), matching SymmetricDecrypt.
func decryptFilename(rawname string, depotKey []byte) (string, error) {
	// Try standard base64 first, then unpadded.
	enc, err := base64.StdEncoding.DecodeString(rawname)
	if err != nil {
		enc, err = base64.RawStdEncoding.DecodeString(rawname)
		if err != nil {
			slog.Debug("decryptFilename: base64 failed", "len", len(rawname), "err", err)
			return "", err
		}
	}
	slog.Debug("decryptFilename: decoded", "b64_len", len(rawname), "bin_len", len(enc))
	plain, err := decryptManifestSection(enc, depotKey)
	if err != nil {
		slog.Debug("decryptFilename: decrypt failed", "err", err)
		return "", err
	}
	result := strings.TrimRight(string(plain), "\x00")
	slog.Debug("decryptFilename: ok", "result", result)
	return result, nil
}

// normalizePath converts Steam's Windows-style backslashes to forward slashes.
func normalizePath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}


// payloadFallback looks for a payload protobuf in a manifest this package could
// not walk: either the body itself, or one of the entries of a zip-wrapped
// manifest, each also tried decrypted and decompressed.
func payloadFallback(raw, depotKey []byte) (proto.ContentManifestPayload, bool) {
	var empty proto.ContentManifestPayload

	variants := make([][]byte, 0, 4)
	if len(raw) >= 4 && binary.LittleEndian.Uint32(raw[:4]) == 0x04034B50 {
		if zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw))); err == nil {
			for _, f := range zr.File {
				rc, err := f.Open()
				if err != nil {
					continue
				}
				if body, err := io.ReadAll(rc); err == nil {
					variants = append(variants, body)
				}
				rc.Close()
			}
		}
	}
	variants = append(variants, raw)

	for _, variant := range variants {
		candidates := [][]byte{variant}
		if len(depotKey) == 32 {
			if plain, err := decryptManifestSection(variant, depotKey); err == nil {
				candidates = append(candidates, plain)
			}
		}
		if plain, err := lzmaDecompress(variant); err == nil {
			candidates = append(candidates, plain)
		}
		// Newer manifests wrap the payload in a ContentManifest message, so the
		// payload has to be unwrapped before it can be decoded.
		if wrapped, ok := unwrapContentManifest(variant); ok {
			candidates = append(candidates, wrapped)
			if len(depotKey) == 32 {
				if plain, err := decryptManifestSection(wrapped, depotKey); err == nil {
					candidates = append(candidates, plain)
				}
			}
			if plain, err := lzmaDecompress(wrapped); err == nil {
				candidates = append(candidates, plain)
			}
		}
		for _, candidate := range candidates {
			var payload proto.ContentManifestPayload
			if err := payload.Unmarshal(candidate); err == nil && len(payload.Mappings) > 0 {
				return payload, true
			}
		}
	}
	return empty, false
}

// unwrapContentManifest pulls the payload (field 1) out of a ContentManifest
// wrapper, which some manifests use instead of the magic-prefixed sections.
func unwrapContentManifest(data []byte) ([]byte, bool) {
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, false
		}
		data = data[n:]
		if num == 1 && typ == protowire.BytesType {
			value, n := protowire.ConsumeBytes(data)
			if n < 0 || len(value) == 0 {
				return nil, false
			}
			return value, true
		}
		n = protowire.ConsumeFieldValue(num, typ, data)
		if n < 0 {
			return nil, false
		}
		data = data[n:]
	}
	return nil, false
}


// decodeManifestSections reads one manifest body, in whichever of the layouts
// Steam has used: magic-prefixed sections, size-prefixed sections, or a plain
// payload protobuf.
func decodeManifestSections(body, depotKey []byte, payload proto.ContentManifestPayload,
	metadata proto.ContentManifestMetadata) (proto.ContentManifestPayload, proto.ContentManifestMetadata) {
	if len(body) >= 8 {
		magic := binary.LittleEndian.Uint32(body)
		if magic == 0x71F617D0 || magic == 0x1F4812BE {
			payload, metadata = walkMagicSections(body, depotKey, payload, metadata)
		}
	}
	if len(payload.Mappings) == 0 {
		payload, metadata = walkSizeSections(body, depotKey, payload, metadata)
	}
	if len(payload.Mappings) == 0 {
		for _, candidate := range sectionCandidates(body, depotKey) {
			var p proto.ContentManifestPayload
			if p.Unmarshal(candidate) == nil && len(p.Mappings) > 0 {
				payload = p
				break
			}
		}
	}
	return payload, metadata
}

// walkMagicSections reads the magic-prefixed ("old binary") layout:
//
//	uint32 magic  (0x71F617D0 payload, 0x1F4812BE metadata, …)
//	uint32 size
//	[size bytes]  (protobuf, possibly AES-CBC then LZMA)
//
// repeated until 0x32C415AB.
func walkMagicSections(body, depotKey []byte, payload proto.ContentManifestPayload,
	metadata proto.ContentManifestMetadata) (proto.ContentManifestPayload, proto.ContentManifestMetadata) {
	pos := 0
	for pos+8 <= len(body) {
		sectionMagic := binary.LittleEndian.Uint32(body[pos:])
		sectionSize := binary.LittleEndian.Uint32(body[pos+4:])
		pos += 8

		if sectionMagic == 0x32C415AB {
			break
		}
		if pos+int(sectionSize) > len(body) {
			break
		}
		section := body[pos : pos+int(sectionSize)]
		pos += int(sectionSize)

		switch sectionMagic {
		case 0x71F617D0:
			for _, candidate := range sectionCandidates(section, depotKey) {
				var p proto.ContentManifestPayload
				if p.Unmarshal(candidate) == nil && len(p.Mappings) > 0 {
					payload = p
					break
				}
			}
		case 0x1F4812BE:
			mergeMetadata(section, depotKey, &metadata)
		}
	}
	return payload, metadata
}

// walkSizeSections reads the legacy layout: a size-prefixed section, repeated.
func walkSizeSections(body, depotKey []byte, payload proto.ContentManifestPayload,
	metadata proto.ContentManifestMetadata) (proto.ContentManifestPayload, proto.ContentManifestMetadata) {
	pos := 0
	for pos+4 <= len(body) {
		size := binary.LittleEndian.Uint32(body[pos:])
		pos += 4
		if pos+int(size) > len(body) {
			break
		}
		section := body[pos : pos+int(size)]
		pos += int(size)

		for _, candidate := range sectionCandidates(section, depotKey) {
			var p proto.ContentManifestPayload
			if p.Unmarshal(candidate) == nil && len(p.Mappings) > 0 {
				payload = p
				break
			}
		}
		if len(payload.Mappings) > 0 {
			continue
		}
		mergeMetadata(section, depotKey, &metadata)
	}
	return payload, metadata
}

// sectionCandidates lists the ways a section may be encoded, plain first so a
// readable protobuf is never replaced by a speculative decrypt.
func sectionCandidates(section, depotKey []byte) [][]byte {
	candidates := [][]byte{section}
	if plain, err := lzmaDecompress(section); err == nil {
		candidates = append(candidates, plain)
	}
	if len(depotKey) == 32 {
		if plain, err := decryptManifestSection(section, depotKey); err == nil {
			candidates = append(candidates, plain)
			if decompressed, err := lzmaDecompress(plain); err == nil {
				candidates = append(candidates, decompressed)
			}
		}
	}
	return candidates
}


// mergeMetadata reads a metadata section, keeping whatever each candidate can
// tell us: a ciphertext candidate that happens to parse must not hide the
// "filenames are encrypted" flag held by the candidate that decoded properly.
func mergeMetadata(section, depotKey []byte, metadata *proto.ContentManifestMetadata) {
	for _, candidate := range sectionCandidates(section, depotKey) {
		var m proto.ContentManifestMetadata
		if m.Unmarshal(candidate) != nil {
			continue
		}
		if metadata.DepotID == 0 && m.DepotID != 0 {
			metadata.DepotID = m.DepotID
		}
		if metadata.GIDManifest == 0 && m.GIDManifest != 0 {
			metadata.GIDManifest = m.GIDManifest
		}
		if metadata.CreationTime == 0 && m.CreationTime != 0 {
			metadata.CreationTime = m.CreationTime
		}
		if metadata.CbDiskOriginal == 0 && m.CbDiskOriginal != 0 {
			metadata.CbDiskOriginal = m.CbDiskOriginal
		}
		if m.FilenamesEncrypted {
			metadata.FilenamesEncrypted = true
		}
	}
}

// payloadLooksEncrypted reports whether the file names decrypt cleanly, which
// only happens when they were encrypted in the first place. Several names are
// looked at rather than the first one: a single name can fail to decrypt for
// reasons that say nothing about the manifest (an unusually long path, a
// directory entry), and deciding on that one sample left whole items written
// out under ciphertext names.
func payloadLooksEncrypted(payload proto.ContentManifestPayload, depotKey []byte) bool {
	if len(depotKey) != 32 {
		return false
	}
	checked, decrypted := 0, 0
	for _, f := range payload.Mappings {
		if f.Flags&fileDir != 0 || f.Filename == "" {
			continue
		}
		checked++
		if plain, err := decryptFilename(f.Filename, depotKey); err == nil && plain != "" && plain != f.Filename {
			decrypted++
		}
		if checked == 8 {
			break
		}
	}
	return checked > 0 && decrypted*2 > checked
}

// namesLookLikeCiphertext reports whether most of the manifest's names are still
// base64 blobs of AES blocks, which is what a manifest decrypted with the wrong
// depot key looks like.
func namesLookLikeCiphertext(mappings []proto.ContentManifestFile) bool {
	checked, blobs := 0, 0
	for _, f := range mappings {
		if f.Flags&fileDir != 0 || f.Filename == "" {
			continue
		}
		checked++
		if looksLikeCiphertext(f.Filename) {
			blobs++
		}
		if checked == 32 {
			break
		}
	}
	return checked > 0 && blobs*2 > checked
}

// looksLikeCiphertext reports whether a name is a base64 blob of an AES
// payload: Steam's encrypted names are an encrypted IV followed by whole blocks.
// Names that carry an extension, or any character base64 does not use, are real
// file names and never match.
func looksLikeCiphertext(name string) bool {
	if len(name) < 44 || strings.Contains(name, ".") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '+', r == '/', r == '=':
		default:
			return false
		}
	}
	raw, err := base64.StdEncoding.DecodeString(name)
	if err != nil {
		return false
	}
	return len(raw) >= 32 && len(raw)%16 == 0
}
