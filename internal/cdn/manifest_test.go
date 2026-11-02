package cdn

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // Steam mandates SHA1
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"testing"

	"github.com/ulikunitz/xz/lzma"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		`a\b\c.txt`: "a/b/c.txt",
		"a/b/c.txt": "a/b/c.txt",
		"plain":     "plain",
		`mix\a/b`:   "mix/a/b",
	}
	for in, want := range cases {
		if got := normalizePath(in); got != want {
			t.Errorf("normalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDecryptManifestSectionRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	plain := []byte("manifest section bytes for round trip test!!")
	enc, err := symmetricEncryptTest(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptManifestSection(enc, key)
	if err != nil {
		t.Fatalf("decryptManifestSection: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("round trip mismatch: got %q, want %q", got, plain)
	}

	// Too-short input errors.
	if _, err := decryptManifestSection([]byte{1, 2}, key); err == nil {
		t.Error("expected error for too-short section")
	}
}

func TestDecryptFilenameRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, 32)
	name := "path/to/secret file.dat"
	// Steam stores names NUL-padded inside the encrypted blob; the decryptor
	// trims trailing NULs. Encrypt the raw name (PKCS7 padding handles alignment).
	enc, err := symmetricEncryptTest([]byte(name), key)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(enc)
	got, err := decryptFilename(b64, key)
	if err != nil {
		t.Fatalf("decryptFilename: %v", err)
	}
	if got != name {
		t.Errorf("decryptFilename = %q, want %q", got, name)
	}

	// Invalid base64 errors.
	if _, err := decryptFilename("!!!not base64!!!", key); err == nil {
		t.Error("expected error for invalid base64")
	}
}

// --- manifest payload builders (hand-encoded protobuf) ----------------------

func encodeChunkProto(sha []byte, offset uint64, orig, compressed uint32) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, sha)
	b = protowire.AppendTag(b, 3, protowire.VarintType)
	b = protowire.AppendVarint(b, offset)
	b = protowire.AppendTag(b, 4, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(orig))
	b = protowire.AppendTag(b, 5, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(compressed))
	return b
}

func encodeFileProto(name string, size uint64, flags uint32, shaContent []byte, chunks ...[]byte) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, name)
	b = protowire.AppendTag(b, 2, protowire.VarintType)
	b = protowire.AppendVarint(b, size)
	b = protowire.AppendTag(b, 3, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(flags))
	b = protowire.AppendTag(b, 5, protowire.BytesType)
	b = protowire.AppendBytes(b, shaContent)
	for _, c := range chunks {
		b = protowire.AppendTag(b, 6, protowire.BytesType)
		b = protowire.AppendBytes(b, c)
	}
	return b
}

func encodePayloadProto(files ...[]byte) []byte {
	var b []byte
	for _, f := range files {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, f)
	}
	return b
}

func lenPrefixedSection(section []byte) []byte {
	out := make([]byte, 4+len(section))
	out[0] = byte(len(section))
	out[1] = byte(len(section) >> 8)
	out[2] = byte(len(section) >> 16)
	out[3] = byte(len(section) >> 24)
	copy(out[4:], section)
	return out
}

func TestDecodeManifest_LegacySections(t *testing.T) {
	sha := make([]byte, 20)
	sha[0] = 0xAB
	chunk := encodeChunkProto(sha, 0, 1024, 512)
	file := encodeFileProto("data/file.bin", 1024, 0, sha, chunk)
	payload := encodePayloadProto(file)

	raw := lenPrefixedSection(payload)

	// depotKey nil → decryption skipped, proto parsed directly.
	m, err := decodeManifest(raw, nil, 1006, 9999)
	if err != nil {
		t.Fatalf("decodeManifest: %v", err)
	}
	if m.DepotID != 1006 || m.ManifestGID != 9999 {
		t.Errorf("manifest ids = %d/%d", m.DepotID, m.ManifestGID)
	}
	if len(m.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(m.Files))
	}
	f := m.Files[0]
	if f.Path != "data/file.bin" || f.Size != 1024 {
		t.Errorf("file fields wrong: %+v", f)
	}
	if len(f.Chunks) != 1 || f.Chunks[0].UncompressedSize != 1024 || f.Chunks[0].CompressedSize != 512 {
		t.Errorf("chunk fields wrong: %+v", f.Chunks)
	}
}

func TestDecodeManifest_SkipsDirectories(t *testing.T) {
	sha := make([]byte, 20)
	dir := encodeFileProto("somedir", 0, fileDir, sha)
	file := encodeFileProto("somedir/f.txt", 10, 0, sha, encodeChunkProto(sha, 0, 10, 10))
	payload := encodePayloadProto(dir, file)
	raw := lenPrefixedSection(payload)

	m, err := decodeManifest(raw, nil, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 1 || m.Files[0].Path != "somedir/f.txt" {
		t.Errorf("directory entry should be skipped, got %+v", m.Files)
	}
}

// ciphertextName encrypts a path the way Steam does for a manifest that keeps
// its file names encrypted.
func ciphertextName(t *testing.T, path string, key []byte) string {
	t.Helper()
	enc, err := symmetricEncryptTest([]byte(path), key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(enc)
}

// Regression test: a manifest that leaves the "names are encrypted" flag unset
// used to be judged on its first name alone, so a single name that did not
// decrypt left every other file of the item written out flat under a blob. The
// rest decrypt, so the whole manifest must be decrypted.
func TestDecodeManifest_DecryptsNamesFromMoreThanOneSample(t *testing.T) {
	key := bytes.Repeat([]byte{0x37}, 32)
	sha := make([]byte, 20)
	plain := encodeFileProto("readme.txt", 4, 0, sha, encodeChunkProto(sha, 0, 4, 4))
	encrypted := [][]byte{
		encodeFileProto(ciphertextName(t, "prototypes/vehicle.script", key), 4, 0, sha, encodeChunkProto(sha, 0, 4, 4)),
		encodeFileProto(ciphertextName(t, "scripts/4_shared/main.nut", key), 4, 0, sha, encodeChunkProto(sha, 0, 4, 4)),
		encodeFileProto(ciphertextName(t, "scripts/4_shared/client.nut", key), 4, 0, sha, encodeChunkProto(sha, 0, 4, 4)),
	}
	// The plain name comes first, which is the sample the old check used.
	raw := lenPrefixedSection(encodePayloadProto(append([][]byte{plain}, encrypted...)...))

	m, err := decodeManifest(raw, key, 3441461, 42)
	if err != nil {
		t.Fatalf("decodeManifest: %v", err)
	}
	want := []string{"prototypes/vehicle.script", "readme.txt", "scripts/4_shared/client.nut", "scripts/4_shared/main.nut"}
	got := make([]string, 0, len(m.Files))
	for _, f := range m.Files {
		got = append(got, f.Path)
	}
	if len(got) != len(want) {
		t.Fatalf("paths = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("paths = %q, want %q", got, want)
		}
	}
}

// A manifest whose names do not decrypt is refused rather than installed as a
// folder of blobs, which is what a mod flattened into its root looks like.
func TestDecodeManifest_RefusesNamesThatDidNotDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x51}, 32)
	wrong := bytes.Repeat([]byte{0x52}, 32)
	sha := make([]byte, 20)
	var files [][]byte
	for _, path := range []string{"a/a.txt", "b/b.txt", "c/c.txt", "d/d.txt", "e/e.txt", "f/f.txt"} {
		files = append(files, encodeFileProto(ciphertextName(t, path, key), 4, 0, sha, encodeChunkProto(sha, 0, 4, 4)))
	}
	raw := lenPrefixedSection(encodePayloadProto(files...))

	if _, err := decodeManifest(raw, wrong, 3441461, 42); err == nil {
		t.Fatal("expected an error for names that did not decrypt")
	}
}

func TestDownloadManifest_TLS(t *testing.T) {
	sha := make([]byte, 20)
	sha[0] = 0x11
	file := encodeFileProto("a.bin", 4, 0, sha, encodeChunkProto(sha, 0, 4, 4))
	payload := encodePayloadProto(file)
	raw := lenPrefixedSection(payload)

	var gotPath string
	server, client, closeFn := serveTLS(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write(raw) //nolint:errcheck
	})
	defer closeFn()

	m, err := DownloadManifest(context.Background(), client, server, 1006, 9999, nil, "", 12345)
	if err != nil {
		t.Fatalf("DownloadManifest: %v", err)
	}
	if len(m.Files) != 1 {
		t.Errorf("expected 1 file, got %d", len(m.Files))
	}
	// manifestRequestCode>0 → request code appended to the path.
	wantPath := "/depot/1006/manifest/9999/5/12345"
	if gotPath != wantPath {
		t.Errorf("manifest path = %q, want %q", gotPath, wantPath)
	}
}

func TestDownloadManifest_HTTPError(t *testing.T) {
	server, client, closeFn := serveTLS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer closeFn()
	if _, err := DownloadManifest(context.Background(), client, server, 1, 2, nil, "", 0); err == nil {
		t.Error("expected error on HTTP 404")
	}
}

func TestLZMADecompressInvalid(t *testing.T) {
	if _, err := lzmaDecompress([]byte{0x00}); err == nil {
		t.Error("expected error decoding invalid lzma")
	}
}

// Regression test: corrupted/non-LZMA input whose first bytes happen to
// parse as an LZMA header with a bogus multi-gigabyte dictionary capacity
// used to make lzma.NewReader allocate that much memory up front and OOM
// the process. lzmaDecompress must reject it via ValidHeader before ever
// calling into the lzma package.
func TestLZMADecompressRejectsBogusDictCap(t *testing.T) {
	data := make([]byte, lzma.HeaderLen+16)
	data[0] = 0x5D // valid LZMA properties byte (lc=3, lp=0, pb=2)
	// Bytes [1:5]: dictCap = 0xe12c0181 (~3.77 GiB), the value observed in
	// the crash — not a power-of-two-ish size a real encoder would emit.
	binary.LittleEndian.PutUint32(data[1:5], 0xe12c0181)
	// Bytes [5:13]: uncompressed size, left as "unknown" (all 0xFF).
	for i := 5; i < 13; i++ {
		data[i] = 0xFF
	}

	if _, err := lzmaDecompress(data); err == nil {
		t.Error("expected error rejecting bogus dictionary capacity, got nil")
	}
}

// guards against accidental change to the SHA1 size assumption in ChunkInfo.
func TestSHA1Size(t *testing.T) {
	h := sha1.New() //nolint:gosec
	if h.Size() != 20 {
		t.Fatalf("sha1 size = %d, want 20", h.Size())
	}
}
