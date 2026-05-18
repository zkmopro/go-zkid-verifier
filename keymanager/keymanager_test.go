package keymanager

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

func TestWriteBoundedAndHash_UnderLimit(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, 100)
	var dst bytes.Buffer

	h, err := writeBoundedAndHash(&dst, bytes.NewReader(payload), 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(dst.Bytes(), payload) {
		t.Fatalf("output mismatch: got %d bytes, want %d", dst.Len(), len(payload))
	}

	want := sha256.Sum256(payload)
	if got := hex.EncodeToString(h.Sum(nil)); got != hex.EncodeToString(want[:]) {
		t.Fatalf("sha256 mismatch: got %s", got)
	}
}

func TestWriteBoundedAndHash_ExactlyAtLimit(t *testing.T) {
	const limit int64 = 64
	payload := bytes.Repeat([]byte{0xCD}, int(limit))
	var dst bytes.Buffer

	if _, err := writeBoundedAndHash(&dst, bytes.NewReader(payload), limit); err != nil {
		t.Fatalf("expected success at exact limit, got: %v", err)
	}
	if dst.Len() != int(limit) {
		t.Fatalf("expected %d bytes written, got %d", limit, dst.Len())
	}
}

func TestWriteBoundedAndHash_OverLimitReturnsTruncated(t *testing.T) {
	const limit int64 = 64
	payload := bytes.Repeat([]byte{0xEF}, int(limit)+1)
	var dst bytes.Buffer

	_, err := writeBoundedAndHash(&dst, bytes.NewReader(payload), limit)
	if !errors.Is(err, errTruncated) {
		t.Fatalf("expected errTruncated, got: %v", err)
	}
}

func TestWriteBoundedAndHash_DetectsTruncationOnStutteringReader(t *testing.T) {
	const limit int64 = 8
	payload := bytes.Repeat([]byte{0x12}, int(limit)+5)
	r := iotest.OneByteReader(bytes.NewReader(payload))

	_, err := writeBoundedAndHash(io.Discard, r, limit)
	if !errors.Is(err, errTruncated) {
		t.Fatalf("expected errTruncated, got: %v", err)
	}
}

// setExpected mutates package-level state; callers must NOT use t.Parallel().
func setExpected(t *testing.T, key, hash string) {
	t.Helper()
	prev, had := expectedSHA256[key]
	t.Cleanup(func() {
		if had {
			expectedSHA256[key] = prev
		} else {
			delete(expectedSHA256, key)
		}
	})
	expectedSHA256[key] = hash
}

func writeTempKey(t *testing.T, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyFile_NoEntrySkips(t *testing.T) {
	path := writeTempKey(t, "anonymous.key", []byte("hi"))

	if err := verifyFile("not-in-manifest.key", path); !errors.Is(err, errSkipVerify) {
		t.Fatalf("expected errSkipVerify, got: %v", err)
	}
}

func TestVerifyFile_EmptyEntrySkips(t *testing.T) {
	setExpected(t, "temp.key", "")
	path := writeTempKey(t, "temp.key", []byte("hi"))

	if err := verifyFile("temp.key", path); !errors.Is(err, errSkipVerify) {
		t.Fatalf("expected errSkipVerify, got: %v", err)
	}
}

func TestVerifyFile_MatchSucceeds(t *testing.T) {
	contents := []byte("verifying-key-bytes")
	want := sha256.Sum256(contents)
	setExpected(t, "temp.key", hex.EncodeToString(want[:]))
	path := writeTempKey(t, "temp.key", contents)

	if err := verifyFile("temp.key", path); err != nil {
		t.Fatalf("expected match, got: %v", err)
	}
}

func TestVerifyFile_MismatchReturnsError(t *testing.T) {
	setExpected(t, "temp.key", strings.Repeat("00", sha256.Size))
	path := writeTempKey(t, "temp.key", []byte("something-else"))

	err := verifyFile("temp.key", path)
	if err == nil || errors.Is(err, errSkipVerify) {
		t.Fatalf("expected sha256 mismatch error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected mismatch error message, got: %v", err)
	}
}
