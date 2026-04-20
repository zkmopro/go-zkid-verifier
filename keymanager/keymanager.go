package keymanager

import (
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

const releaseURL = "https://github.com/zkmopro/zkID/releases/download/latest"

// RequiredKeys lists the verifying key files needed for link-verify.
var RequiredKeys = []string{
	"cert_chain_rs2048_verifying.key",
	"cert_chain_rs4096_verifying.key",
	"device_sig_rs2048_verifying.key",
}

// EnsureKeys checks for each required verifying key in keysDir and downloads
// any missing keys from the zkID GitHub release. Returns an error if any
// download fails.
func EnsureKeys(keysDir string) error {
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		return fmt.Errorf("create keys dir: %w", err)
	}

	for _, key := range RequiredKeys {
		dest := filepath.Join(keysDir, key)
		if _, err := os.Stat(dest); err == nil {
			log.Printf("  %s exists, skipping", key)
			continue
		}

		if err := downloadAndDecompress(key, dest); err != nil {
			return fmt.Errorf("download %s: %w", key, err)
		}
		log.Printf("  %s downloaded", key)
	}
	return nil
}

func downloadAndDecompress(key, dest string) error {
	url := fmt.Sprintf("%s/%s.gz", releaseURL, key)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("create %s: %w", dest, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, gz); err != nil {
		os.Remove(dest)
		return fmt.Errorf("decompress %s: %w", key, err)
	}

	return nil
}
