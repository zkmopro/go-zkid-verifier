package verifier

import (
	"os"
	"testing"
)

func TestLinkVerifyRS2048(t *testing.T) {
	baseDir := os.Getenv("ZK_BASE_DIR")
	if baseDir == "" {
		t.Skip("set ZK_BASE_DIR=/path/to/dir/containing/keys/ to run")
	}

	valid, err := LinkVerify(baseDir, CertChainRS2048)
	if err != nil {
		t.Fatalf("LinkVerify RS2048: %v", err)
	}
	if !valid {
		t.Fatal("expected link-verify RS2048 to pass")
	}
	t.Log("Link-verify RS2048 passed")
}

func TestLinkVerifyRS4096(t *testing.T) {
	baseDir := os.Getenv("ZK_BASE_DIR")
	if baseDir == "" {
		t.Skip("set ZK_BASE_DIR=/path/to/dir/containing/keys/ to run")
	}

	valid, err := LinkVerify(baseDir, CertChainRS4096)
	if err != nil {
		t.Fatalf("LinkVerify RS4096: %v", err)
	}
	if !valid {
		t.Fatal("expected link-verify RS4096 to pass")
	}
	t.Log("Link-verify RS4096 passed")
}
