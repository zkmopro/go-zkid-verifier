package verifier

import (
	"os"
	"testing"
)

func TestVerify(t *testing.T) {
	baseDir := os.Getenv("ZK_BASE_DIR")
	if baseDir == "" {
		t.Skip("set ZK_BASE_DIR=/path/to/dir/containing/keys/ to run")
	}

	valid, err := Verify(baseDir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid {
		t.Fatal("expected proof to be valid")
	}
	t.Log("Proof verified successfully")
}
