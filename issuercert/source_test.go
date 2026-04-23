package issuercert

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readEmbeddedCert(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("certs", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func newTestProvider(t *testing.T, sources map[IssuerID]Source) *Provider {
	t.Helper()
	p, err := NewProvider(Config{
		Sources:         sources,
		RefreshInterval: time.Hour,
		FetchTimeout:    2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	p.now = func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }
	return p
}

func TestFetchNow_SuccessReplacesEmbedded(t *testing.T) {
	g2Bytes := readEmbeddedCert(t, "moica-g2.cer")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Write(g2Bytes)
	}))
	defer srv.Close()

	p := newTestProvider(t, map[IssuerID]Source{
		IssuerG2: NewHTTPSource(IssuerG2, srv.URL, time.Second),
	})

	before, ok := p.Trusted(IssuerG2)
	if !ok {
		t.Fatal("embedded G2 missing before fetch")
	}
	if before.Source != "embedded" {
		t.Fatalf("pre-fetch source: got %q, want \"embedded\"", before.Source)
	}

	if err := p.FetchNow(context.Background(), "test"); err != nil {
		t.Fatalf("FetchNow: %v", err)
	}
	after, ok := p.Trusted(IssuerG2)
	if !ok {
		t.Fatal("G2 missing after fetch")
	}
	if after.Source != "https" {
		t.Errorf("post-fetch source: got %q, want \"https\"", after.Source)
	}
	if after.SHA256 != before.SHA256 {
		t.Error("fetched cert fingerprint differs from embedded (should match — same bytes)")
	}
}

func TestFetchNow_WrongFingerprintIsRejected(t *testing.T) {
	g3Bytes := readEmbeddedCert(t, "moica-g3.cer")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(g3Bytes)
	}))
	defer srv.Close()

	p := newTestProvider(t, map[IssuerID]Source{
		IssuerG2: NewHTTPSource(IssuerG2, srv.URL, time.Second),
	})
	before, _ := p.Trusted(IssuerG2)

	err := p.FetchNow(context.Background(), "test")
	if err == nil {
		t.Fatal("FetchNow: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Errorf("error should mention fingerprint mismatch: %v", err)
	}

	after, _ := p.Trusted(IssuerG2)
	if after.Source != "embedded" {
		t.Errorf("post-failure source: got %q, want \"embedded\"", after.Source)
	}
	if after.SHA256 != before.SHA256 {
		t.Error("cached record mutated on failed fetch")
	}
}

func TestFetchNow_HTTP500KeepsCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := newTestProvider(t, map[IssuerID]Source{
		IssuerG2: NewHTTPSource(IssuerG2, srv.URL, time.Second),
	})
	before, _ := p.Trusted(IssuerG2)

	if err := p.FetchNow(context.Background(), "test"); err == nil {
		t.Fatal("FetchNow: expected error")
	}
	after, _ := p.Trusted(IssuerG2)
	if after.Source != before.Source || after.SHA256 != before.SHA256 {
		t.Error("cache mutated on HTTP 500")
	}
	st := p.Status()
	if st.ConsecutiveFail != 1 {
		t.Errorf("ConsecutiveFail: got %d, want 1", st.ConsecutiveFail)
	}
	if st.LastError == "" {
		t.Error("Status.LastError should be set after failed fetch")
	}
}

func TestFetchNow_TruncatedBodyIsRejected(t *testing.T) {
	g2Bytes := readEmbeddedCert(t, "moica-g2.cer")
	truncated := g2Bytes[:len(g2Bytes)-10]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(truncated)
	}))
	defer srv.Close()

	p := newTestProvider(t, map[IssuerID]Source{
		IssuerG2: NewHTTPSource(IssuerG2, srv.URL, time.Second),
	})
	if err := p.FetchNow(context.Background(), "test"); err == nil {
		t.Fatal("FetchNow: expected error")
	}
	after, _ := p.Trusted(IssuerG2)
	if after.Source != "embedded" {
		t.Errorf("cache mutated on truncated fetch: source=%q", after.Source)
	}
}

func TestFetchNow_OversizedBodyIsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, maxCertBodyBytes+1))
	}))
	defer srv.Close()

	p := newTestProvider(t, map[IssuerID]Source{
		IssuerG2: NewHTTPSource(IssuerG2, srv.URL, time.Second),
	})
	if err := p.FetchNow(context.Background(), "test"); err == nil {
		t.Fatal("FetchNow: expected error")
	}
}

func TestFetchNow_ClearsConsecutiveFailOnSuccess(t *testing.T) {
	g2Bytes := readEmbeddedCert(t, "moica-g2.cer")
	var fail bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Write(g2Bytes)
	}))
	defer srv.Close()

	p := newTestProvider(t, map[IssuerID]Source{
		IssuerG2: NewHTTPSource(IssuerG2, srv.URL, time.Second),
	})

	fail = true
	_ = p.FetchNow(context.Background(), "test")
	if got := p.Status().ConsecutiveFail; got != 1 {
		t.Fatalf("after fail: got %d, want 1", got)
	}
	fail = false
	if err := p.FetchNow(context.Background(), "test"); err != nil {
		t.Fatalf("FetchNow success: %v", err)
	}
	if got := p.Status().ConsecutiveFail; got != 0 {
		t.Errorf("after success: got %d, want 0", got)
	}
}
