package smtroot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

const (
	DefaultGitHubRepo = "privacy-ethereum/moica-revocation-smt"
	// Upstream CI refreshes this tag twice a day.
	DefaultGitHubTag = "snapshot-latest"
)

// GitHubReleaseSource parses roots from the release body markdown rather than
// the ~70 MB snapshot asset.
type GitHubReleaseSource struct {
	Repo      string
	Tag       string
	APIBase   string // test override; defaults to https://api.github.com
	Client    *http.Client
	UserAgent string
}

func NewGitHubReleaseSource(repo, tag string, timeout time.Duration) *GitHubReleaseSource {
	if repo == "" {
		repo = DefaultGitHubRepo
	}
	if tag == "" {
		tag = DefaultGitHubTag
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &GitHubReleaseSource{
		Repo:      repo,
		Tag:       tag,
		APIBase:   "https://api.github.com",
		Client:    &http.Client{Timeout: timeout},
		UserAgent: "go-zkid-verifier",
	}
}

func (s *GitHubReleaseSource) Name() string { return "github" }

func (s *GitHubReleaseSource) FetchAll(ctx context.Context) (map[IssuerID]Root, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/tags/%s", s.APIBase, s.Repo, s.Tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if s.UserAgent != "" {
		req.Header.Set("User-Agent", s.UserAgent)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var payload struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}

	return parseReleaseBody(payload.Body)
}

// parseReleaseBody requires every issuer to be present so a partial upstream
// update cannot silently overwrite the cache.
func parseReleaseBody(body string) (map[IssuerID]Root, error) {
	out := make(map[IssuerID]Root, len(AllIssuers))
	for _, issuer := range AllIssuers {
		m := issuerRootRegex[issuer].FindStringSubmatch(body)
		if len(m) < 2 {
			return nil, fmt.Errorf("release body missing root for %s", issuer.LongName())
		}
		r, err := ParseRoot(m[1])
		if err != nil {
			return nil, fmt.Errorf("parse %s root: %w", issuer.LongName(), err)
		}
		out[issuer] = r
	}
	return out, nil
}

// Populated in init(); FetchAll may run concurrently and lazy init would race.
var issuerRootRegex = map[IssuerID]*regexp.Regexp{}

func init() {
	for _, issuer := range AllIssuers {
		pattern := `(?is)###\s*` + regexp.QuoteMeta(shortHeader(issuer)) + `\b.*?\*\*Root:\*\*\s*` + "`?0x([0-9a-fA-F]{64})`?"
		issuerRootRegex[issuer] = regexp.MustCompile(pattern)
	}
}

func shortHeader(issuer IssuerID) string {
	switch issuer {
	case IssuerG2:
		return "G2"
	case IssuerG3:
		return "G3"
	default:
		return issuer.LongName()
	}
}
