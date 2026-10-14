package repository

// GitHub owner (organization or user) repository listing for fleet import.
// It never clones and never follows redirects, and it shares the error
// statuses of the single-repository importer. /users/{owner}/repos serves
// both user and organization accounts, so one path covers both.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/d01ki/PatchTriage-go/internal/ingest"
)

const (
	DefaultRepoLimit   = 10
	maxRepoLimit       = 100
	listPerPage        = 100
	listMaxPages       = 5 // 500 repositories scanned is plenty for a triage fleet
	listTimeout        = 30 * time.Second
	maxListingBodySize = 32 * 1024 * 1024
)

// OwnerReference is a validated GitHub account.
type OwnerReference struct{ OriginalURL, NormalizedURL, Owner string }

// OwnerRepo is one listed repository, reduced to what fleet import needs.
type OwnerRepo struct {
	FullName, HTMLURL, DefaultBranch, PushedAt string
	Fork, Archived                             bool
}

// OwnerListing is the selected repositories plus what was filtered and why:
// a fleet result must be explainable as "these repositories, chosen by this
// rule", never a silent subset.
type OwnerListing struct {
	Reference                                  OwnerReference
	Repositories                               []OwnerRepo
	TotalListed, SkippedForks, SkippedArchived int
	Truncated                                  bool
	Warnings                                   []string
}

// NormalizeOwner validates https://github.com/OWNER and nothing broader; a
// URL with a repository belongs to the single-repository importer.
func NormalizeOwner(value string) (OwnerReference, error) {
	candidate := strings.TrimSpace(value)
	switch {
	case candidate == "":
		return OwnerReference{}, invalidURL("organization URL is required")
	case hasControl(candidate):
		return OwnerReference{}, invalidURL("organization URL contains control characters")
	case strings.Contains(candidate, `\`):
		return OwnerReference{}, invalidURL("organization URL must use forward slashes")
	}
	scheme, netloc, path, query, fragment := splitURL(candidate)
	if !strings.EqualFold(scheme, "https") {
		return OwnerReference{}, invalidURL("organization URL must use HTTPS")
	}
	hostport := netloc[strings.LastIndex(netloc, "@")+1:]
	host, port, hasPort := strings.Cut(hostport, ":")
	if n, err := strconv.Atoi(port); hasPort && port != "" && (err != nil || n < 0 || n > 65535) {
		return OwnerReference{}, invalidURL("organization URL is malformed")
	}
	if !strings.EqualFold(host, githubHost) {
		return OwnerReference{}, invalidURL("organization import currently supports github.com accounts only")
	}
	if port != "" && strings.TrimLeft(port, "0") != "443" {
		return OwnerReference{}, invalidURL("github.com organization URLs may not use a custom port")
	}
	if strings.Contains(netloc, "@") {
		return OwnerReference{}, invalidURL("organization URL must not contain user information")
	}
	if query != "" || fragment != "" {
		return OwnerReference{}, invalidURL("organization URL must not contain query or fragment parts")
	}
	var segments []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			segments = append(segments, s)
		}
	}
	if len(segments) != 1 {
		return OwnerReference{}, invalidURL("organization URL must be https://github.com/<owner>; a specific " +
			"repository belongs in the repository importer")
	}
	owner := segments[0]
	if !ownerPattern.MatchString(owner) || strings.Contains(owner, "--") {
		return OwnerReference{}, invalidURL("organization URL contains an invalid account name")
	}
	return OwnerReference{candidate, "https://" + githubHost + "/" + owner, owner}, nil
}

func listStatusError(resp *http.Response) *Error {
	switch status := resp.StatusCode; {
	case status == 404:
		return newError(404, "GitHub account was not found or has no visible repositories")
	case status == 429 || status == 403 && resp.Header.Get("x-ratelimit-remaining") == "0":
		e := newError(429, "GitHub API rate limit reached while listing repositories; retry later or configure GITHUB_TOKEN")
		e.RetryAfter = resp.Header.Get("retry-after")
		if e.RetryAfter == "" {
			e.RetryAfter = resp.Header.Get("x-ratelimit-reset")
		}
		return e
	case status == 401 || status == 403:
		return newError(403, "GitHub denied the repository listing request")
	case status >= 300 && status < 400:
		return fetchError("GitHub API returned an unexpected redirect; the repository listing did not follow it")
	default:
		return fetchError("GitHub repository listing returned HTTP %d", status)
	}
}

func parseRepoEntry(raw json.RawMessage) (OwnerRepo, bool) {
	var entry map[string]any
	if json.Unmarshal(raw, &entry) != nil || entry == nil {
		return OwnerRepo{}, false
	}
	fullName, _ := entry["full_name"].(string)
	htmlURL, _ := entry["html_url"].(string)
	if !strings.Contains(fullName, "/") || !strings.HasPrefix(htmlURL, "https://"+githubHost+"/") {
		return OwnerRepo{}, false
	}
	text := func(key string) string {
		if v := entry[key]; ingest.Truthy(v) {
			return fmt.Sprint(v)
		}
		return ""
	}
	return OwnerRepo{FullName: fullName, HTMLURL: htmlURL, DefaultBranch: text("default_branch"),
		PushedAt: text("pushed_at"), Fork: ingest.Truthy(entry["fork"]), Archived: ingest.Truthy(entry["archived"])}, true
}

// ListOwner lists an account's public repositories, newest activity first.
// limit bounds the selected repositories. Forks are skipped by default (a
// fork's graph usually restates its upstream) and so are archived
// repositories (they no longer receive the patches this tool schedules).
func (g GitHub) ListOwner(ctx context.Context, ref OwnerReference, token string, limit int, includeForks, includeArchived bool) (OwnerListing, error) {
	if limit <= 0 {
		return OwnerListing{}, newError(400, "limit must be a positive integer")
	}
	limit = min(limit, maxRepoLimit)
	g = g.withDefaults()
	g.Timeout = listTimeout
	headers := map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
		"User-Agent": "patchtriage/0.6"}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	listing := OwnerListing{Reference: ref, Repositories: []OwnerRepo{}, Warnings: []string{}}
	exhausted := true
	for page := 1; page <= listMaxPages; page++ {
		target := fmt.Sprintf("%s/users/%s/repos?per_page=%d&page=%d&sort=pushed&direction=desc",
			g.APIRoot, ingest.PyQuote(ref.Owner, ""), listPerPage, page)
		resp, cancel, err := g.get(ctx, target, headers)
		if err != nil {
			if errorClass(err) == "TimeoutException" {
				return OwnerListing{}, fetchError("GitHub repository listing timed out")
			}
			return OwnerListing{}, fetchError("GitHub repository listing failed: %s", errorClass(err))
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxListingBodySize))
		resp.Body.Close()
		cancel()
		if resp.StatusCode != 200 {
			return OwnerListing{}, listStatusError(resp)
		}
		var payload []json.RawMessage
		if readErr != nil || !utf8.Valid(raw) || !json.Valid(raw) {
			return OwnerListing{}, fetchError("GitHub repository listing is not valid JSON")
		}
		if json.Unmarshal(raw, &payload) != nil || payload == nil {
			return OwnerListing{}, fetchError("GitHub repository listing has an unexpected shape")
		}
		for _, entry := range payload {
			repo, ok := parseRepoEntry(entry)
			if !ok {
				continue
			}
			listing.TotalListed++
			switch {
			case repo.Fork && !includeForks:
				listing.SkippedForks++
			case repo.Archived && !includeArchived:
				listing.SkippedArchived++
			case len(listing.Repositories) >= limit:
				listing.Truncated = true
			default:
				listing.Repositories = append(listing.Repositories, repo)
			}
		}
		if len(payload) < listPerPage {
			exhausted = false
			break
		}
	}
	if exhausted {
		listing.Truncated = true
		listing.Warnings = append(listing.Warnings, fmt.Sprintf("Listing stopped after %d repositories; the account "+
			"owns more than were examined.", listMaxPages*listPerPage))
	}
	if listing.Truncated && len(listing.Repositories) >= limit {
		listing.Warnings = append(listing.Warnings, fmt.Sprintf("Repository selection was capped at %d; additional "+
			"repositories exist and were not imported.", limit))
	}
	return listing, nil
}
