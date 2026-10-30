package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	githubAPIBase = "https://api.github.com"
	repository    = "XTLS/Xray-core"
)

type Client struct {
	HTTP *http.Client
}

type Release struct {
	ID          int64   `json:"id"`
	TagName     string  `json:"tag_name"`
	Name        string  `json:"name"`
	Draft       bool    `json:"draft"`
	Prerelease  bool    `json:"prerelease"`
	PublishedAt string  `json:"published_at"`
	Assets      []Asset `json:"assets"`
}

type Asset struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"`
}

type ImportedRelease struct {
	Version            string `json:"version"`
	DownloadURL        string `json:"download_url"`
	SHA256             string `json:"sha256"`
	UpstreamPrerelease bool   `json:"upstream_prerelease"`
	ReleaseID          int64  `json:"github_release_id"`
	AssetID            int64  `json:"github_asset_id"`
	AssetName          string `json:"asset_name"`
	PublishedAt        string `json:"published_at"`
}

func NewClient() *Client {
	return &Client{
		HTTP: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (c *Client) LatestLinuxAMD64(
	ctx context.Context,
) (ImportedRelease, error) {

	releases, err := c.listReleases(ctx)
	if err != nil {
		return ImportedRelease{}, err
	}

	for _, release := range releases {
		if release.Draft {
			continue
		}

		result, err :=
			c.releaseLinuxAMD64(
				ctx,
				release,
			)

		if err == nil {
			return result, nil
		}

		if !errors.Is(
			err,
			errAssetNotFound,
		) {
			return ImportedRelease{}, err
		}
	}

	return ImportedRelease{},
		errors.New(
			"no usable Xray linux amd64 release found",
		)
}

var errAssetNotFound = errors.New("required release asset not found")

func (c *Client) listReleases(
	ctx context.Context,
) ([]Release, error) {

	url := githubAPIBase +
		"/repos/" +
		repository +
		"/releases?per_page=20"

	req, err :=
		http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			url,
			nil,
		)

	if err != nil {
		return nil, err
	}

	setGitHubHeaders(req)

	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(
			io.LimitReader(
				res.Body,
				4096,
			),
		)

		return nil, fmt.Errorf(
			"github releases API: %s: %s",
			res.Status,
			strings.TrimSpace(
				string(body),
			),
		)
	}

	var releases []Release

	if err := json.NewDecoder(
		res.Body,
	).Decode(&releases); err != nil {
		return nil, err
	}

	return releases, nil
}

func (c *Client) releaseLinuxAMD64(
	ctx context.Context,
	release Release,
) (ImportedRelease, error) {

	const zipName = "Xray-linux-64.zip"

	const digestName = "Xray-linux-64.zip.dgst"

	var zip Asset
	var digest Asset

	for _, asset := range release.Assets {
		switch asset.Name {
		case zipName:
			zip = asset

		case digestName:
			digest = asset
		}
	}

	if zip.BrowserDownloadURL == "" {
		return ImportedRelease{},
			errAssetNotFound
	}

	if !strings.HasPrefix(
		zip.BrowserDownloadURL,
		"https://github.com/XTLS/Xray-core/releases/download/",
	) {
		return ImportedRelease{},
			errors.New(
				"unexpected Xray asset download host/path",
			)
	}

	sha256 :=
		parseGitHubDigest(
			zip.Digest,
		)

	if sha256 == "" {
		if digest.BrowserDownloadURL == "" {
			return ImportedRelease{},
				errors.New(
					"Xray release has no usable SHA256 digest",
				)
		}

		var err error

		sha256, err =
			c.fetchDigest(
				ctx,
				digest.BrowserDownloadURL,
			)

		if err != nil {
			return ImportedRelease{}, err
		}
	}

	version :=
		strings.TrimPrefix(
			release.TagName,
			"v",
		)

	if version == "" {
		return ImportedRelease{},
			errors.New(
				"Xray release has empty version",
			)
	}

	return ImportedRelease{
		Version: version,

		DownloadURL: zip.BrowserDownloadURL,

		SHA256: sha256,

		UpstreamPrerelease: release.Prerelease,

		ReleaseID: release.ID,

		AssetID: zip.ID,

		AssetName: zip.Name,

		PublishedAt: release.PublishedAt,
	}, nil
}

func parseGitHubDigest(
	value string,
) string {

	value =
		strings.TrimSpace(
			strings.ToLower(value),
		)

	if !strings.HasPrefix(
		value,
		"sha256:",
	) {
		return ""
	}

	hash :=
		strings.TrimPrefix(
			value,
			"sha256:",
		)

	if !validSHA256(hash) {
		return ""
	}

	return hash
}

func (c *Client) fetchDigest(
	ctx context.Context,
	url string,
) (string, error) {

	if !strings.HasPrefix(
		url,
		"https://github.com/XTLS/Xray-core/releases/download/",
	) {
		return "", errors.New(
			"unexpected Xray digest download host/path",
		)
	}

	req, err :=
		http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			url,
			nil,
		)

	if err != nil {
		return "", err
	}

	req.Header.Set(
		"User-Agent",
		"vpn-platform-control-plane",
	)

	res, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf(
			"xray digest download: %s",
			res.Status,
		)
	}

	raw, err := io.ReadAll(
		io.LimitReader(
			res.Body,
			64*1024,
		),
	)

	if err != nil {
		return "", err
	}

	return parseDGST(string(raw))
}

var sha256Regexp = regexp.MustCompile(
	`(?i)\b[0-9a-f]{64}\b`,
)

func parseDGST(
	raw string,
) (string, error) {

	for _, line := range strings.Split(
		raw,
		"\n",
	) {
		lower :=
			strings.ToLower(line)

		if !strings.Contains(
			lower,
			"sha256",
		) &&
			!strings.Contains(
				lower,
				"sha2-256",
			) {
			continue
		}

		hash :=
			sha256Regexp.FindString(
				line,
			)

		if hash != "" {
			return strings.ToLower(hash),
				nil
		}
	}

	return "", errors.New(
		"sha256 not found in Xray .dgst asset",
	)
}

func validSHA256(
	value string,
) bool {

	if len(value) != 64 {
		return false
	}

	for _, char := range value {
		isDigit :=
			char >= '0' &&
				char <= '9'

		isHex :=
			char >= 'a' &&
				char <= 'f'

		if !isDigit && !isHex {
			return false
		}
	}

	return true
}

func setGitHubHeaders(
	req *http.Request,
) {
	req.Header.Set(
		"Accept",
		"application/vnd.github+json",
	)

	req.Header.Set(
		"X-GitHub-Api-Version",
		"2026-03-10",
	)

	req.Header.Set(
		"User-Agent",
		"vpn-platform-control-plane",
	)
}

func (c *Client) LinuxAMD64ByVersion(
	ctx context.Context,
	version string,
) (ImportedRelease, error) {

	version = strings.TrimSpace(
		strings.TrimPrefix(version, "v"),
	)

	if version == "" {
		return ImportedRelease{},
			errors.New("Xray version is required")
	}

	for _, char := range version {
		isDigit :=
			char >= '0' && char <= '9'

		isDot :=
			char == '.'

		if !isDigit && !isDot {
			return ImportedRelease{},
				errors.New(
					"invalid Xray version",
				)
		}
	}

	apiURL :=
		githubAPIBase +
			"/repos/" +
			repository +
			"/releases/tags/v" +
			version

	req, err :=
		http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			apiURL,
			nil,
		)

	if err != nil {
		return ImportedRelease{}, err
	}

	setGitHubHeaders(req)

	res, err := c.HTTP.Do(req)
	if err != nil {
		return ImportedRelease{}, err
	}

	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		return ImportedRelease{},
			errors.New(
				"Xray upstream release not found",
			)
	}

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(
			io.LimitReader(
				res.Body,
				4096,
			),
		)

		return ImportedRelease{},
			fmt.Errorf(
				"github release API: %s: %s",
				res.Status,
				strings.TrimSpace(
					string(body),
				),
			)
	}

	var release Release

	if err := json.NewDecoder(
		res.Body,
	).Decode(&release); err != nil {
		return ImportedRelease{}, err
	}

	if release.Draft {
		return ImportedRelease{},
			errors.New(
				"Xray upstream release is draft",
			)
	}

	return c.releaseLinuxAMD64(
		ctx,
		release,
	)
}

func (c *Client) RecentLinuxAMD64(
	ctx context.Context,
	limit int,
) ([]ImportedRelease, error) {

	if limit < 1 {
		return nil,
			errors.New("release limit must be greater than zero")
	}

	if limit > 50 {
		limit = 50
	}

	apiURL :=
		fmt.Sprintf(
			"%s/repos/%s/releases?per_page=%d",
			githubAPIBase,
			repository,
			limit,
		)

	req, err :=
		http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			apiURL,
			nil,
		)

	if err != nil {
		return nil, err
	}

	setGitHubHeaders(req)

	res, err :=
		c.HTTP.Do(req)

	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ :=
			io.ReadAll(
				io.LimitReader(
					res.Body,
					4096,
				),
			)

		return nil,
			fmt.Errorf(
				"github releases API: %s: %s",
				res.Status,
				strings.TrimSpace(
					string(body),
				),
			)
	}

	var releases []Release

	if err :=
		json.NewDecoder(
			res.Body,
		).Decode(&releases); err != nil {

		return nil, err
	}

	imported :=
		make(
			[]ImportedRelease,
			0,
			len(releases),
		)

	for _, release := range releases {

		if release.Draft {
			continue
		}

		item, err :=
			c.releaseLinuxAMD64(
				ctx,
				release,
			)

		if err != nil {
			// A release without the expected linux/amd64
			// artifact must not break discovery of all
			// remaining releases.
			continue
		}

		imported =
			append(
				imported,
				item,
			)
	}

	if len(imported) == 0 {
		return nil,
			errors.New(
				"no usable Xray linux/amd64 releases found",
			)
	}

	return imported, nil
}
