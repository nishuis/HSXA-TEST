// Package client implements the bfp-cli side of the identify protocol: HTTP
// submission with retries and batching, input parsing and output rendering.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"hsxa-banner-fingerprint/internal/model"
	"hsxa-banner-fingerprint/internal/version"
)

// ErrUnreachable reports that the server could not be reached at all; bfp-cli
// maps it to exit code 3.
var ErrUnreachable = errors.New("bfp-server is unreachable")

// Client talks to a bfp-server instance.
type Client struct {
	baseURL string
	http    *http.Client
	retries int
}

// New returns a client for baseURL, retrying network errors and 5xx responses
// up to retries times with an exponential backoff.
func New(baseURL string, timeout time.Duration, retries int) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: timeout},
		retries: retries,
	}
}

// Ping checks that the server is up and returns its metadata.
func (c *Client) Ping(ctx context.Context) (model.Meta, error) {
	var meta model.Meta
	body, err := c.do(ctx, http.MethodGet, "/api/v1/meta", "")
	if err != nil {
		return meta, err
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return meta, fmt.Errorf("decode meta response: %w", err)
	}
	return meta, nil
}

// Identify submits one batch and returns its results in input order.
func (c *Client) Identify(ctx context.Context, records []model.ScanRecord) ([]model.Result, error) {
	payload, err := json.Marshal(model.Request{Records: records})
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	body, err := c.do(ctx, http.MethodPost, "/api/v1/identify", string(payload))
	if err != nil {
		return nil, err
	}
	var envelope model.Response
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Results != nil {
		return envelope.Results, nil
	}
	var results []model.Result
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("decode identify response: %w", err)
	}
	return results, nil
}

// IdentifyBatched submits records in batches of batchSize with at most
// concurrency requests in flight. Results keep the input order and always have
// the same length as records; a failed batch contributes degraded results and
// increments failed.
func (c *Client) IdentifyBatched(
	ctx context.Context,
	records []model.ScanRecord,
	batchSize, concurrency int,
	failFast bool,
) (results []model.Result, failed int, err error) {
	if batchSize < 1 {
		batchSize = len(records)
	}
	if concurrency < 1 {
		concurrency = 1
	}
	results = make([]model.Result, len(records))
	// Pre-fill with the degraded result so the output is 1:1 with the input
	// even when a batch never reaches the server; successful batches overwrite
	// their slice.
	for i, rec := range records {
		results[i] = model.Unknown(rec.IP, rec.Port)
	}
	type batch struct{ from, to int }
	var batches []batch
	for from := 0; from < len(records); from += batchSize {
		to := from + batchSize
		if to > len(records) {
			to = len(records)
		}
		batches = append(batches, batch{from: from, to: to})
	}

	sem := make(chan struct{}, concurrency)
	done := make(chan error, len(batches))
	var firstErr error
	for _, b := range batches {
		sem <- struct{}{}
		go func(b batch) {
			defer func() { <-sem }()
			out, err := c.Identify(ctx, records[b.from:b.to])
			if err != nil {
				done <- err
				return
			}
			if len(out) != b.to-b.from {
				done <- fmt.Errorf("server returned %d results for %d records", len(out), b.to-b.from)
				return
			}
			copy(results[b.from:b.to], out)
			done <- nil
		}(b)
	}
	for range batches {
		if err := <-done; err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return results, failed, firstErr
}

func (c *Client) do(ctx context.Context, method, path, body string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff(attempt)):
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, strings.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("User-Agent", "bfp-cli/"+version.Version)
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("%w: %w", ErrUnreachable, err)
			continue
		}
		payload, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("%w: read response: %w", ErrUnreachable, readErr)
			continue
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			return payload, nil
		case resp.StatusCode >= 500:
			// Transient: retry.
			lastErr = fmt.Errorf("server returned %s: %s", resp.Status, truncate(string(payload), 200))
		default:
			// A 4xx is a caller error, retrying cannot help.
			return nil, fmt.Errorf("server rejected the request with %s: %s",
				resp.Status, decodeErrorBody(payload))
		}
	}
	return nil, lastErr
}

// decodeErrorBody renders the server's error envelope as a readable message.
func decodeErrorBody(payload []byte) string {
	var envelope model.ErrorResponse
	if err := json.Unmarshal(payload, &envelope); err == nil && len(envelope.Errors) > 0 {
		var b bytes.Buffer
		for i, e := range envelope.Errors {
			if i > 0 {
				b.WriteString("; ")
			}
			if e.Index >= 0 {
				fmt.Fprintf(&b, "record %d: ", e.Index)
			}
			if e.Field != "" {
				fmt.Fprintf(&b, "%s: ", e.Field)
			}
			b.WriteString(e.Message)
		}
		return b.String()
	}
	return truncate(string(payload), 200)
}

func backoff(attempt int) time.Duration {
	d := 100 * time.Millisecond << uint(attempt-1)
	if d > 2*time.Second {
		d = 2 * time.Second
	}
	return d
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
