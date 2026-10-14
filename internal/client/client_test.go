package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hsxa-banner-fingerprint/internal/model"
)

func TestReadRecordsFormats(t *testing.T) {
	jsonArray := `[{"ip":"1.1.1.1","port":22,"banner":"SSH-2.0-x"}]`
	jsonEnvelope := `{"records":[{"ip":"1.1.1.2","port":80,"banner":"HTTP/1.1 200 OK"}]}`
	jsonSingle := `{"ip":"1.1.1.3","port":21,"banner":"220 x"}`
	jsonl := "{\"ip\":\"1.1.1.4\",\"port\":22,\"banner\":\"SSH-2.0-a\"}\n\n{\"ip\":\"1.1.1.5\",\"port\":22,\"banner\":\"SSH-2.0-b\"}\n"
	csvWithHeader := "ip,port,banner\n1.1.1.6,22,SSH-2.0-c\n1.1.1.7,80,\"HTTP/1.1 200 OK, with a comma\"\n"
	csvNoHeader := "1.1.1.8,22,SSH-2.0-d\n"

	tests := []struct {
		name   string
		format string
		input  string
		want   int
	}{
		{"json-array", "json", jsonArray, 1},
		{"json-envelope", "json", jsonEnvelope, 1},
		{"json-single", "json", jsonSingle, 1},
		{"jsonl", "jsonl", jsonl, 2},
		{"csv-header", "csv", csvWithHeader, 2},
		{"csv-no-header", "csv", csvNoHeader, 1},
		{"auto-array", "auto", jsonArray, 1},
		{"auto-envelope", "auto", jsonEnvelope, 1},
		{"auto-jsonl", "auto", jsonl, 2},
		{"auto-csv", "auto", csvWithHeader, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadRecords(strings.NewReader(tc.input), tc.format)
			if err != nil {
				t.Fatalf("ReadRecords: %v", err)
			}
			if len(got) != tc.want {
				t.Fatalf("got %d records, want %d", len(got), tc.want)
			}
		})
	}

	recs, err := ReadRecords(strings.NewReader(csvWithHeader), "csv")
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	if recs[1].Banner != "HTTP/1.1 200 OK, with a comma" {
		t.Errorf("quoted csv banner = %q", recs[1].Banner)
	}
	if recs[0].IP != "1.1.1.6" || recs[0].Port != 22 {
		t.Errorf("csv row = %+v", recs[0])
	}
}

func TestReadRecordsErrors(t *testing.T) {
	if _, err := ReadRecords(strings.NewReader("{not json"), "json"); err == nil {
		t.Error("invalid json accepted")
	}
	got, err := ReadRecords(strings.NewReader("ip,port,banner\n"), "csv")
	if err != nil || len(got) != 0 {
		t.Errorf("header-only csv = %v, %v; want no records and no error", got, err)
	}
	if _, err := ReadRecords(strings.NewReader("1.1.1.1,notaport,x"), "csv"); err == nil {
		t.Error("invalid csv port accepted")
	}
	if _, err := ReadRecords(strings.NewReader("plain text"), "auto"); err == nil {
		t.Error("undetectable input accepted")
	}
	if _, err := ReadRecords(strings.NewReader("x"), "xml"); err == nil {
		t.Error("unknown format accepted")
	}
	got, err = ReadRecords(strings.NewReader("  \n "), "auto")
	if err != nil || len(got) != 0 {
		t.Errorf("blank input = %v, %v", got, err)
	}
}

func TestWriteResultsFormats(t *testing.T) {
	results := []model.Result{
		{IP: "1.1.1.1", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95},
		{IP: "1.1.1.2", Port: 6379, Protocol: "Redis", Product: "Redis", Confidence: 0.7},
	}
	tests := []struct {
		format string
		check  func(t *testing.T, out string)
	}{
		{"array", func(t *testing.T, out string) {
			if !strings.HasPrefix(out, "[{") || !strings.HasSuffix(strings.TrimSpace(out), "]") {
				t.Errorf("not a bare array: %s", out)
			}
			var parsed []model.Result
			if err := json.Unmarshal([]byte(out), &parsed); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(parsed) != 2 || parsed[1].Version != "" {
				t.Errorf("parsed = %+v", parsed)
			}
			if strings.Contains(out, "null") {
				t.Errorf("null in output: %s", out)
			}
		}},
		{"json", func(t *testing.T, out string) {
			var parsed model.Response
			if err := json.Unmarshal([]byte(out), &parsed); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(parsed.Results) != 2 || parsed.Stats.Total != 2 {
				t.Errorf("parsed = %+v", parsed)
			}
		}},
		{"jsonl", func(t *testing.T, out string) {
			lines := strings.Split(strings.TrimSpace(out), "\n")
			if len(lines) != 2 {
				t.Fatalf("got %d lines", len(lines))
			}
			for _, line := range lines {
				var parsed model.Result
				if err := json.Unmarshal([]byte(line), &parsed); err != nil {
					t.Fatalf("decode line: %v", err)
				}
			}
		}},
		{"csv", func(t *testing.T, out string) {
			lines := strings.Split(strings.TrimSpace(out), "\n")
			if len(lines) != 3 {
				t.Fatalf("got %d lines, want a header and two rows", len(lines))
			}
			if lines[0] != "ip,port,protocol,product,version,os_hint,confidence" {
				t.Errorf("header = %q", lines[0])
			}
			if !strings.Contains(lines[1], "0.95") {
				t.Errorf("confidence should be two decimals: %q", lines[1])
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteResults(&buf, results, tc.format, false); err != nil {
				t.Fatalf("WriteResults: %v", err)
			}
			tc.check(t, buf.String())
		})
	}

	var buf bytes.Buffer
	if err := WriteResults(&buf, results, "array", true); err != nil {
		t.Fatalf("pretty: %v", err)
	}
	if !strings.Contains(buf.String(), "\n  {") {
		t.Errorf("pretty output not indented: %s", buf.String())
	}

	buf.Reset()
	if err := WriteResults(&buf, nil, "array", false); err != nil {
		t.Fatalf("nil results: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != "[]" {
		t.Errorf("nil results rendered as %q, want []", got)
	}

	if err := WriteResults(&buf, nil, "yaml", false); err == nil {
		t.Error("unknown output format accepted")
	}
}

func TestPrepareForTransport(t *testing.T) {
	records := []model.ScanRecord{
		{IP: "1.1.1.1", Port: 22, Banner: "SSH-2.0-x"},
		{IP: "1.1.1.2", Port: 445, Banner: string([]byte{0xff, 0xfe, 0x00, 0x01})},
		{IP: "1.1.1.3", Port: 23, Banner: string([]byte{0xff, 0xfd, 0x18}), Encoding: "text"},
	}
	got := PrepareForTransport(records)
	if got[0].BannerBase64 != "" {
		t.Error("a valid UTF-8 banner must not be re-encoded")
	}
	if got[1].Banner != "" || got[1].BannerBase64 == "" || got[1].Encoding != model.EncodingBase64 {
		t.Errorf("binary banner not moved to base64: %+v", got[1])
	}
	if got[2].Encoding != "text" || got[2].BannerBase64 != "" {
		t.Errorf("an explicit encoding must be left alone: %+v", got[2])
	}
}

// TestIdentifyRetryAndErrors checks the transport behaviour against a stub
// server: retry on 5xx, immediate failure on 4xx and the unreachable sentinel.
func TestIdentifyRetryAndErrors(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"ip":"1.1.1.1","port":22,"protocol":"SSH","product":"OpenSSH","version":"","os_hint":"","confidence":0.9}]}`))
	}))
	defer srv.Close()

	cli := New(srv.URL, 5*time.Second, 2)
	results, err := cli.Identify(context.Background(), []model.ScanRecord{{IP: "1.1.1.1", Port: 22}})
	if err != nil {
		t.Fatalf("Identify should have retried past the 500: %v", err)
	}
	if len(results) != 1 || results[0].Protocol != "SSH" {
		t.Errorf("results = %+v", results)
	}
	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("attempts = %d, want 2", attempts)
	}

	// A 400 is not retried.
	client400 := New(srv.URL, 5*time.Second, 3)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":[{"index":1,"field":"port","message":"port 0 is outside 1-65535"}]}`))
	}))
	defer bad.Close()
	client400.baseURL = bad.URL
	if _, err := client400.Identify(context.Background(), nil); err == nil {
		t.Error("a 400 must surface as an error")
	} else if !strings.Contains(err.Error(), "record 1") {
		t.Errorf("error should locate the record: %v", err)
	}

	// An unreachable server maps to ErrUnreachable after the retries.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	unreachable := New(deadURL, 500*time.Millisecond, 1)
	if _, err := unreachable.Identify(context.Background(), nil); !errors.Is(err, ErrUnreachable) {
		t.Errorf("error = %v, want ErrUnreachable", err)
	}
}

// TestIdentifyBatchedKeepsOrder checks that parallel batches land in the input
// order and that a failing batch degrades instead of aborting the run.
func TestIdentifyBatchedKeepsOrder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req model.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		results := make([]model.Result, 0, len(req.Records))
		for _, rec := range req.Records {
			if rec.IP == "fail" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			results = append(results, model.Result{
				IP: rec.IP, Port: rec.Port, Protocol: model.ProtocolSSH, Confidence: 0.9,
			})
		}
		_ = json.NewEncoder(w).Encode(model.Response{Results: results})
	}))
	defer srv.Close()

	cli := New(srv.URL, 5*time.Second, 0)
	records := []model.ScanRecord{
		{IP: "a", Port: 22}, {IP: "b", Port: 22}, {IP: "c", Port: 22}, {IP: "d", Port: 22},
	}
	results, failed, err := cli.IdentifyBatched(context.Background(), records, 2, 2, false)
	if err != nil || failed != 0 {
		t.Fatalf("failed = %d, err = %v", failed, err)
	}
	for i, rec := range records {
		if results[i].IP != rec.IP {
			t.Fatalf("result %d is %s, want %s (order not preserved)", i, results[i].IP, rec.IP)
		}
	}

	withFailure := []model.ScanRecord{{IP: "a", Port: 22}, {IP: "fail", Port: 22}}
	results, failed, err = cli.IdentifyBatched(context.Background(), withFailure, 2, 1, false)
	if failed == 0 || err == nil {
		t.Fatalf("failed = %d, err = %v; want a reported failure", failed, err)
	}
	if len(results) != 2 || results[0].IP != "a" {
		t.Fatalf("results = %+v", results)
	}
	// A failed batch still yields a degraded, order-preserving placeholder.
	if results[1].IP != "fail" || results[1].Port != 22 || results[1].Protocol != model.ProtocolUnknown {
		t.Errorf("failed batch placeholder = %+v", results[1])
	}
}

func TestPing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/meta" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(model.Meta{Version: "1.2.3", Protocols: []string{"SSH", "HTTP"}, RuleCount: 42})
	}))
	defer srv.Close()
	meta, err := New(srv.URL, 5*time.Second, 0).Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if meta.Version != "1.2.3" || len(meta.Protocols) != 2 || meta.RuleCount != 42 {
		t.Errorf("meta = %+v", meta)
	}
}
