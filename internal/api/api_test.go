package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hsxa-banner-fingerprint/internal/engine"
	"hsxa-banner-fingerprint/internal/model"
	"hsxa-banner-fingerprint/internal/rules"
	"hsxa-banner-fingerprint/internal/verify"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// withDefaults fills an Options value: zero fields fall back to the documented
// defaults, so a test only spells out what it cares about.
func withDefaults(opt Options) Options {
	def := DefaultOptions()
	if opt.Logger != nil {
		def.Logger = opt.Logger
	}
	if opt.MaxBodyBytes > 0 {
		def.MaxBodyBytes = opt.MaxBodyBytes
	}
	if opt.MaxRecords > 0 {
		def.MaxRecords = opt.MaxRecords
	}
	if opt.MaxBannerBytes > 0 {
		def.MaxBannerBytes = opt.MaxBannerBytes
	}
	if !opt.StartedAt.IsZero() {
		def.StartedAt = opt.StartedAt
	}
	return def
}

func testServer(t *testing.T, opt Options) *Server {
	t.Helper()
	registry, err := rules.Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	opt.Logger = discardLogger()
	opt.StartedAt = time.Now()
	s := New(engine.New(registry), withDefaults(opt))
	s.SetReady(true)
	return s
}

func post(t *testing.T, s *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestIdentifyEnvelope(t *testing.T) {
	s := testServer(t, Options{})
	body := `{"records":[
		{"ip":"10.0.0.1","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"},
		{"ip":"10.0.0.2","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"},
		{"ip":"10.0.0.3","port":443,"banner":"HTTP/1.1 200 OK\r\nServer: Apache/2.4.57\r\n\r\n"},
		{"ip":"10.0.0.4","port":3306,"banner_base64":"SQAAAAo4LjAuMzIAAQAAAGFiY2RlZmdoAP/3IQIA/4EVAAAAAAAAAAAAAGlqa2xtbm9wcXJzAG15c3FsX25hdGl2ZV9wYXNzd29yZAA=","encoding":"base64"},
		{"ip":"10.0.0.5","port":6379,"banner":"-NOAUTH Authentication required.\r\n"},
		{"ip":"10.0.0.6","port":21,"banner":"220 ProFTPD 1.3.7 Server ready.\r\n"},
		{"ip":"10.0.0.7","port":8080,"banner":"HTTP/1.1 200 OK\r\nServer: Jetty(9.4.51)\r\n\r\n"},
		{"ip":"10.0.0.8","port":9999,"banner":"nothing recognisable here"}
	]}`
	rec := post(t, s, "/api/v1/identify", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got model.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Results) != 8 {
		t.Fatalf("results = %d, want 8 (1:1 with the input)", len(got.Results))
	}
	for i, want := range []string{"SSH", "HTTP", "HTTP", "MySQL", "Redis", "FTP", "HTTP", "unknown"} {
		if got.Results[i].Protocol != want {
			t.Errorf("result %d protocol = %q, want %q", i, got.Results[i].Protocol, want)
		}
		if got.Results[i].IP != fmt.Sprintf("10.0.0.%d", i+1) {
			t.Errorf("result %d is not in input order: %s", i, got.Results[i].IP)
		}
	}
	if got.Stats.Total != 8 || got.Stats.Unknown != 1 || got.Stats.Identified != 7 {
		t.Errorf("stats = %+v", got.Stats)
	}
}

// TestArrayOutputContract is the acceptance-critical case: the bare array is
// isomorphic to the example, with no nulls and the frozen field order.
func TestArrayOutputContract(t *testing.T) {
	s := testServer(t, Options{})
	body := `{"records":[{"ip":"10.10.1.15","port":6379,"banner":"-NOAUTH Authentication required.\r\n"}]}`
	rec := post(t, s, "/api/v1/identify?output=array", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if problems := verify.CheckJSONContract(rec.Body.Bytes()); len(problems) > 0 {
		t.Errorf("json contract: %v", problems)
	}
	want := `[{"ip":"10.10.1.15","port":6379,"protocol":"Redis","product":"Redis","version":"","os_hint":"","confidence":0.7}]`
	if got := strings.TrimSpace(rec.Body.String()); got != want {
		t.Errorf("array output:\n got %s\nwant %s", got, want)
	}
}

func TestIdentifyEvidence(t *testing.T) {
	s := testServer(t, Options{})
	body := `{"records":[{"ip":"1.1.1.1","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"}],"options":{"include_evidence":true}}`
	rec := post(t, s, "/api/v1/identify?output=array", body)
	if !strings.Contains(rec.Body.String(), `"evidence":{"protocol_rule":"http-status-line"`) {
		t.Fatalf("evidence missing: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "null") {
		t.Errorf("evidence output contains null: %s", rec.Body.String())
	}
}

// TestMalformedPayloadsStillReturn200 covers FR-8 and NFR-3: a broken banner
// degrades one record and never fails the batch.
func TestMalformedPayloadsStillReturn200(t *testing.T) {
	s := testServer(t, Options{})
	records := []model.ScanRecord{
		{IP: "1.1.1.1", Port: 22, Banner: ""},
		{IP: "1.1.1.2", Port: 22, Banner: "%%%not-base64%%%", Encoding: "base64"},
		{IP: "1.1.1.3", Port: 22, Banner: "SSH-2.0-OpenSSH_9.6"},
		{IP: "1.1.1.4", Port: 9999, Banner: strings.Repeat("\x00\xff", 500)},
		{IP: "1.1.1.5", Port: 22, Banner: `\x00\x01\x02\r\n`},
	}
	payload, err := json.Marshal(model.Request{Records: records})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := post(t, s, "/api/v1/identify", string(payload))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got model.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Results) != len(records) {
		t.Fatalf("results = %d, want %d", len(got.Results), len(records))
	}
	if got.Results[2].Product != "OpenSSH" {
		t.Errorf("the good record in the batch degraded: %+v", got.Results[2])
	}
}

func TestMalformedJSON(t *testing.T) {
	s := testServer(t, Options{})
	rec := post(t, s, "/api/v1/identify", `{"records":[{"ip":`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var got model.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Errors) == 0 || got.Errors[0].Index != -1 {
		t.Errorf("errors = %+v, want a request level problem", got.Errors)
	}
}

func TestValidationErrorsLocateTheRecord(t *testing.T) {
	s := testServer(t, Options{})
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantIndex  int
		wantField  string
	}{
		{"empty-ip", `{"records":[{"ip":"1.1.1.1","port":22},{"ip":"","port":22}]}`, http.StatusBadRequest, 1, "ip"},
		{"bad-port", `{"records":[{"ip":"1.1.1.1","port":0}]}`, http.StatusBadRequest, 0, "port"},
		{"unknown-encoding", `{"records":[{"ip":"1.1.1.1","port":22,"encoding":"rot13"}]}`, http.StatusUnsupportedMediaType, 0, "encoding"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(t, s, "/api/v1/identify", tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			var got model.ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(got.Errors) == 0 || got.Errors[0].Index != tc.wantIndex || got.Errors[0].Field != tc.wantField {
				t.Errorf("errors = %+v, want index %d field %q", got.Errors, tc.wantIndex, tc.wantField)
			}
		})
	}
}

func TestEmptyBatch(t *testing.T) {
	s := testServer(t, Options{})
	rec := post(t, s, "/api/v1/identify", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"results":[]`) {
		t.Errorf("empty batch should return an empty array, got %s", rec.Body.String())
	}
}

func TestLimits(t *testing.T) {
	t.Run("oversize-body", func(t *testing.T) {
		s := testServer(t, Options{MaxBodyBytes: 256})
		body := `{"records":[{"ip":"1.1.1.1","port":22,"banner":"` + strings.Repeat("A", 1024) + `"}]}`
		if rec := post(t, s, "/api/v1/identify", body); rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", rec.Code)
		}
	})
	t.Run("too-many-records", func(t *testing.T) {
		s := testServer(t, Options{MaxRecords: 2})
		body := `{"records":[{"ip":"1.1.1.1","port":22},{"ip":"1.1.1.2","port":22},{"ip":"1.1.1.3","port":22}]}`
		if rec := post(t, s, "/api/v1/identify", body); rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", rec.Code)
		}
	})
	t.Run("banner-too-long", func(t *testing.T) {
		s := testServer(t, Options{MaxBannerBytes: 32})
		body := `{"records":[{"ip":"1.1.1.1","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4-extended"}]}`
		rec := post(t, s, "/api/v1/identify", body)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"index":0`) {
			t.Errorf("error does not locate the record: %s", rec.Body.String())
		}
	})
}

func TestProbesAndMeta(t *testing.T) {
	s := testServer(t, Options{})
	handler := s.Handler()
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	if rec := get("/healthz"); rec.Code != http.StatusOK {
		t.Errorf("/healthz status = %d", rec.Code)
	}
	if rec := get("/readyz"); rec.Code != http.StatusOK {
		t.Errorf("/readyz status = %d", rec.Code)
	}
	rec := get("/api/v1/meta")
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/v1/meta status = %d", rec.Code)
	}
	var meta model.Meta
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("decode meta: %v", err)
	}
	if len(meta.Protocols) != 17 || meta.RuleCount == 0 {
		t.Errorf("meta = %+v", meta)
	}
}

// TestReadyzWaitsForRules covers the 503-until-loaded contract of plan.md §4.3.
func TestReadyzWaitsForRules(t *testing.T) {
	s := New(engine.New(nil), withDefaults(Options{Logger: discardLogger(), StartedAt: time.Now()}))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz before SetReady = %d, want 503", rec.Code)
	}
	s.SetReady(true)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz after SetReady = %d, want 200", rec.Code)
	}
}

func TestMethodNotAllowedAndNotFound(t *testing.T) {
	s := testServer(t, Options{})
	handler := s.Handler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/identify", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/v1/identify = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "POST" {
		t.Errorf("Allow = %q, want POST", allow)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /nope = %d, want 404", rec.Code)
	}
}

func TestRequestIDEchoedAndPanicRecovered(t *testing.T) {
	s := testServer(t, Options{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-Id", "trace-me")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if got := rec.Header().Get("X-Request-Id"); got != "trace-me" {
		t.Errorf("X-Request-Id = %q, want trace-me", got)
	}

	// A panicking handler must produce a 500 rather than a dropped connection.
	panicky := s.recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec = httptest.NewRecorder()
	panicky.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panic", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "internal error") {
		t.Errorf("panic body = %s", rec.Body.String())
	}
}
