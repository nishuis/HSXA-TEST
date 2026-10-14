// Package api implements the REST interface of bfp-server: the identify
// endpoint, the probes and the metadata endpoint (plan.md §3.1).
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"hsxa-banner-fingerprint/internal/engine"
	"hsxa-banner-fingerprint/internal/model"
	"hsxa-banner-fingerprint/internal/version"
)

// maxReportedErrors caps the error list of a single response.
const maxReportedErrors = 32

// Options configures the HTTP layer.
type Options struct {
	// MaxBodyBytes caps the request body (413 beyond it).
	MaxBodyBytes int64
	// MaxRecords caps the number of records per request (413 beyond it).
	MaxRecords int
	// MaxBannerBytes caps a single banner (413 beyond it).
	MaxBannerBytes int
	// Logger receives the structured access and error logs.
	Logger *slog.Logger
	// StartedAt is used for the uptime reported by /api/v1/meta.
	StartedAt time.Time
}

// DefaultOptions returns the documented defaults (NFR-5).
func DefaultOptions() Options {
	return Options{
		MaxBodyBytes:   32 << 20,
		MaxRecords:     200000,
		MaxBannerBytes: 64 << 10,
		Logger:         slog.Default(),
		StartedAt:      time.Now(),
	}
}

// Server is the HTTP front end of the identification engine.
type Server struct {
	eng    *engine.Engine
	opt    Options
	logger *slog.Logger
	ready  chan struct{}
}

// New returns a server around eng. A nil engine yields a server that reports
// every record as unknown rather than failing.
func New(eng *engine.Engine, opt Options) *Server {
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.MaxBodyBytes <= 0 {
		opt.MaxBodyBytes = DefaultOptions().MaxBodyBytes
	}
	if opt.MaxRecords <= 0 {
		opt.MaxRecords = DefaultOptions().MaxRecords
	}
	if opt.MaxBannerBytes <= 0 {
		opt.MaxBannerBytes = DefaultOptions().MaxBannerBytes
	}
	if opt.StartedAt.IsZero() {
		opt.StartedAt = time.Now()
	}
	return &Server{eng: eng, opt: opt, logger: opt.Logger, ready: make(chan struct{})}
}

// SetReady marks the server ready: /readyz reports 503 until it is called,
// which happens once the rule files have loaded (plan.md §4.3).
func (s *Server) SetReady(ready bool) {
	select {
	case <-s.ready:
		if ready {
			return
		}
		s.ready = make(chan struct{})
	default:
		if ready {
			close(s.ready)
		}
	}
}

// Handler returns the routed, instrumented HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/identify", s.handleIdentify)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /api/v1/meta", s.handleMeta)
	mux.HandleFunc("/api/v1/identify", methodNotAllowed("POST"))
	mux.HandleFunc("/healthz", methodNotAllowed("GET"))
	mux.HandleFunc("/readyz", methodNotAllowed("GET"))
	mux.HandleFunc("/api/v1/meta", methodNotAllowed("GET"))
	mux.HandleFunc("/", s.handleNotFound)
	return s.recoverer(s.requestID(s.accessLog(mux)))
}

func (s *Server) handleIdentify(w http.ResponseWriter, r *http.Request) {
	var req model.Request
	body := http.MaxBytesReader(w, r.Body, s.opt.MaxBodyBytes)
	dec := json.NewDecoder(body)
	if err := dec.Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.writeErrors(w, http.StatusRequestEntityTooLarge, []model.APIError{{
				Index:   -1,
				Field:   "body",
				Message: fmt.Sprintf("request body exceeds %d bytes", s.opt.MaxBodyBytes),
			}})
			return
		}
		s.writeErrors(w, http.StatusBadRequest, []model.APIError{{
			Index:   -1,
			Field:   "body",
			Message: "invalid JSON body: " + err.Error(),
		}})
		return
	}

	if len(req.Records) > s.opt.MaxRecords {
		s.writeErrors(w, http.StatusRequestEntityTooLarge, []model.APIError{{
			Index:   -1,
			Field:   "records",
			Message: fmt.Sprintf("batch has %d records, the limit is %d", len(req.Records), s.opt.MaxRecords),
		}})
		return
	}
	if problems, status := s.validate(req.Records); len(problems) > 0 {
		s.writeErrors(w, status, problems)
		return
	}

	includeEvidence := req.Options != nil && req.Options.IncludeEvidence
	start := time.Now()
	results := make([]model.Result, 0, len(req.Records))
	var evidences []model.Evidence
	if includeEvidence {
		evidences = make([]model.Evidence, 0, len(req.Records))
	}
	// A record can never fail here: engine.Identify degrades instead, so one
	// malformed banner cannot turn the batch into an error response (FR-8).
	for _, rec := range req.Records {
		if includeEvidence {
			res, ev := s.eng.IdentifyWithEvidence(rec)
			results = append(results, res)
			evidences = append(evidences, ev)
			continue
		}
		results = append(results, s.eng.Identify(rec))
	}
	elapsed := time.Since(start).Milliseconds()

	if r.URL.Query().Get("output") == "array" {
		if includeEvidence {
			withEvidence := make([]model.ResultWithEvidence, 0, len(results))
			for i := range results {
				ev := evidences[i]
				withEvidence = append(withEvidence, model.ResultWithEvidence{Result: results[i], Evidence: &ev})
			}
			s.writeJSON(w, http.StatusOK, withEvidence)
			return
		}
		s.writeJSON(w, http.StatusOK, results)
		return
	}
	s.writeJSON(w, http.StatusOK, model.Response{
		Results: results,
		Stats:   model.StatsOf(results, elapsed),
	})
}

// validate checks every record and returns the problems together with the most
// severe status they imply: 413 over 415 over 400.
func (s *Server) validate(records []model.ScanRecord) ([]model.APIError, int) {
	var (
		problems []model.APIError
		status   = http.StatusBadRequest
		escalate = func(code int) {
			if code > status {
				status = code
			}
		}
	)
	add := func(index int, field, message string) {
		if len(problems) < maxReportedErrors {
			problems = append(problems, model.APIError{Index: index, Field: field, Message: message})
		}
	}
	for i, rec := range records {
		if strings.TrimSpace(rec.IP) == "" {
			add(i, "ip", "ip must not be empty")
		}
		if rec.Port < 1 || rec.Port > 65535 {
			add(i, "port", fmt.Sprintf("port %d is outside 1-65535", rec.Port))
		}
		if enc := strings.ToLower(strings.TrimSpace(rec.Encoding)); enc != "" && !validEncoding(enc) {
			add(i, "encoding", fmt.Sprintf("unsupported encoding %q", rec.Encoding))
			escalate(http.StatusUnsupportedMediaType)
		}
		if len(rec.Banner) > s.opt.MaxBannerBytes {
			add(i, "banner", fmt.Sprintf("banner is %d bytes, the limit is %d", len(rec.Banner), s.opt.MaxBannerBytes))
			escalate(http.StatusRequestEntityTooLarge)
		}
		if len(rec.BannerBase64) > s.opt.MaxBannerBytes {
			add(i, "banner_base64", fmt.Sprintf("banner_base64 is %d bytes, the limit is %d", len(rec.BannerBase64), s.opt.MaxBannerBytes))
			escalate(http.StatusRequestEntityTooLarge)
		}
	}
	return problems, status
}

func validEncoding(enc string) bool {
	switch enc {
	case model.EncodingAuto, model.EncodingText, model.EncodingBase64, model.EncodingHex:
		return true
	}
	return false
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	select {
	case <-s.ready:
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	default:
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "loading"})
	}
}

func (s *Server) handleMeta(w http.ResponseWriter, _ *http.Request) {
	protocols := []string{}
	rules := 0
	if reg := s.eng.Registry(); reg != nil {
		protocols = reg.Protocols()
		rules = reg.RuleCount()
	}
	s.writeJSON(w, http.StatusOK, model.Meta{
		Version:    version.Version,
		Protocols:  protocols,
		RuleCount:  rules,
		UptimeSecs: int64(time.Since(s.opt.StartedAt).Seconds()),
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	s.writeErrors(w, http.StatusNotFound, []model.APIError{{
		Index:   -1,
		Message: fmt.Sprintf("no route for %s %s", r.Method, r.URL.Path),
	}})
}

func methodNotAllowed(allowed string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allowed)
		writeJSONResponse(w, http.StatusMethodNotAllowed, model.ErrorResponse{Errors: []model.APIError{{
			Index:   -1,
			Message: fmt.Sprintf("method %s is not allowed, use %s", r.Method, allowed),
		}}})
	}
}

func (s *Server) writeErrors(w http.ResponseWriter, status int, problems []model.APIError) {
	s.writeJSON(w, status, model.ErrorResponse{Errors: problems})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	writeJSONResponse(w, status, payload)
}

func writeJSONResponse(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	// The acceptance contract is a byte-comparable JSON array, so HTML
	// escaping is off and the encoder writes one trailing newline.
	enc.SetEscapeHTML(false)
	_ = enc.Encode(payload)
}
