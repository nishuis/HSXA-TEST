// Package engine implements the offline banner fingerprinting pipeline:
// decode → probe → extract → score.
//
// The package is a pure, IO-free library. It never dials a network, never
// touches the filesystem, never panics and keeps no mutable state, so a single
// Engine may be shared by every request of a server (plan.md D1, NFR-4).
package engine

import (
	"time"

	"hsxa-banner-fingerprint/internal/engine/decode"
	"hsxa-banner-fingerprint/internal/engine/extract"
	"hsxa-banner-fingerprint/internal/engine/probe"
	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// Engine identifies protocols, products and versions from raw banner data.
type Engine struct {
	reg *rule.Registry
}

// New returns an engine backed by reg. A nil registry yields an engine that
// reports every record as unknown instead of failing.
func New(reg *rule.Registry) *Engine { return &Engine{reg: reg} }

// Registry exposes the compiled rule registry backing the engine.
func (e *Engine) Registry() *rule.Registry { return e.reg }

// Identify analyses a single record.
//
// It never returns an error and never panics: a record that carries no usable
// signal degrades to protocol "unknown" (or to the port prior) with empty
// product, version and os_hint, and a low confidence (FR-8). A single bad
// record therefore can never fail the batch that contains it.
func (e *Engine) Identify(rec model.ScanRecord) model.Result {
	res, _ := e.identify(rec)
	return res
}

// IdentifyWithEvidence is Identify plus the rules that produced the result. It
// backs the include_evidence option of the REST API.
func (e *Engine) IdentifyWithEvidence(rec model.ScanRecord) (model.Result, model.Evidence) {
	return e.identify(rec)
}

func (e *Engine) identify(rec model.ScanRecord) (res model.Result, evidence model.Evidence) {
	res = model.Unknown(rec.IP, rec.Port)
	// Defence in depth: malformed payloads must never take down a batch, so a
	// panic anywhere below degrades this single record instead.
	defer func() {
		if r := recover(); r != nil {
			res = model.Unknown(rec.IP, rec.Port)
			evidence = model.Evidence{}
		}
	}()
	if e.reg == nil {
		return res, evidence
	}
	payload, err := decode.Decode(rec.Banner, rec.BannerBase64, rec.Encoding)
	if err != nil {
		// An undecodable payload degrades exactly like an empty one; the API
		// layer is responsible for rejecting unknown encoding names outright.
		payload = decode.Payload{}
	}
	evidence.Encoding = payload.Encoding
	in := rule.Input{Bytes: payload.Bytes, Port: rec.Port}
	candidates := probe.Decide(e.reg, in)
	if len(candidates) == 0 {
		return res, evidence
	}
	best := candidates[0]
	res.Protocol = best.Protocol
	evidence.ProtocolRule = best.Rule
	evidence.TLSOnly = best.TLSOnly
	if best.PortOnly {
		evidence.PortPrior = best.Protocol
	}
	var findings rule.Findings
	if set := e.reg.Set(best.Protocol); set != nil && !best.TLSOnly {
		if f, ok := extract.Product(set, in); ok {
			findings = f
		}
	}
	res.Product = findings.Product
	res.Version = findings.Version
	res.OSHint = findings.OSHint
	res.Confidence = score.Compose(
		best.Weight,
		findings.Weight,
		findings.Version != "",
		findings.OSHint != "",
	)
	evidence.ProductRule = findings.Rule
	return res, evidence
}

// IdentifyBatch analyses records in input order. The returned slice is always
// 1:1 with records and preserves their order (FR-9).
func (e *Engine) IdentifyBatch(recs []model.ScanRecord) []model.Result {
	out := make([]model.Result, len(recs))
	for i := range recs {
		out[i] = e.Identify(recs[i])
	}
	return out
}

// IdentifyBatchWithStats analyses records in input order and additionally
// reports the elapsed wall time.
func (e *Engine) IdentifyBatchWithStats(recs []model.ScanRecord) ([]model.Result, int64) {
	start := time.Now()
	results := e.IdentifyBatch(recs)
	return results, time.Since(start).Milliseconds()
}
