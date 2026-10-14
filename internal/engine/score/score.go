// Package score synthesises the confidence value of one identification.
//
// The model is evidence-layered (plan.md §2.4): a protocol signature carries a
// base weight and a product match, a version capture and an OS hint each add a
// layer. The seven acceptance anchors of plan.md §1.3 (0.95 / 0.90 / 0.90 /
// 0.90 / 0.70 / 0.90 / 0.85) are the regression reference every constant below
// is calibrated against.
package score

import "math"

// Evidence layer weights.
const (
	// WeightProtoSignature is a unique, unambiguous protocol signature.
	WeightProtoSignature = 0.60
	// WeightProtoWeak is an ambiguous signature, such as a bare 220 greeting.
	WeightProtoWeak = 0.55
	// WeightProtoDistinctive is a signature that is at once a protocol and a
	// product mark, such as the Elasticsearch or Docker API headers. It ranks
	// above a generic HTTP status line so the product-specific protocol wins.
	WeightProtoDistinctive = 0.65
	// WeightProtoTLSOnly is a TLS record: HTTP by port, no readable plaintext.
	WeightProtoTLSOnly = 0.40
	// WeightProtoPortOnly is the port prior table alone.
	WeightProtoPortOnly = 0.35
	// WeightProductStrong is a product signature with a canonical name.
	WeightProductStrong = 0.15
	// WeightProductWeak is a product confirmation without version evidence.
	WeightProductWeak = 0.10
	// WeightVersion is added when a version was captured.
	WeightVersion = 0.15
	// WeightOS is added when an OS hint was captured.
	WeightOS = 0.05
	// MaxConfidence caps a confidence: no offline heuristic is ever certain.
	MaxConfidence = 0.99
)

// Compose returns the two-decimal confidence of one identification:
// protocol signature weight + product weight + version layer + OS layer,
// clamped to [0, MaxConfidence].
func Compose(protoWeight, productWeight float64, hasVersion, hasOS bool) float64 {
	c := protoWeight + productWeight
	if hasVersion {
		c += WeightVersion
	}
	if hasOS {
		c += WeightOS
	}
	return Round(c)
}

// Round clamps and rounds a confidence to the two decimals of the output
// contract.
func Round(c float64) float64 {
	if c < 0 {
		c = 0
	}
	if c > MaxConfidence {
		c = MaxConfidence
	}
	return math.Round(c*100) / 100
}
