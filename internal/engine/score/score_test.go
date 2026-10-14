package score

import "testing"

// TestAcceptanceAnchors pins the seven example confidences of plan.md §1.3.
// Every layer of the model is calibrated to reproduce them exactly, so a
// change here is a change to the acceptance contract.
func TestAcceptanceAnchors(t *testing.T) {
	tests := []struct {
		name          string
		protoWeight   float64
		productWeight float64
		hasVersion    bool
		hasOS         bool
		want          float64
	}{
		{"ssh-with-os", WeightProtoSignature, WeightProductStrong, true, true, 0.95},
		{"http-nginx", WeightProtoSignature, WeightProductStrong, true, false, 0.90},
		{"http-apache", WeightProtoSignature, WeightProductStrong, true, false, 0.90},
		{"mysql-handshake", WeightProtoSignature, WeightProductStrong, true, false, 0.90},
		{"redis-no-version", WeightProtoSignature, WeightProductWeak, false, false, 0.70},
		{"ftp-proftpd", WeightProtoSignature, WeightProductStrong, true, false, 0.90},
		{"http-jetty", WeightProtoSignature, WeightProductWeak, true, false, 0.85},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Compose(tc.protoWeight, tc.productWeight, tc.hasVersion, tc.hasOS)
			if got != tc.want {
				t.Fatalf("Compose() = %.2f, anchor %.2f", got, tc.want)
			}
		})
	}
}

func TestComposeTiers(t *testing.T) {
	tests := []struct {
		name           string
		proto, product float64
		version, os    bool
		min, max       float64
	}{
		{"signature-only", WeightProtoSignature, 0, false, false, 0.60, 0.75},
		{"product-without-version", WeightProtoSignature, WeightProductStrong, false, false, 0.65, 0.80},
		{"port-prior-only", WeightProtoPortOnly, 0, false, false, 0.30, 0.50},
		{"tls-record", WeightProtoTLSOnly, 0, false, false, 0.30, 0.50},
		{"full-evidence", WeightProtoDistinctive, WeightProductStrong, true, true, 0.90, 0.99},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Compose(tc.proto, tc.product, tc.version, tc.os)
			if got < tc.min || got > tc.max {
				t.Fatalf("Compose() = %.2f, want within [%.2f, %.2f]", got, tc.min, tc.max)
			}
		})
	}
}

func TestComposeClampsAndRounds(t *testing.T) {
	if got := Compose(0.99, 0.5, true, true); got != MaxConfidence {
		t.Errorf("Compose() = %.2f, want the %.2f cap", got, MaxConfidence)
	}
	if got := Compose(-1, -1, false, false); got != 0 {
		t.Errorf("Compose() = %.2f, want 0", got)
	}
	if got := Round(0.333333); got != 0.33 {
		t.Errorf("Round(0.333333) = %v, want 0.33", got)
	}
	if got := Round(0.6666666); got != 0.67 {
		t.Errorf("Round(0.6666666) = %v, want 0.67", got)
	}
}
