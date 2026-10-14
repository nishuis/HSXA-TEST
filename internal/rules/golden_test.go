package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"hsxa-banner-fingerprint/internal/engine"
	"hsxa-banner-fingerprint/internal/model"
	"hsxa-banner-fingerprint/internal/verify"
)

// testDataRoot is the repository's testdata directory, relative to this
// package.
var testDataRoot = filepath.Join("..", "..", "testdata")

// testEngine builds an engine over the built-in rule sets.
func testEngine(t *testing.T) *engine.Engine {
	t.Helper()
	reg, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
	}
	return engine.New(reg)
}

// TestGoldenCorpus runs every testdata/<name>/input.json against its
// expected.json: the acceptance fixture plus one corpus per protocol.
func TestGoldenCorpus(t *testing.T) {
	eng := testEngine(t)
	entries, err := os.ReadDir(testDataRoot)
	if err != nil {
		t.Fatalf("read %s: %v", testDataRoot, err)
	}
	dirs := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		inputPath := filepath.Join(testDataRoot, name, "input.json")
		expectedPath := filepath.Join(testDataRoot, name, "expected.json")
		if _, err := os.Stat(inputPath); err != nil {
			continue
		}
		dirs++
		t.Run(name, func(t *testing.T) {
			records := readRecords(t, inputPath)
			want := readResults(t, expectedPath)
			got := eng.IdentifyBatch(records)
			for _, problem := range verify.Compare(want, got, verify.DefaultOptions) {
				t.Errorf("%s: %s", name, problem)
			}
		})
	}
	if dirs < 2 {
		t.Fatalf("expected at least the acceptance corpus plus one protocol corpus, found %d", dirs)
	}
}

// TestAcceptanceAnchors pins the seven acceptance records of plan.md §1.3 to
// their protocol, product, version, os_hint and confidence anchor.
func TestAcceptanceAnchors(t *testing.T) {
	eng := testEngine(t)
	type anchor struct {
		protocol, product, version, osHint string
		confidence                         float64
	}
	anchors := []anchor{
		{"SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.95},
		{"HTTP", "nginx", "1.24.0", "", 0.90},
		{"HTTP", "Apache", "2.4.57", "", 0.90},
		{"MySQL", "MySQL", "8.0.32", "", 0.90},
		{"Redis", "Redis", "", "", 0.70},
		{"FTP", "ProFTPD", "1.3.7", "", 0.90},
		{"HTTP", "Jetty", "9.4.51", "", 0.85},
	}
	records := readRecords(t, filepath.Join(testDataRoot, "acceptance", "input.json"))
	got := eng.IdentifyBatch(records)
	if len(got) != len(anchors) {
		t.Fatalf("acceptance corpus has %d records, want %d", len(got), len(anchors))
	}
	const tolerance = 0.05
	for i, want := range anchors {
		g := got[i]
		if g.Protocol != want.protocol || g.Product != want.product ||
			g.Version != want.version || g.OSHint != want.osHint {
			t.Errorf("record %d: got %s/%s/%s/%q, want %s/%s/%s/%q",
				i, g.Protocol, g.Product, g.Version, g.OSHint,
				want.protocol, want.product, want.version, want.osHint)
		}
		if diff := g.Confidence - want.confidence; diff > tolerance || diff < -tolerance {
			t.Errorf("record %d: confidence %.2f, anchor %.2f (±%.2f)",
				i, g.Confidence, want.confidence, tolerance)
		}
	}
}

// TestAcceptanceCorpusIsSevenRecords guards the size of the acceptance fixture
// against accidental edits.
func TestAcceptanceCorpusIsSevenRecords(t *testing.T) {
	records := readRecords(t, filepath.Join(testDataRoot, "acceptance", "input.json"))
	if len(records) != 7 {
		t.Fatalf("acceptance corpus has %d records, want 7", len(records))
	}
}

func readRecords(t *testing.T, path string) []model.ScanRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var request model.Request
	if err := json.Unmarshal(data, &request); err == nil && len(request.Records) > 0 {
		return request.Records
	}
	var records []model.ScanRecord
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return records
}

func readResults(t *testing.T, path string) []model.Result {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var results []model.Result
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return results
}
