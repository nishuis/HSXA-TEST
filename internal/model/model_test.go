package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestResultJSONContract pins the frozen serialisation contract of plan.md
// §1.2: exact key names, exact key order, empty strings instead of null, port
// as an integer and confidence as a float.
func TestResultJSONContract(t *testing.T) {
	res := Result{
		IP:         "1.2.3.4",
		Port:       22,
		Protocol:   ProtocolSSH,
		Product:    "OpenSSH",
		Version:    "8.9p1",
		OSHint:     "Ubuntu",
		Confidence: 0.95,
	}
	want := `{"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95}`
	got, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != want {
		t.Fatalf("result JSON:\n got %s\nwant %s", got, want)
	}
}

// TestMissingValuesAreEmptyStrings is the acceptance rule that separates a
// clean response from a failing one: no null anywhere.
func TestMissingValuesAreEmptyStrings(t *testing.T) {
	res := Result{IP: "10.0.0.1", Port: 6379, Protocol: ProtocolRedis, Product: "Redis", Confidence: 0.7}
	got, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(got), "null") {
		t.Fatalf("missing values serialised as null: %s", got)
	}
	want := `{"ip":"10.0.0.1","port":6379,"protocol":"Redis","product":"Redis","version":"","os_hint":"","confidence":0.7}`
	if string(got) != want {
		t.Fatalf("result JSON:\n got %s\nwant %s", got, want)
	}
}

func TestUnknownResult(t *testing.T) {
	res := Unknown("10.0.0.9", 4242)
	if res.Protocol != ProtocolUnknown || res.Product != "" || res.Version != "" || res.OSHint != "" || res.Confidence != 0 {
		t.Errorf("Unknown() = %+v", res)
	}
	if res.IP != "10.0.0.9" || res.Port != 4242 {
		t.Errorf("Unknown() did not echo the record: %+v", res)
	}
}

func TestStatsOf(t *testing.T) {
	results := []Result{
		{Protocol: ProtocolSSH, Product: "OpenSSH"},
		{Protocol: ProtocolHTTP, Product: ""},
		{Protocol: ProtocolUnknown, Product: ""},
		{Protocol: "", Product: ""},
	}
	stats := StatsOf(results, 12)
	if stats.Total != 4 || stats.Identified != 1 || stats.Unknown != 2 || stats.ElapsedMS != 12 {
		t.Errorf("StatsOf = %+v", stats)
	}
	if got := StatsOf(nil, 0); got.Total != 0 {
		t.Errorf("StatsOf(nil) = %+v", got)
	}
}

func TestEncodings(t *testing.T) {
	got := Encodings()
	if len(got) != 4 || got[0] != EncodingAuto || got[3] != EncodingHex {
		t.Errorf("Encodings() = %v", got)
	}
}

func TestResultWithEvidenceKeepsFieldOrder(t *testing.T) {
	res := ResultWithEvidence{
		Result:   Result{IP: "1.1.1.1", Port: 80, Protocol: ProtocolHTTP, Confidence: 0.6},
		Evidence: &Evidence{ProtocolRule: "http-status-line", Encoding: "text"},
	}
	got, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"ip":"1.1.1.1","port":80,"protocol":"HTTP","product":"","version":"","os_hint":"","confidence":0.6,"evidence":{"protocol_rule":"http-status-line","encoding":"text"}}`
	if string(got) != want {
		t.Fatalf("result with evidence:\n got %s\nwant %s", got, want)
	}
}
