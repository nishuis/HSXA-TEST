package verify

import (
	"strings"
	"testing"

	"hsxa-banner-fingerprint/internal/model"
)

func result(ip string, port int, protocol, product, version, osHint string, confidence float64) model.Result {
	return model.Result{
		IP: ip, Port: port, Protocol: protocol, Product: product,
		Version: version, OSHint: osHint, Confidence: confidence,
	}
}

func TestCompareMatches(t *testing.T) {
	want := []model.Result{result("1.1.1.1", 22, "SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.95)}
	got := []model.Result{result("1.1.1.1", 22, "SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.91)}
	if problems := Compare(want, got, DefaultOptions); len(problems) != 0 {
		t.Errorf("Compare() = %v, want no problems within the confidence tolerance", problems)
	}
}

func TestCompareReportsEveryDifference(t *testing.T) {
	want := []model.Result{result("1.1.1.1", 22, "SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.95)}
	got := []model.Result{result("1.1.1.2", 2222, "FTP", "ProFTPD", "1.3.7", "Debian", 0.60)}
	problems := Compare(want, got, DefaultOptions)
	for _, field := range []string{"ip ", "port ", "protocol ", "product ", "version ", "os_hint ", "confidence "} {
		found := false
		for _, p := range problems {
			if strings.Contains(p, field) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no problem reported for %q: %v", field, problems)
		}
	}
}

func TestCompareReportsCountMismatch(t *testing.T) {
	want := []model.Result{result("1.1.1.1", 22, "SSH", "", "", "", 0.6)}
	if problems := Compare(want, nil, DefaultOptions); len(problems) == 0 {
		t.Error("want a count mismatch, got none")
	}
	if problems := Compare(nil, want, DefaultOptions); len(problems) == 0 {
		t.Error("want a count mismatch, got none")
	}
}

func TestCheckJSONContract(t *testing.T) {
	clean := []byte(`{"results":[{"ip":"1.1.1.1","product":""}],"stats":{"total":1}}`)
	if problems := CheckJSONContract(clean); len(problems) != 0 {
		t.Errorf("clean body reported problems: %v", problems)
	}
	dirty := []byte(`{"results":[{"ip":"1.1.1.1","product":null}]}`)
	if problems := CheckJSONContract(dirty); len(problems) == 0 {
		t.Error("a null value must be reported")
	}
}
