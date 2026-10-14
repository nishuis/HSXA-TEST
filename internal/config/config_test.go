package config

import (
	"testing"
	"time"
)

func envFrom(pairs map[string]string) func(string) string {
	return func(key string) string { return pairs[key] }
}

func TestLoadServerDefaults(t *testing.T) {
	cfg, err := LoadServer(nil, envFrom(nil))
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.ListenAddr != DefaultListenAddr || cfg.LogLevel != DefaultLogLevel {
		t.Errorf("defaults = %+v", cfg)
	}
	if cfg.MaxBody != DefaultMaxBody || cfg.MaxRecords != DefaultMaxRecords || cfg.MaxBannerBytes != DefaultMaxBannerBytes {
		t.Errorf("limits = %+v", cfg)
	}
	if cfg.HealthCheck || cfg.ShowVersion {
		t.Errorf("boolean defaults = %+v", cfg)
	}
	if cfg.HealthCheckURL != "http://127.0.0.1:8080/healthz" {
		t.Errorf("HealthCheckURL = %q", cfg.HealthCheckURL)
	}
}

func TestLoadServerPrecedence(t *testing.T) {
	env := envFrom(map[string]string{
		"BFP_LISTEN_ADDR":      "0.0.0.0:9000",
		"BFP_LOG_LEVEL":        "debug",
		"BFP_MAX_BODY":         "1024",
		"BFP_MAX_RECORDS":      "7",
		"BFP_MAX_BANNER_BYTES": "128",
		"BFP_RULES_DIR":        "/etc/bfp/rules",
	})
	cfg, err := LoadServer(nil, env)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.ListenAddr != "0.0.0.0:9000" || cfg.LogLevel != "debug" {
		t.Errorf("env not applied: %+v", cfg)
	}
	if cfg.MaxBody != 1024 || cfg.MaxRecords != 7 || cfg.MaxBannerBytes != 128 {
		t.Errorf("env limits not applied: %+v", cfg)
	}
	if cfg.RulesDir != "/etc/bfp/rules" {
		t.Errorf("RulesDir = %q", cfg.RulesDir)
	}
	if cfg.HealthCheckURL != "http://127.0.0.1:9000/healthz" {
		t.Errorf("HealthCheckURL should follow the listen address: %q", cfg.HealthCheckURL)
	}

	// A flag beats the environment.
	cfg, err = LoadServer([]string{"--listen", "127.0.0.1:1234", "--max-records", "3"}, env)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:1234" || cfg.MaxRecords != 3 {
		t.Errorf("flag did not win: %+v", cfg)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("untouched env value lost: %+v", cfg)
	}
}

func TestLoadServerErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{"unknown-flag", []string{"--nope"}, nil},
		{"positional-arg", []string{"extra"}, nil},
		{"bad-log-level", []string{"--log-level", "chatty"}, nil},
		{"negative-limit", []string{"--max-records", "0"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadServer(tc.args, envFrom(tc.env)); err == nil {
				t.Fatal("LoadServer() = nil, want an error")
			}
		})
	}
}

func TestHealthCheckURLVariants(t *testing.T) {
	tests := map[string]string{
		"0.0.0.0:8080":   "http://127.0.0.1:8080/healthz",
		"[::]:8080":      "http://127.0.0.1:8080/healthz",
		":8080":          "http://127.0.0.1:8080/healthz",
		"127.0.0.1:9001": "http://127.0.0.1:9001/healthz",
	}
	for listen, want := range tests {
		cfg, err := LoadServer([]string{"--listen", listen}, envFrom(nil))
		if err != nil {
			t.Fatalf("LoadServer(%q): %v", listen, err)
		}
		if cfg.HealthCheckURL != want {
			t.Errorf("listen %q → %q, want %q", listen, cfg.HealthCheckURL, want)
		}
	}
}

func TestLoadCLIDefaultsAndFlags(t *testing.T) {
	cfg, err := LoadCLI(nil, envFrom(nil))
	if err != nil {
		t.Fatalf("LoadCLI: %v", err)
	}
	if cfg.Server != DefaultServer || cfg.Input != "-" || cfg.Output != "-" {
		t.Errorf("defaults = %+v", cfg)
	}
	if cfg.OutFormat != "array" {
		t.Errorf("default out format = %q, want array", cfg.OutFormat)
	}
	if cfg.InFormat != "auto" || cfg.Encoding != "auto" {
		t.Errorf("default formats = %+v", cfg)
	}
	if cfg.BatchSize != DefaultBatchSize || cfg.Concurrency != DefaultConcurrency || cfg.Retry != DefaultRetry || cfg.Timeout != DefaultTimeout {
		t.Errorf("default batching = %+v", cfg)
	}

	cfg, err = LoadCLI([]string{
		"--server", "http://example:9", "--input", "in.jsonl", "--output", "out.csv",
		"--in-format", "jsonl", "--out-format", "csv", "--banner-encoding", "hex",
		"--batch-size", "10", "--concurrency", "2", "--retry", "5",
		"--timeout", "5s", "--fail-fast", "--quiet", "--pretty",
	}, envFrom(nil))
	if err != nil {
		t.Fatalf("LoadCLI: %v", err)
	}
	if cfg.Server != "http://example:9" || cfg.InFormat != "jsonl" || cfg.OutFormat != "csv" {
		t.Errorf("flags not applied: %+v", cfg)
	}
	if cfg.Encoding != "hex" || cfg.BatchSize != 10 || cfg.Concurrency != 2 || cfg.Retry != 5 {
		t.Errorf("flags not applied: %+v", cfg)
	}
	if cfg.Timeout != 5*time.Second || !cfg.FailFast || !cfg.Quiet || !cfg.Pretty {
		t.Errorf("flags not applied: %+v", cfg)
	}

	// Environment supplies the server and the batching defaults.
	cfg, err = LoadCLI(nil, envFrom(map[string]string{
		"BFP_SERVER":      "http://env:8080",
		"BFP_BATCH_SIZE":  "77",
		"BFP_CONCURRENCY": "9",
		"BFP_OUT_FORMAT":  "jsonl",
	}))
	if err != nil {
		t.Fatalf("LoadCLI: %v", err)
	}
	if cfg.Server != "http://env:8080" || cfg.BatchSize != 77 || cfg.Concurrency != 9 || cfg.OutFormat != "jsonl" {
		t.Errorf("env not applied: %+v", cfg)
	}
}

func TestLoadCLIErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"bad-in-format", []string{"--in-format", "xml"}},
		{"bad-out-format", []string{"--out-format", "yaml"}},
		{"bad-encoding", []string{"--banner-encoding", "rot13"}},
		{"bad-batch-size", []string{"--batch-size", "0"}},
		{"bad-concurrency", []string{"--concurrency", "0"}},
		{"bad-retry", []string{"--retry", "-1"}},
		{"bad-timeout", []string{"--timeout", "0s"}},
		{"unknown-flag", []string{"--nope"}},
		{"positional", []string{"extra"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadCLI(tc.args, envFrom(nil)); err == nil {
				t.Fatal("LoadCLI() = nil, want an error")
			}
		})
	}
}

func TestEnvHelpers(t *testing.T) {
	env := envFrom(map[string]string{"SET": "value", "NUM": "12", "BAD": "abc", "BLANK": "  "})
	if got := EnvString(env, "SET", "def"); got != "value" {
		t.Errorf("EnvString = %q", got)
	}
	if got := EnvString(env, "MISSING", "def"); got != "def" {
		t.Errorf("EnvString default = %q", got)
	}
	if got := EnvString(env, "BLANK", "def"); got != "def" {
		t.Errorf("blank EnvString = %q, want the default", got)
	}
	if got := EnvInt(env, "NUM", 1); got != 12 {
		t.Errorf("EnvInt = %d", got)
	}
	if got := EnvInt(env, "BAD", 5); got != 5 {
		t.Errorf("EnvInt should fall back on a parse error, got %d", got)
	}
	if got := EnvInt(env, "MISSING", 5); got != 5 {
		t.Errorf("EnvInt default = %d", got)
	}
}
