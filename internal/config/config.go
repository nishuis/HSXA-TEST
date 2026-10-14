// Package config loads the settings of bfp-server and bfp-cli from command
// line flags and BFP_* environment variables.
//
// Precedence is flag > environment > default. Defaults live in the
// Default* functions so that both binaries and the tests share one source of
// truth for the limits of plan.md §NFR-5.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Default limits of the REST API (NFR-5).
const (
	DefaultListenAddr     = ":8080"
	DefaultLogLevel       = "info"
	DefaultMaxBody        = 32 << 20 // 32 MiB
	DefaultMaxRecords     = 200000
	DefaultMaxBannerBytes = 64 << 10 // 64 KiB
	DefaultReadTimeout    = 15 * time.Second
	DefaultWriteTimeout   = 60 * time.Second
	DefaultIdleTimeout    = 60 * time.Second
	DefaultShutdownGrace  = 10 * time.Second
)

// Default CLI settings (plan.md §3.2).
const (
	DefaultServer         = "http://localhost:8080"
	DefaultBatchSize      = 1000
	DefaultConcurrency    = 4
	DefaultRetry          = 2
	DefaultTimeout        = 30 * time.Second
	DefaultInFormat       = "auto"
	DefaultOutFormat      = "array"
	DefaultBannerEncoding = "auto"
)

// Server holds the bfp-server configuration.
type Server struct {
	ListenAddr     string
	LogLevel       string
	MaxBody        int64
	MaxRecords     int
	MaxBannerBytes int
	RulesDir       string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	ShutdownGrace  time.Duration
	HealthCheck    bool
	HealthCheckURL string
	ShowVersion    bool
}

// LoadServer parses the bfp-server command line. args must not include the
// program name. getenv is os.Getenv in production and a stub in tests.
func LoadServer(args []string, getenv func(string) string) (*Server, error) {
	cfg := &Server{
		ListenAddr:     EnvString(getenv, "BFP_LISTEN_ADDR", DefaultListenAddr),
		LogLevel:       EnvString(getenv, "BFP_LOG_LEVEL", DefaultLogLevel),
		MaxBody:        int64(EnvInt(getenv, "BFP_MAX_BODY", int(DefaultMaxBody))),
		MaxRecords:     EnvInt(getenv, "BFP_MAX_RECORDS", DefaultMaxRecords),
		MaxBannerBytes: EnvInt(getenv, "BFP_MAX_BANNER_BYTES", DefaultMaxBannerBytes),
		RulesDir:       EnvString(getenv, "BFP_RULES_DIR", ""),
		ReadTimeout:    DefaultReadTimeout,
		WriteTimeout:   DefaultWriteTimeout,
		IdleTimeout:    DefaultIdleTimeout,
		ShutdownGrace:  DefaultShutdownGrace,
	}
	fs := flag.NewFlagSet("bfp-server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "address to listen on")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level: debug, info, warn, error")
	fs.Int64Var(&cfg.MaxBody, "max-body", cfg.MaxBody, "maximum request body size in bytes")
	fs.IntVar(&cfg.MaxRecords, "max-records", cfg.MaxRecords, "maximum records per request")
	fs.IntVar(&cfg.MaxBannerBytes, "max-banner-bytes", cfg.MaxBannerBytes, "maximum banner size in bytes")
	fs.StringVar(&cfg.RulesDir, "rules-dir", cfg.RulesDir, "directory of external YAML rule overlays")
	fs.DurationVar(&cfg.ReadTimeout, "read-timeout", cfg.ReadTimeout, "HTTP read timeout")
	fs.DurationVar(&cfg.WriteTimeout, "write-timeout", cfg.WriteTimeout, "HTTP write timeout")
	fs.DurationVar(&cfg.ShutdownGrace, "shutdown-grace", cfg.ShutdownGrace, "grace period for in-flight requests")
	fs.BoolVar(&cfg.HealthCheck, "health-check", false, "probe /healthz and exit (used by container healthchecks)")
	fs.StringVar(&cfg.HealthCheckURL, "health-check-url", "", "override the URL probed by -health-check")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "print the build version and exit")
	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("parse flags: %w", err)
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	switch strings.ToLower(cfg.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		return nil, fmt.Errorf("invalid log level %q", cfg.LogLevel)
	}
	if cfg.MaxBody <= 0 || cfg.MaxRecords <= 0 || cfg.MaxBannerBytes <= 0 {
		return nil, errors.New("limits must be positive")
	}
	if cfg.HealthCheckURL == "" {
		cfg.HealthCheckURL = "http://127.0.0.1" + healthHostPort(cfg.ListenAddr) + "/healthz"
	}
	return cfg, nil
}

// healthHostPort turns a listen address into a host:port pair a loopback probe
// can dial.
func healthHostPort(listen string) string {
	switch {
	case strings.HasPrefix(listen, ":"):
		return listen
	case strings.HasPrefix(listen, "0.0.0.0"):
		return strings.TrimPrefix(listen, "0.0.0.0")
	case strings.HasPrefix(listen, "[::]"):
		return strings.TrimPrefix(listen, "[::]")
	default:
		if i := strings.LastIndex(listen, ":"); i >= 0 {
			return listen[i:]
		}
		return ":8080"
	}
}

// CLI holds the bfp-cli configuration.
type CLI struct {
	Server      string
	Input       string
	Output      string
	InFormat    string
	OutFormat   string
	Encoding    string
	BatchSize   int
	Concurrency int
	Retry       int
	Timeout     time.Duration
	FailFast    bool
	Quiet       bool
	Pretty      bool
	ShowVersion bool
}

// LoadCLI parses the bfp-cli command line for the identify and ping commands.
func LoadCLI(args []string, getenv func(string) string) (*CLI, error) {
	cfg := &CLI{
		Server:      EnvString(getenv, "BFP_SERVER", DefaultServer),
		Input:       "-",
		Output:      "-",
		InFormat:    DefaultInFormat,
		OutFormat:   DefaultOutFormat,
		Encoding:    DefaultBannerEncoding,
		BatchSize:   DefaultBatchSize,
		Concurrency: DefaultConcurrency,
		Retry:       DefaultRetry,
		Timeout:     DefaultTimeout,
	}
	if v := getenv("BFP_OUT_FORMAT"); v != "" {
		cfg.OutFormat = v
	}
	if v := getenv("BFP_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.BatchSize = n
		}
	}
	if v := getenv("BFP_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Concurrency = n
		}
	}
	fs := flag.NewFlagSet("bfp-cli", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.Server, "server", cfg.Server, "bfp-server base URL")
	fs.StringVar(&cfg.Input, "input", cfg.Input, "input file or - for stdin")
	fs.StringVar(&cfg.Output, "output", cfg.Output, "output file or - for stdout")
	fs.StringVar(&cfg.InFormat, "in-format", cfg.InFormat, "input format: auto, json, jsonl, csv")
	fs.StringVar(&cfg.OutFormat, "out-format", cfg.OutFormat, "output format: array, json, jsonl, csv")
	fs.StringVar(&cfg.Encoding, "banner-encoding", cfg.Encoding, "banner encoding: auto, text, base64, hex")
	fs.IntVar(&cfg.BatchSize, "batch-size", cfg.BatchSize, "records per request")
	fs.IntVar(&cfg.Concurrency, "concurrency", cfg.Concurrency, "parallel batches in flight")
	fs.IntVar(&cfg.Retry, "retry", cfg.Retry, "retries for network errors and 5xx")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "per-request timeout")
	fs.BoolVar(&cfg.FailFast, "fail-fast", false, "stop at the first failed batch")
	fs.BoolVar(&cfg.Quiet, "quiet", false, "suppress progress output on stderr")
	fs.BoolVar(&cfg.Pretty, "pretty", false, "indent JSON output")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "print the build version and exit")
	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("parse flags: %w", err)
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	switch cfg.InFormat {
	case "auto", "json", "jsonl", "csv":
	default:
		return nil, fmt.Errorf("invalid --in-format %q", cfg.InFormat)
	}
	switch cfg.OutFormat {
	case "array", "json", "jsonl", "csv":
	default:
		return nil, fmt.Errorf("invalid --out-format %q", cfg.OutFormat)
	}
	switch cfg.Encoding {
	case "auto", "text", "base64", "hex":
	default:
		return nil, fmt.Errorf("invalid --banner-encoding %q", cfg.Encoding)
	}
	if cfg.BatchSize < 1 || cfg.Concurrency < 1 || cfg.Retry < 0 {
		return nil, errors.New("--batch-size and --concurrency must be >= 1, --retry >= 0")
	}
	if cfg.Timeout <= 0 {
		return nil, errors.New("--timeout must be positive")
	}
	return cfg, nil
}

// EnvString returns the environment value or a default.
func EnvString(getenv func(string) string, key, def string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return def
}

// EnvInt returns the environment value as an int or a default.
func EnvInt(getenv func(string) string, key string, def int) int {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
