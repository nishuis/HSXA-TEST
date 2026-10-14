// Command bfp-cli identifies banners through a bfp-server instance.
//
// Usage:
//
//	bfp-cli identify [flags]
//	bfp-cli ping
//	bfp-cli version
//
// The identify command is the default, so "bfp-cli --input data.json" works as
// well. Exit codes: 0 all batches succeeded, 1 some batches failed,
// 2 usage or input error, 3 the server was unreachable.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"hsxa-banner-fingerprint/internal/client"
	"hsxa-banner-fingerprint/internal/config"
	"hsxa-banner-fingerprint/internal/model"
	"hsxa-banner-fingerprint/internal/version"
)

// Exit codes of bfp-cli (plan.md §3.2).
const (
	exitOK          = 0
	exitPartial     = 1
	exitUsage       = 2
	exitUnreachable = 3
)

const usage = `bfp-cli - banner fingerprinting client

Usage:
  bfp-cli identify [flags]   identify the records of an input file (default command)
  bfp-cli ping               check that the server is reachable
  bfp-cli version            print the build version

Common flags:
  --server string            server base URL (env BFP_SERVER, default http://localhost:8080)
  --version                  print the build version and exit

Identify flags:
  --input path|-             input file or stdin (default -)
  --output path|-            output file or stdout (default -)
  --in-format auto|json|jsonl|csv        (default auto)
  --out-format array|json|jsonl|csv      (default array)
  --banner-encoding auto|text|base64|hex (default auto)
  --batch-size N             records per request (default 1000)
  --concurrency N            parallel batches in flight (default 4)
  --timeout duration         per-request timeout (default 30s)
  --retry N                  retries for network errors and 5xx (default 2)
  --fail-fast                stop at the first failed batch
  --pretty                   indent JSON output
  --quiet                    suppress progress output on stderr

Exit codes: 0 success, 1 partial failure, 2 usage error, 3 server unreachable.
`

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	command := "identify"
	if len(args) > 0 {
		switch args[0] {
		case "identify", "ping", "version", "help":
			command = args[0]
			args = args[1:]
		}
	}
	switch command {
	case "help":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "version":
		fmt.Fprintln(stdout, "bfp-cli", version.String())
		return exitOK
	}

	cfg, err := config.LoadCLI(args, getenv)
	if err != nil {
		fmt.Fprintln(stderr, "bfp-cli:", err)
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	if cfg.ShowVersion {
		fmt.Fprintln(stdout, "bfp-cli", version.String())
		return exitOK
	}

	// The timeout of the HTTP client must cover the retry backoff as well.
	cli := client.New(cfg.Server, cfg.Timeout, cfg.Retry)
	if command == "ping" {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
		defer cancel()
		meta, err := cli.Ping(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "bfp-cli: ping failed:", err)
			return unreachableOr(err)
		}
		fmt.Fprintf(stdout, "server ok: version=%s protocols=%d rules=%d uptime=%ds\n",
			meta.Version, len(meta.Protocols), meta.RuleCount, meta.UptimeSecs)
		return exitOK
	}

	records, err := readInput(cfg.Input, cfg.InFormat, stdin)
	if err != nil {
		fmt.Fprintln(stderr, "bfp-cli:", err)
		return exitUsage
	}
	if len(records) == 0 {
		fmt.Fprintln(stderr, "bfp-cli: no records to identify")
		return exitUsage
	}
	records = client.PrepareForTransport(records)

	if !cfg.Quiet {
		fmt.Fprintf(stderr, "bfp-cli: %d records, batch-size %d, concurrency %d\n",
			len(records), cfg.BatchSize, cfg.Concurrency)
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestBudget(cfg, len(records)))
	defer cancel()
	results, failed, firstErr := cli.IdentifyBatched(ctx, records, cfg.BatchSize, cfg.Concurrency, cfg.FailFast)

	if err := writeOutput(cfg, stdout, results); err != nil {
		fmt.Fprintln(stderr, "bfp-cli:", err)
		return exitUsage
	}
	if failed > 0 {
		fmt.Fprintf(stderr, "bfp-cli: %d of %d batches failed: %v\n", failed, batchCount(len(records), cfg.BatchSize), firstErr)
		return unreachableOr(firstErr)
	}
	if !cfg.Quiet {
		fmt.Fprintf(stderr, "bfp-cli: identified %d records\n", len(results))
	}
	return exitOK
}

// requestBudget scales the overall deadline with the amount of work.
func requestBudget(cfg *config.CLI, records int) time.Duration {
	batches := batchCount(records, cfg.BatchSize)
	rounds := batches / cfg.Concurrency
	if batches%cfg.Concurrency != 0 {
		rounds++
	}
	if rounds < 1 {
		rounds = 1
	}
	return time.Duration(rounds+1) * cfg.Timeout
}

func batchCount(records, batchSize int) int {
	if batchSize < 1 {
		return 1
	}
	n := records / batchSize
	if records%batchSize != 0 {
		n++
	}
	return n
}

func unreachableOr(err error) int {
	if errors.Is(err, client.ErrUnreachable) {
		return exitUnreachable
	}
	return exitPartial
}

func readInput(path, format string, stdin io.Reader) ([]model.ScanRecord, error) {
	reader := stdin
	if path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open input: %w", err)
		}
		defer func() { _ = file.Close() }()
		reader = file
	}
	return client.ReadRecords(reader, format)
}

func writeOutput(cfg *config.CLI, stdout io.Writer, results []model.Result) error {
	writer := stdout
	if cfg.Output != "-" {
		file, err := os.Create(cfg.Output)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer func() { _ = file.Close() }()
		writer = file
	}
	return client.WriteResults(writer, results, cfg.OutFormat, cfg.Pretty)
}
