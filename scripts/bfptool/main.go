// Command bfptool is the acceptance helper of the banner fingerprinting
// system. It is not part of the delivered product; it exists so that
// scripts/acceptance.sh and the performance check can compare results and
// generate samples without depending on jq or Python.
//
// Usage:
//
//	bfptool compare [--epsilon 0.05] <expected.json> <actual.json>
//	bfptool shape   [--count N] <results.json>
//	bfptool gen     --records N [--out path]
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"regexp"
	"strings"

	"hsxa-banner-fingerprint/internal/model"
	"hsxa-banner-fingerprint/internal/verify"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "compare":
		return compare(args[1:], stdout, stderr)
	case "shape":
		return shape(args[1:], stdout, stderr)
	case "gen":
		return gen(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "bfptool: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `bfptool - acceptance helper

  bfptool compare [--epsilon 0.05] <expected.json> <actual.json>
  bfptool shape   [--count N] <results.json>
  bfptool gen     --records N [--out path]

Use - to read a file from stdin.
`)
}

func compare(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(stderr)
	epsilon := fs.Float64("epsilon", verify.DefaultOptions.ConfidenceEpsilon, "tolerated confidence difference")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "compare needs an expected and an actual file")
		return 2
	}
	want, err := readResults(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "bfptool:", err)
		return 2
	}
	got, err := readResults(fs.Arg(1))
	if err != nil {
		fmt.Fprintln(stderr, "bfptool:", err)
		return 2
	}
	problems := verify.Compare(want, got, verify.Options{ConfidenceEpsilon: *epsilon})
	for _, p := range problems {
		fmt.Fprintln(stderr, "mismatch:", p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(stderr, "compare: %d mismatch(es) over %d expected records\n", len(problems), len(want))
		return 1
	}
	fmt.Fprintf(stdout, "compare: %d records match (protocol, product, version, os_hint, order, confidence ±%.2f)\n",
		len(want), *epsilon)
	return 0
}

// resultKeys is the frozen field order of a result object (plan.md §1.2).
var resultKeys = []string{"ip", "port", "protocol", "product", "version", "os_hint", "confidence"}

// integerRe and numberRe enforce the declared JSON types of port and
// confidence without relying on Go's permissive number decoding.
var (
	integerRe = regexp.MustCompile(`^-?\d+$`)
	numberRe  = regexp.MustCompile(`^-?\d+(\.\d+)?$`)
)

func shape(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("shape", flag.ContinueOnError)
	fs.SetOutput(stderr)
	count := fs.Int("count", -1, "expected number of results")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "shape needs exactly one results file")
		return 2
	}
	raw, err := readFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "bfptool:", err)
		return 2
	}
	problems := checkShape(raw, *count)
	for _, p := range problems {
		fmt.Fprintln(stderr, "shape:", p)
	}
	if len(problems) > 0 {
		return 1
	}
	fmt.Fprintf(stdout, "shape: contract holds (%d results, 7 fields, no null, port int, confidence float)\n", *count)
	return 0
}

// checkShape validates the serialisation contract of plan.md §1.2 and §3.3 on
// a raw response body.
func checkShape(raw []byte, wantCount int) []string {
	var problems []string
	if bytes.Contains(raw, []byte("null")) {
		problems = append(problems, "body contains null; missing values must be the empty string")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return append(problems, "invalid JSON: "+err.Error())
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return append(problems, "top level is not a JSON array")
	}
	index := 0
	for dec.More() {
		fields, err := scanObject(dec)
		if err != nil {
			return append(problems, fmt.Sprintf("result %d: %v", index, err))
		}
		if len(fields) != len(resultKeys) {
			problems = append(problems, fmt.Sprintf("result %d has %d fields, want %d", index, len(fields), len(resultKeys)))
		}
		for i, key := range resultKeys {
			if i >= len(fields) {
				break
			}
			if fields[i].key != key {
				problems = append(problems, fmt.Sprintf("result %d field %d is %q, want %q", index, i, fields[i].key, key))
				continue
			}
			problems = append(problems, checkFieldType(index, key, fields[i].raw)...)
		}
		index++
	}
	if wantCount >= 0 && index != wantCount {
		problems = append(problems, fmt.Sprintf("result count is %d, want %d", index, wantCount))
	}
	return problems
}

type field struct {
	key string
	raw json.RawMessage
}

// scanObject reads one JSON object, preserving the key order.
func scanObject(dec *json.Decoder) ([]field, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("expected a JSON object")
	}
	var fields []field
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, errors.New("object key is not a string")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		fields = append(fields, field{key: key, raw: raw})
	}
	if _, err := dec.Token(); err != nil { // consume '}'
		return nil, err
	}
	return fields, nil
}

func checkFieldType(index int, key string, raw json.RawMessage) []string {
	value := strings.TrimSpace(string(raw))
	asString := func() (string, bool) {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", false
		}
		return s, true
	}
	switch key {
	case "ip":
		if _, ok := asString(); !ok {
			return []string{fmt.Sprintf("result %d: ip is not a string", index)}
		}
	case "port":
		if !integerRe.MatchString(value) {
			return []string{fmt.Sprintf("result %d: port %s is not an integer", index, value)}
		}
	case "protocol", "product", "version", "os_hint":
		if _, ok := asString(); !ok {
			return []string{fmt.Sprintf("result %d: %s is not a string", index, key)}
		}
	case "confidence":
		if !numberRe.MatchString(value) {
			return []string{fmt.Sprintf("result %d: confidence %s is not a number", index, value)}
		}
		var f float64
		if err := json.Unmarshal(raw, &f); err == nil && (f < 0 || f > 1) {
			return []string{fmt.Sprintf("result %d: confidence %.2f is outside 0..1", index, f)}
		}
	}
	return nil
}

// gen writes a synthetic input file for the performance and boundary checks.
func gen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	records := fs.Int("records", 1000, "number of records to generate")
	out := fs.String("out", "-", "output file or - for stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *records < 1 {
		fmt.Fprintln(stderr, "bfptool: --records must be >= 1")
		return 2
	}
	payload := generate(*records)
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(model.Request{Records: payload}); err != nil {
		fmt.Fprintln(stderr, "bfptool: encode:", err)
		return 1
	}
	if *out == "-" {
		if _, err := stdout.Write(buf.Bytes()); err != nil {
			fmt.Fprintln(stderr, "bfptool:", err)
			return 1
		}
		return 0
	}
	if err := os.WriteFile(*out, buf.Bytes(), 0o600); err != nil {
		fmt.Fprintln(stderr, "bfptool:", err)
		return 1
	}
	fmt.Fprintf(stderr, "wrote %d records to %s\n", *records, *out)
	return 0
}

// templates are real banners, one per supported protocol family plus
// deliberately broken payloads.
var templates = []struct {
	port   int
	banner string
	base64 string
}{
	{22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4", ""},
	{22, "SSH-2.0-dropbear_2020.81", ""},
	{80, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n<html></html>", ""},
	{443, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Ubuntu)\r\n\r\n", ""},
	{8080, "HTTP/1.1 200 OK\r\nServer: Jetty(9.4.51)\r\n\r\n", ""},
	{21, "220 ProFTPD 1.3.7 Server (Debian) [::ffff:10.0.0.1]", ""},
	{21, "220 (vsFTPd 3.0.5)", ""},
	{25, "220 mx.example.com ESMTP Postfix", ""},
	{110, "+OK Dovecot ready.", ""},
	{143, "* OK [CAPABILITY IMAP4rev1] Dovecot ready.", ""},
	{6379, "-NOAUTH Authentication required.\r\n", ""},
	{6379, "# Server\r\nredis_version:7.2.3\r\n", ""},
	{11211, "VERSION 1.6.21\r\n", ""},
	{5432, "", "UgAAAAgAAAAAUwAAADJzZXJ2ZXJfdmVyc2lvbgAxNi4xIChEZWJpYW4gMTYuMS0xLnBnZGcxMjArMSkA"},
	{27017, "buildInfo: {\"version\":\"6.0.12\"}", ""},
	{5900, "RFB 003.008\r\n", ""},
	{9200, "HTTP/1.1 200 OK\r\nX-elastic-product: Elasticsearch\r\n\r\n{\"version\":{\"number\":\"8.11.1\"}}", ""},
	{9999, "nothing to identify here", ""},
	{9999, "", ""},
	{9999, "\xff\xfe\x00\x01 not utf8 \xff", ""},
}

func generate(n int) []model.ScanRecord {
	rng := rand.New(rand.NewSource(20261014))
	out := make([]model.ScanRecord, 0, n)
	for i := 0; i < n; i++ {
		tpl := templates[rng.Intn(len(templates))]
		rec := model.ScanRecord{
			IP:   fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256),
			Port: tpl.port,
		}
		switch {
		case tpl.base64 != "":
			rec.BannerBase64 = tpl.base64
			rec.Encoding = model.EncodingBase64
		default:
			rec.Banner = tpl.banner
		}
		out = append(out, rec)
	}
	return out
}

func readResults(path string) ([]model.Result, error) {
	raw, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var results []model.Result
	if err := json.Unmarshal(raw, &results); err == nil {
		return results, nil
	}
	var envelope model.Response
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("parse %s: expected a result array or a response envelope", path)
	}
	return envelope.Results, nil
}

func readFile(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return raw, nil
}
