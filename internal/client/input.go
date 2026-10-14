package client

import (
	"bufio"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"hsxa-banner-fingerprint/internal/model"
)

// ReadRecords reads records from r in the requested format: json, jsonl, csv
// or auto (content sniffing).
func ReadRecords(r io.Reader, format string) ([]model.ScanRecord, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	switch format {
	case "json":
		return decodeJSON(data)
	case "jsonl":
		return decodeJSONL(data)
	case "csv":
		return decodeCSV(data)
	case "auto", "":
		return decodeAuto(data)
	default:
		return nil, fmt.Errorf("unknown input format %q", format)
	}
}

// decodeAuto sniffs the format: a JSON document wins, then JSONL, then CSV.
func decodeAuto(data []byte) ([]model.ScanRecord, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}
	switch {
	case strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{"):
		if records, err := decodeJSON(data); err == nil {
			return records, nil
		}
		return decodeJSONL(data)
	case strings.HasPrefix(strings.ToLower(trimmed), "ip,"),
		strings.HasPrefix(strings.ToLower(trimmed), "\"ip\","),
		looksLikeCSV(trimmed):
		return decodeCSV(data)
	default:
		return nil, fmt.Errorf("cannot detect the input format, pass --in-format")
	}
}

func looksLikeCSV(s string) bool {
	line := s
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		line = s[:i]
	}
	return strings.Count(line, ",") >= 2
}

// decodeJSON accepts a bare array, the {"records":[...]} request envelope or a
// single record object.
func decodeJSON(data []byte) ([]model.ScanRecord, error) {
	var records []model.ScanRecord
	if err := json.Unmarshal(data, &records); err == nil {
		return records, nil
	}
	var request model.Request
	if err := json.Unmarshal(data, &request); err == nil && request.Records != nil {
		return request.Records, nil
	}
	var single model.ScanRecord
	if err := json.Unmarshal(data, &single); err == nil && single.IP != "" {
		return []model.ScanRecord{single}, nil
	}
	return nil, fmt.Errorf("invalid JSON input: expected an array of records or a {\"records\":[...]} envelope")
}

func decodeJSONL(data []byte) ([]model.ScanRecord, error) {
	var records []model.ScanRecord
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		var rec model.ScanRecord
		if err := json.Unmarshal([]byte(text), &rec); err != nil {
			return nil, fmt.Errorf("jsonl line %d: %w", line, err)
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read jsonl: %w", err)
	}
	return records, nil
}

// decodeCSV reads the ip,port,banner layout of plan.md §3.2. The header row is
// optional; banner_base64 and encoding columns are understood when present.
func decodeCSV(data []byte) ([]model.ScanRecord, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse csv: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	header := indexHeader(rows[0])
	start := 0
	if header != nil {
		start = 1
	}
	var records []model.ScanRecord
	for i := start; i < len(rows); i++ {
		row := rows[i]
		rec := model.ScanRecord{}
		if header != nil {
			rec.IP = field(row, header, "ip")
			rec.Banner = field(row, header, "banner")
			rec.BannerBase64 = field(row, header, "banner_base64")
			rec.Encoding = field(row, header, "encoding")
			if port := field(row, header, "port"); port != "" {
				n, err := strconv.Atoi(strings.TrimSpace(port))
				if err != nil {
					return nil, fmt.Errorf("csv row %d: invalid port %q", i+1, port)
				}
				rec.Port = n
			}
		} else {
			if len(row) > 0 {
				rec.IP = strings.TrimSpace(row[0])
			}
			if len(row) > 1 {
				n, err := strconv.Atoi(strings.TrimSpace(row[1]))
				if err != nil {
					return nil, fmt.Errorf("csv row %d: invalid port %q", i+1, row[1])
				}
				rec.Port = n
			}
			if len(row) > 2 {
				rec.Banner = row[2]
			}
		}
		if rec.IP == "" && rec.Banner == "" {
			continue
		}
		records = append(records, rec)
	}
	return records, nil
}

func indexHeader(row []string) map[string]int {
	index := make(map[string]int, len(row))
	for i, cell := range row {
		index[strings.ToLower(strings.TrimSpace(cell))] = i
	}
	for _, required := range []string{"ip", "port"} {
		if _, ok := index[required]; !ok {
			return nil
		}
	}
	return index
}

func field(row []string, header map[string]int, name string) string {
	i, ok := header[name]
	if !ok || i >= len(row) {
		return ""
	}
	return row[i]
}

// PrepareForTransport encodes banners that are not valid UTF-8 as Base64, so a
// binary payload survives JSON untouched (plan.md R4). An explicitly requested
// encoding is left alone.
func PrepareForTransport(records []model.ScanRecord) []model.ScanRecord {
	for i := range records {
		rec := &records[i]
		if rec.Encoding != "" && rec.Encoding != model.EncodingAuto {
			continue
		}
		if rec.BannerBase64 == "" && rec.Banner != "" && !utf8.ValidString(rec.Banner) {
			rec.BannerBase64 = base64.StdEncoding.EncodeToString([]byte(rec.Banner))
			rec.Banner = ""
			rec.Encoding = model.EncodingBase64
		}
	}
	return records
}
