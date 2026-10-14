package client

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"hsxa-banner-fingerprint/internal/model"
)

// WriteResults renders results in the requested format: array (a bare JSON
// array, the default of bfp-cli), json (the response envelope), jsonl or csv.
func WriteResults(w io.Writer, results []model.Result, format string, pretty bool) error {
	if results == nil {
		// Never serialise a nil slice: the contract is [] rather than null.
		results = []model.Result{}
	}
	switch format {
	case "", "array":
		return writeJSONValue(w, results, pretty)
	case "json":
		return writeJSONValue(w, model.Response{
			Results: results,
			Stats:   model.StatsOf(results, 0),
		}, pretty)
	case "jsonl":
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		for _, res := range results {
			if err := enc.Encode(res); err != nil {
				return fmt.Errorf("write jsonl: %w", err)
			}
		}
		return nil
	case "csv":
		return writeCSV(w, results)
	default:
		return fmt.Errorf("unknown output format %q", format)
	}
}

func writeJSONValue(w io.Writer, value any, pretty bool) error {
	var (
		data []byte
		err  error
	)
	if pretty {
		data, err = json.MarshalIndent(value, "", "  ")
	} else {
		data, err = json.Marshal(value)
	}
	if err != nil {
		return fmt.Errorf("encode output: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	_, err = io.WriteString(w, "\n")
	return err
}

// csvHeader is the column order of the CSV output, matching the input layout
// plus the identification fields.
var csvHeader = []string{"ip", "port", "protocol", "product", "version", "os_hint", "confidence"}

func writeCSV(w io.Writer, results []model.Result) error {
	writer := csv.NewWriter(w)
	if err := writer.Write(csvHeader); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}
	for _, res := range results {
		row := []string{
			res.IP,
			strconv.Itoa(res.Port),
			res.Protocol,
			res.Product,
			res.Version,
			res.OSHint,
			strconv.FormatFloat(res.Confidence, 'f', 2, 64),
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("write csv row: %w", err)
		}
	}
	writer.Flush()
	return writer.Error()
}
