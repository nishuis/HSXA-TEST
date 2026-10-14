package engine_test

import (
	"fmt"
	"testing"

	"hsxa-banner-fingerprint/internal/engine"
	"hsxa-banner-fingerprint/internal/model"
	"hsxa-banner-fingerprint/internal/rules"
)

// benchmarkRecords builds a mixed batch that exercises every protocol family,
// including records that cannot be identified.
func benchmarkRecords(n int) []model.ScanRecord {
	templates := []model.ScanRecord{
		{Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"},
		{Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"},
		{Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Ubuntu)\r\n\r\n"},
		{Port: 8080, Banner: "HTTP/1.1 200 OK\r\nServer: Jetty(9.4.51)\r\n\r\n"},
		{Port: 3306, BannerBase64: "SQAAAAo4LjAuMzIAAQAAAGFiY2RlZmdoAP/3IQIA/4EVAAAAAAAAAAAAAGlqa2xtbm9wcXJzAG15c3FsX25hdGl2ZV9wYXNzd29yZAA=", Encoding: "base64"},
		{Port: 6379, Banner: "-NOAUTH Authentication required.\r\n"},
		{Port: 21, Banner: "220 ProFTPD 1.3.7 Server (Debian) [::ffff:10.0.0.1]"},
		{Port: 25, Banner: "220 mx.example.com ESMTP Postfix"},
		{Port: 5432, BannerBase64: "UgAAAAgAAAAAUwAAADJzZXJ2ZXJfdmVyc2lvbgAxNi4xIChEZWJpYW4gMTYuMS0xLnBnZGcxMjArMSkA", Encoding: "base64"},
		{Port: 11211, Banner: "VERSION 1.6.21\r\n"},
		{Port: 5900, Banner: "RFB 003.008\r\n"},
		{Port: 9999, Banner: "nothing to identify here"},
		{Port: 9999, Banner: ""},
	}
	records := make([]model.ScanRecord, 0, n)
	for i := 0; i < n; i++ {
		tpl := templates[i%len(templates)]
		tpl.IP = fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)
		records = append(records, tpl)
	}
	return records
}

func benchmarkEngine(b *testing.B) *engine.Engine {
	b.Helper()
	reg, err := rules.Builtin()
	if err != nil {
		b.Fatalf("Builtin: %v", err)
	}
	return engine.New(reg)
}

// BenchmarkIdentify measures the single record cost; NFR-1 asks for the 1ms
// order of magnitude.
func BenchmarkIdentify(b *testing.B) {
	eng := benchmarkEngine(b)
	records := benchmarkRecords(1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eng.Identify(records[i%len(records)])
	}
}

// BenchmarkIdentifyBatch100k is the acceptance-scale run of NFR-1.
func BenchmarkIdentifyBatch100k(b *testing.B) {
	eng := benchmarkEngine(b)
	records := benchmarkRecords(100000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results := eng.IdentifyBatch(records)
		if len(results) != len(records) {
			b.Fatalf("results = %d, want %d", len(results), len(records))
		}
	}
}
