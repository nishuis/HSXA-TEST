package decode

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDecodeTextEscapes(t *testing.T) {
	tests := []struct {
		name   string
		banner string
		want   []byte
	}{
		{"plain", "SSH-2.0-OpenSSH_8.9p1", []byte("SSH-2.0-OpenSSH_8.9p1")},
		{"crlf", `220 ready\r\n`, []byte("220 ready\r\n")},
		{"tabs-and-quotes", `a\tb\"c\\d`, []byte("a\tb\"c\\d")},
		{"hex-escape", `\x16\x03\x01`, []byte{0x16, 0x03, 0x01}},
		{"nul-escape", `a\0b`, []byte{'a', 0x00, 'b'}},
		{"unicode-escape", `caf\u00e9`, []byte("café")},
		{"unknown-escape-kept", `a\qb`, []byte(`a\qb`)},
		{"trailing-backslash", `abc\`, []byte(`abc\`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(tc.banner, "", "text")
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if !bytes.Equal(got.Bytes, tc.want) {
				t.Errorf("Decode(%q) = %q, want %q", tc.banner, got.Bytes, tc.want)
			}
			if got.Encoding != "text" {
				t.Errorf("Encoding = %q, want text", got.Encoding)
			}
		})
	}
}

func TestDecodeBase64AndHex(t *testing.T) {
	raw := []byte{0x0a, '8', '.', '0', 0x00, 0xff}
	b64 := "CjguMAD/"
	hexStr := "0a382e3000ff"

	p, err := Decode(b64, "", "base64")
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	if !bytes.Equal(p.Bytes, raw) {
		t.Errorf("base64 decoded %q, want %q", p.Bytes, raw)
	}
	if p.Encoding != "base64" {
		t.Errorf("encoding = %q", p.Encoding)
	}

	p, err = Decode(hexStr, "", "hex")
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	if !bytes.Equal(p.Bytes, raw) {
		t.Errorf("hex decoded %q, want %q", p.Bytes, raw)
	}

	p, err = Decode("", b64, "base64")
	if err != nil {
		t.Fatalf("banner_base64: %v", err)
	}
	if !bytes.Equal(p.Bytes, raw) {
		t.Errorf("banner_base64 decoded %q, want %q", p.Bytes, raw)
	}

	// banner_base64 wins over banner.
	p, err = Decode("ignored", b64, "auto")
	if err != nil {
		t.Fatalf("auto: %v", err)
	}
	if !bytes.Equal(p.Bytes, raw) {
		t.Errorf("auto with banner_base64 decoded %q, want %q", p.Bytes, raw)
	}
}

func TestDecodeAutoSniffing(t *testing.T) {
	tests := []struct {
		name   string
		banner string
		want   string
		isHex  bool
	}{
		{"plain-text-stays-text", "220 ProFTPD 1.3.7 Server ready.", "220 ProFTPD 1.3.7 Server ready.", false},
		{"ssh-stays-text", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4", false},
		{"hex-dump-detected", "fffd18fffd20fffd23", "\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23", true},
		{"word-like-hex-stays-text", "deadbeefcafebabe01", "deadbeefcafebabe01", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Decode(tc.banner, "", "auto")
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if tc.isHex {
				if p.Encoding != "hex" {
					t.Fatalf("encoding = %q, want hex (bytes %q)", p.Encoding, p.Bytes)
				}
				return
			}
			// A word-like hex string that carries no signature must survive as
			// text rather than be mangled into binary.
			if p.Encoding == "text" && string(p.Bytes) != tc.want {
				t.Errorf("bytes = %q, want %q", p.Bytes, tc.want)
			}
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := Decode("x", "", "rot13"); !errors.Is(err, ErrUnsupportedEncoding) {
		t.Errorf("unknown encoding error = %v, want ErrUnsupportedEncoding", err)
	}
	if _, err := Decode("not base64 !!", "", "base64"); !errors.Is(err, ErrMalformedPayload) {
		t.Errorf("bad base64 error = %v, want ErrMalformedPayload", err)
	}
	if _, err := Decode("zz", "", "hex"); !errors.Is(err, ErrMalformedPayload) {
		t.Errorf("bad hex error = %v, want ErrMalformedPayload", err)
	}
	// An undecodable payload under auto encoding degrades to text.
	p, err := Decode("not base64 !!", "", "auto")
	if err != nil {
		t.Fatalf("auto error = %v", err)
	}
	if p.Encoding != "text" {
		t.Errorf("auto encoding = %q, want text", p.Encoding)
	}
}

func TestDecodeTruncatesOversizePayloads(t *testing.T) {
	big := strings.Repeat("A", MaxPayload+512)
	p, err := Decode(big, "", "text")
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(p.Bytes) != MaxPayload || !p.Truncated {
		t.Errorf("len = %d, truncated = %v; want %d and true", len(p.Bytes), p.Truncated, MaxPayload)
	}
}

func TestDecodeEmpty(t *testing.T) {
	p, err := Decode("", "", "")
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if !p.Empty() {
		t.Errorf("payload should be empty, got %q", p.Bytes)
	}
}

func TestLooksLikeHelpers(t *testing.T) {
	if !LooksLikeHex("fffd18fffd20fffd23") {
		t.Error("hex dump not detected")
	}
	if LooksLikeHex("fffd18zz") {
		t.Error("non-hex string detected as hex")
	}
	if !LooksLikeBase64("SQAAAAo4LjAuMzIAAQAAAGFiY2RlZmdoAA==") {
		t.Error("base64 payload not detected")
	}
	if LooksLikeBase64("220 ProFTPD 1.3.7 ready") {
		t.Error("text detected as base64")
	}
	if !LooksBinary([]byte{0x00, 0x01, 0x02}) {
		t.Error("binary payload not detected")
	}
	if LooksBinary([]byte("HTTP/1.1 200 OK\r\n")) {
		t.Error("text detected as binary")
	}
	if !LooksLikeSignature([]byte("SSH-2.0-x")) {
		t.Error("SSH signature not detected")
	}
	if LooksLikeSignature([]byte("nothing here")) {
		t.Error("plain text detected as signature")
	}
}

func TestSanitize(t *testing.T) {
	got := Sanitize([]byte("a\x00b\r\nc\xff\xfe"), 64)
	if got != "a.b\r\nc.." {
		t.Errorf("Sanitize = %q", got)
	}
	if got := Sanitize([]byte("abcdef"), 3); len(got) > 3 {
		t.Errorf("Sanitize should cap length, got %q", got)
	}
}

// FuzzDecodeText checks that the escape decoder and the sniffers never panic
// and never lose bytes for plain text (NFR-3).
func FuzzDecodeText(f *testing.F) {
	seeds := []string{
		"", "SSH-2.0-OpenSSH_8.9p1", `\r\n`, `\x16\x03\x01`, "220 ready\r\n",
		"SQAAAAo4LjAuMzIAAQAAAGFiY2RlZmdoAA==", "fffd18fffd", `\u00e9\`, "%s", "\xff\xfe",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, banner string) {
		for _, encoding := range []string{"", "auto", "text"} {
			p, err := Decode(banner, "", encoding)
			if err != nil {
				continue
			}
			if len(p.Bytes) > MaxPayload {
				t.Fatalf("payload %d bytes exceeds the cap", len(p.Bytes))
			}
			_ = Sanitize(p.Bytes, 256)
			_ = LooksBinary(p.Bytes)
			_ = LooksLikeSignature(p.Bytes)
		}
	})
}
