// Package decode normalises the raw payload of a scan record into bytes.
//
// It performs no IO, keeps no mutable state and never panics, so it is safe
// for concurrent use. Escaped text, Base64 and Hex inputs all funnel into the
// same normalised byte slice that the rest of the engine matches against.
package decode

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxPayload caps the number of bytes one record may carry; longer payloads
// are truncated and flagged.
const MaxPayload = 64 << 10

// Sentinel errors returned by Decode.
var (
	// ErrUnsupportedEncoding reports an encoding name outside the supported set.
	ErrUnsupportedEncoding = errors.New("unsupported banner encoding")
	// ErrMalformedPayload reports a payload that the requested encoding cannot
	// decode.
	ErrMalformedPayload = errors.New("malformed banner payload")
)

// Payload is the normalised representation of one record's banner.
type Payload struct {
	// Bytes holds the normalised payload.
	Bytes []byte
	// Encoding is the encoding that was actually used: text, base64, hex or
	// empty for a record with no payload at all.
	Encoding string
	// Binary reports that the payload looks like a binary handshake rather
	// than printable text.
	Binary bool
	// Truncated reports that the payload was longer than MaxPayload.
	Truncated bool
}

// Empty reports whether the payload carries no bytes.
func (p Payload) Empty() bool { return len(p.Bytes) == 0 }

// Decode turns the banner fields of a scan record into a Payload.
//
// bannerBase64 wins over banner when both are set. encoding selects the
// strategy and defaults to auto, which sniffs Hex, then Base64, then escaped
// plain text.
func Decode(banner, bannerBase64, encoding string) (Payload, error) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	if enc == "" {
		enc = "auto"
	}
	switch enc {
	case "auto":
		return autoDecode(banner, bannerBase64)
	case "text":
		return newPayload(Unescape(banner), "text")
	case "base64":
		raw := strings.TrimSpace(banner)
		if raw == "" {
			raw = strings.TrimSpace(bannerBase64)
		}
		b, err := decodeBase64(raw)
		if err != nil {
			return Payload{}, fmt.Errorf("%w: %w", ErrMalformedPayload, err)
		}
		return newPayload(b, "base64")
	case "hex":
		raw := strings.TrimSpace(banner)
		if raw == "" {
			raw = strings.TrimSpace(bannerBase64)
		}
		b, err := decodeHex(raw)
		if err != nil {
			return Payload{}, fmt.Errorf("%w: %w", ErrMalformedPayload, err)
		}
		return newPayload(b, "hex")
	default:
		return Payload{}, fmt.Errorf("%w: %q", ErrUnsupportedEncoding, encoding)
	}
}

// autoDecode sniffs the encoding of an untagged payload. Sniffing only fires
// when the decoded bytes actually look like a protocol payload or like binary
// data, so ordinary text banners are never mangled.
func autoDecode(banner, bannerBase64 string) (Payload, error) {
	if b64 := strings.TrimSpace(bannerBase64); b64 != "" {
		b, err := decodeBase64(b64)
		if err != nil {
			return Payload{}, fmt.Errorf("%w: %w", ErrMalformedPayload, err)
		}
		return newPayload(b, "base64")
	}
	s := banner
	if s == "" {
		return newPayload(nil, "text")
	}
	if LooksLikeHex(s) {
		if b, err := decodeHex(s); err == nil && (LooksLikeSignature(b) || mostlyUnprintable(b)) {
			return newPayload(b, "hex")
		}
	}
	if LooksLikeBase64(s) {
		if b, err := decodeBase64(s); err == nil && (LooksLikeSignature(b) || mostlyUnprintable(b)) {
			return newPayload(b, "base64")
		}
	}
	return newPayload(Unescape(s), "text")
}

func newPayload(b []byte, enc string) (Payload, error) {
	p := Payload{Encoding: enc, Bytes: b}
	if len(b) > MaxPayload {
		p.Bytes = b[:MaxPayload]
		p.Truncated = true
	}
	p.Binary = LooksBinary(p.Bytes)
	return p, nil
}

// Unescape expands the backslash escapes found in scan tool output
// (\r \n \t \0 \a \b \f \v \\ \" \' \xHH \uHHHH) into raw bytes. Unknown
// escapes are kept verbatim.
func Unescape(s string) []byte {
	if !strings.ContainsRune(s, '\\') {
		return []byte(s)
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			out = append(out, c)
			continue
		}
		switch s[i+1] {
		case 'r':
			out = append(out, '\r')
			i++
		case 'n':
			out = append(out, '\n')
			i++
		case 't':
			out = append(out, '\t')
			i++
		case '0':
			out = append(out, 0x00)
			i++
		case 'a':
			out = append(out, 0x07)
			i++
		case 'b':
			out = append(out, 0x08)
			i++
		case 'f':
			out = append(out, 0x0c)
			i++
		case 'v':
			out = append(out, 0x0b)
			i++
		case '\\':
			out = append(out, '\\')
			i++
		case '"':
			out = append(out, '"')
			i++
		case '\'':
			out = append(out, '\'')
			i++
		case 'x', 'X':
			if i+3 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					out = append(out, byte(v))
					i += 3
					continue
				}
			}
			out = append(out, c)
		case 'u':
			if i+5 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil {
					r := rune(v)
					if utf8.ValidRune(r) {
						out = utf8.AppendRune(out, r)
						i += 5
						continue
					}
				}
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

// Sanitize renders a payload as a printable string for logs and for evidence
// blocks: control bytes and invalid UTF-8 become '.'. The result is at most
// max bytes long.
func Sanitize(b []byte, max int) string {
	var sb strings.Builder
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size <= 1 {
			sb.WriteByte('.')
			i++
		} else {
			if r < 0x20 && r != '\r' && r != '\n' && r != '\t' || r == 0x7f {
				sb.WriteByte('.')
			} else {
				sb.WriteRune(r)
			}
			i += size
		}
		if sb.Len() >= max {
			break
		}
	}
	s := sb.String()
	if len(s) > max {
		return s[:max]
	}
	return s
}

// LooksLikeHex reports whether s is plausibly a hex dump rather than text.
func LooksLikeHex(s string) bool {
	if len(s) < 16 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// LooksLikeBase64 reports whether s is plausibly a Base64 blob rather than
// text: long, no whitespace, standard alphabet, padded only at the end.
func LooksLikeBase64(s string) bool {
	if len(s) < 16 || len(s)%4 != 0 || strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	pad := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			if pad > 0 {
				return false
			}
		case c == '=':
			pad++
		default:
			return false
		}
	}
	return pad <= 2
}

// LooksBinary reports whether a payload looks like a binary handshake: it
// contains NUL bytes or a large share of control bytes.
func LooksBinary(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return true
	}
	bad := 0
	for _, c := range b {
		if c == '\r' || c == '\n' || c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			bad++
		}
	}
	return bad*100/len(b) > 15
}

// signatureProbes are byte prefixes and substrings that only occur in
// protocol payloads; they gate the auto encoding sniffers.
var signatureProbes = [][]byte{
	[]byte("SSH-"), []byte("HTTP/"), []byte("GET /"), []byte("POST /"),
	[]byte("+OK"), []byte("-ERR"), []byte("-NOAUTH"), []byte("+PONG"),
	[]byte("* OK"), []byte("* PREAUTH"), []byte("220 "), []byte("RFB "),
	[]byte("\xffSMB"), []byte("\xfeSMB"), []byte("\x16\x03"), []byte("AMQP"),
	[]byte("\xff\xfd"), []byte("\xff\xfb"), []byte("\xff\xfa"), []byte("\xff\xf0"),
	[]byte("mysql_native_password"), []byte("caching_sha2_password"),
	[]byte("server_version"), []byte("isMaster"), []byte("buildInfo"),
	[]byte("ERROR\r\n"), []byte("CLIENT_ERROR"), []byte("SERVER_ERROR"),
	[]byte("VERSION "), []byte("NTLMSSP"), []byte("\x03\x00\x00"),
}

// LooksLikeSignature reports whether a payload starts with or contains one of
// the well-known protocol signatures.
func LooksLikeSignature(b []byte) bool {
	for _, probe := range signatureProbes {
		if bytes.Contains(b, probe) {
			return true
		}
	}
	return false
}

func mostlyUnprintable(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	bad := 0
	for _, c := range b {
		if c < 0x20 && c != '\r' && c != '\n' && c != '\t' || c == 0x7f {
			bad++
		}
	}
	return bad*100/len(b) > 30
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("invalid base64 payload")
}

func decodeHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if s == "" {
		return nil, nil
	}
	s = hexReplacer.Replace(s)
	if len(s)%2 != 0 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid hex payload")
	}
	return b, nil
}

var hexReplacer = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "")

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
