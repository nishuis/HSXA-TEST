// Package model defines the domain types shared by the engine, the REST API
// and the CLI, together with the frozen JSON contract of an identification
// result (plan.md §1.2).
package model

// Protocol names used by Result.Protocol.
const (
	ProtocolUnknown       = "unknown"
	ProtocolSSH           = "SSH"
	ProtocolFTP           = "FTP"
	ProtocolSMTP          = "SMTP"
	ProtocolPOP3          = "POP3"
	ProtocolIMAP          = "IMAP"
	ProtocolTelnet        = "Telnet"
	ProtocolRedis         = "Redis"
	ProtocolHTTP          = "HTTP"
	ProtocolElasticsearch = "Elasticsearch"
	ProtocolDockerAPI     = "Docker API"
	ProtocolMySQL         = "MySQL"
	ProtocolPostgreSQL    = "PostgreSQL"
	ProtocolMongoDB       = "MongoDB"
	ProtocolSMB           = "SMB"
	ProtocolVNC           = "VNC"
	ProtocolRDP           = "RDP"
	ProtocolMemcached     = "Memcached"
	ProtocolAMQP          = "AMQP"
	ProtocolLDAP          = "LDAP"
)

// Banner encodings accepted in ScanRecord.Encoding.
const (
	EncodingAuto   = "auto"
	EncodingText   = "text"
	EncodingBase64 = "base64"
	EncodingHex    = "hex"
)

// Encodings lists every accepted encoding name.
func Encodings() []string {
	return []string{EncodingAuto, EncodingText, EncodingBase64, EncodingHex}
}

// ScanRecord is one raw observation to identify.
type ScanRecord struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
	// Banner is the payload as text; backslash escapes such as \r\n are
	// expanded when the resolved encoding is text or auto.
	Banner string `json:"banner,omitempty"`
	// BannerBase64 carries binary payloads and wins over Banner when set.
	BannerBase64 string `json:"banner_base64,omitempty"`
	// Encoding is one of auto, text, base64, hex; empty means auto.
	Encoding string `json:"encoding,omitempty"`
}

// Result is the identification outcome of one record.
//
// The field set, field order, field types and empty-value representation are a
// frozen acceptance contract: product, version and os_hint are the empty
// string when unknown, never null.
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// Evidence lists the rules behind one identification. It is only serialised
// when a caller explicitly asks for it.
type Evidence struct {
	ProtocolRule string `json:"protocol_rule,omitempty"`
	ProductRule  string `json:"product_rule,omitempty"`
	Encoding     string `json:"encoding,omitempty"`
	PortPrior    string `json:"port_prior,omitempty"`
	TLSOnly      bool   `json:"tls_only,omitempty"`
}

// ResultWithEvidence is a Result plus its evidence, used by include_evidence
// responses. The embedded Result keeps the frozen field order.
type ResultWithEvidence struct {
	Result
	Evidence *Evidence `json:"evidence,omitempty"`
}

// Unknown returns the degraded result for a record with no usable signal
// (FR-8). Product, version and os_hint stay empty strings.
func Unknown(ip string, port int) Result {
	return Result{IP: ip, Port: port, Protocol: ProtocolUnknown}
}

// Request is the POST /api/v1/identify request body.
type Request struct {
	Records []ScanRecord `json:"records"`
	Options *Options     `json:"options,omitempty"`
}

// Options tunes the response detail of a request.
type Options struct {
	// IncludeEvidence adds the matched rule names to every result.
	IncludeEvidence bool `json:"include_evidence,omitempty"`
}

// Response is the envelope returned by POST /api/v1/identify.
type Response struct {
	Results []Result `json:"results"`
	Stats   Stats    `json:"stats"`
}

// Stats summarises one batch.
type Stats struct {
	Total      int   `json:"total"`
	Identified int   `json:"identified"`
	Unknown    int   `json:"unknown"`
	ElapsedMS  int64 `json:"elapsed_ms"`
}

// StatsOf summarises results. Unknown counts records with no protocol signal
// at all; Identified counts records that carry a product name.
func StatsOf(results []Result, elapsedMS int64) Stats {
	s := Stats{Total: len(results), ElapsedMS: elapsedMS}
	for _, r := range results {
		switch {
		case r.Protocol == "" || r.Protocol == ProtocolUnknown:
			s.Unknown++
		case r.Product != "":
			s.Identified++
		}
	}
	return s
}

// APIError locates one request problem: Index is the record position, or -1
// for a problem with the request as a whole.
type APIError struct {
	Index   int    `json:"index"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// ErrorResponse is the 4xx/5xx envelope of the REST API.
type ErrorResponse struct {
	Errors []APIError `json:"errors"`
}

// Meta is the GET /api/v1/meta payload.
type Meta struct {
	Version    string   `json:"version"`
	Protocols  []string `json:"protocols"`
	RuleCount  int      `json:"rule_count"`
	UptimeSecs int64    `json:"uptime_seconds"`
}
