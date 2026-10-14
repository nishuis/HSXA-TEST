package rules

import (
	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// httpPorts are the ports whose prior points at HTTP. Port 443 is included on
// purpose: the acceptance contract reports plaintext HTTP served over TLS as
// protocol HTTP, never HTTPS.
var httpPorts = []int{80, 443, 8000, 8080, 8443, 8888}

// httpProductRules identify the most common HTTP servers from their Server and
// X-Powered-By headers. More specific products come first so that, for
// example, "Apache-Coyote" is reported as Tomcat rather than Apache.
func httpProductRules() []*rule.Rule {
	return []*rule.Rule{
		{
			Name: "http-server-apache-coyote", MatchType: rule.MatchRegex,
			Pattern: `(?i)server:\s*apache-coyote(?:/([0-9][\w.\-]*))?`,
			Product: "Tomcat", VersionGroup: 1, Weight: score.WeightProductStrong, Priority: 300,
		},
		{
			Name: "http-server-jetty", MatchType: rule.MatchRegex,
			Pattern: `(?i)server:\s*jetty\(?(\d+(?:\.\d+)+)?`,
			Product: "Jetty", VersionGroup: 1, Weight: score.WeightProductWeak, Priority: 290,
		},
		{
			Name: "http-server-nginx", MatchType: rule.MatchRegex,
			Pattern: `(?i)server:\s*nginx(?:/([0-9][\w.\-]*))?`,
			Product: "nginx", VersionGroup: 1, Weight: score.WeightProductStrong, Priority: 280,
		},
		{
			Name: "http-server-apache", MatchType: rule.MatchRegex,
			Pattern: `(?i)server:\s*apache(?:/([0-9][\w.\-]*))?(?:\s*\(([^)]*)\))?`,
			Product: "Apache", VersionGroup: 1, OSGroup: 2,
			Weight: score.WeightProductStrong, Priority: 270,
		},
		{
			Name: "http-server-iis", MatchType: rule.MatchRegex,
			Pattern: `(?i)server:\s*microsoft-iis(?:/([0-9][\w.\-]*))?`,
			Product: "IIS", VersionGroup: 1, OSHint: "Windows",
			Weight: score.WeightProductStrong, Priority: 260,
		},
		{
			Name: "http-server-openresty", MatchType: rule.MatchRegex,
			Pattern: `(?i)server:\s*openresty(?:/([0-9][\w.\-]*))?`,
			Product: "openresty", VersionGroup: 1, Weight: score.WeightProductStrong, Priority: 250,
		},
		{
			Name: "http-server-lighttpd", MatchType: rule.MatchRegex,
			Pattern: `(?i)server:\s*lighttpd(?:/([0-9][\w.\-]*))?`,
			Product: "lighttpd", VersionGroup: 1, Weight: score.WeightProductStrong, Priority: 240,
		},
		{
			Name: "http-server-gunicorn", MatchType: rule.MatchRegex,
			Pattern: `(?i)server:\s*gunicorn(?:/([0-9][\w.\-]*))?`,
			Product: "gunicorn", VersionGroup: 1, Weight: score.WeightProductStrong, Priority: 230,
		},
		{
			Name: "http-server-werkzeug", MatchType: rule.MatchRegex,
			Pattern: `(?i)server:\s*werkzeug(?:/([0-9][\w.\-]*))?`,
			Product: "Werkzeug", VersionGroup: 1, Weight: score.WeightProductStrong, Priority: 220,
		},
		{
			Name: "http-server-uvicorn", MatchType: rule.MatchRegex,
			Pattern: `(?i)server:\s*uvicorn`,
			Product: "uvicorn", Weight: score.WeightProductWeak, Priority: 210,
		},
		{
			Name: "http-server-envoy", MatchType: rule.MatchRegex,
			Pattern: `(?i)server:\s*envoy`,
			Product: "Envoy", Weight: score.WeightProductWeak, Priority: 200,
		},
		{
			Name: "http-server-cloudflare", MatchType: rule.MatchRegex,
			Pattern: `(?i)server:\s*cloudflare`,
			Product: "Cloudflare", Weight: score.WeightProductWeak, Priority: 190,
		},
		{
			Name: "http-powered-by-php", MatchType: rule.MatchRegex,
			Pattern: `(?i)x-powered-by:\s*php(?:/([0-9][\w.\-]*))?`,
			Product: "PHP", VersionGroup: 1, Weight: score.WeightProductWeak, Priority: 120,
		},
		{
			Name: "http-powered-by-express", MatchType: rule.MatchRegex,
			Pattern: `(?i)x-powered-by:\s*express`,
			Product: "Express", Weight: score.WeightProductWeak, Priority: 110,
		},
		{
			Name: "http-aspnet-version", MatchType: rule.MatchRegex,
			Pattern: `(?i)x-aspnet-version:\s*([0-9][\w.\-]*)`,
			Product: "ASP.NET", VersionGroup: 1, OSHint: "Windows",
			Weight: score.WeightProductWeak, Priority: 100,
		},
		{
			Name: "http-server-openssl-hint", MatchType: rule.MatchRegex,
			Pattern: `(?i)server:\s*.*\(([^)]*(?:ubuntu|debian|centos|red hat|fedora|windows|freebsd)[^)]*)\)`,
			OSGroup: 1, Weight: score.WeightProductWeak, Priority: 90,
		},
	}
}

func httpSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolHTTP,
		Ports:    httpPorts,
		ProtoRules: []*rule.Rule{
			{
				Name: "http-status-line", MatchType: rule.MatchRegex,
				Pattern: `(?s)^HTTP/1\.[01] \d{3}`, Weight: score.WeightProtoSignature, Priority: 100,
			},
			{
				Name: "http-status-line-inline", MatchType: rule.MatchRegex,
				Pattern: `(?s)HTTP/1\.[01] \d{3}`, Weight: score.WeightProtoWeak, Priority: 60,
			},
			{
				Name: "http-request-line", MatchType: rule.MatchRegex,
				Pattern: `(?s)^(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|TRACE|CONNECT) \S+ HTTP/1\.[01]`,
				Weight:  score.WeightProtoWeak, Priority: 50,
			},
			{
				Name: "http2-preface", MatchType: rule.MatchContains,
				Pattern: "PRI * HTTP/2.0", Weight: score.WeightProtoSignature, Priority: 40,
			},
		},
		ProductRules: httpProductRules(),
	}
}
