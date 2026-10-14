// Package version carries the build metadata of the bfp toolchain. The values
// are overridden at link time with -ldflags -X.
package version

// Build metadata. Injected by the Makefile and the Dockerfiles via:
//
//	-ldflags "-X hsxa-banner-fingerprint/internal/version.Name=..."
var (
	// Version is the semantic version of the build.
	Version = "0.1.0-dev"
	// GitCommit is the abbreviated commit the build came from.
	GitCommit = "unknown"
	// BuildDate is the UTC build timestamp.
	BuildDate = "unknown"
)

// String renders a single-line build identifier.
func String() string {
	return Version + " (" + GitCommit + ", " + BuildDate + ")"
}
