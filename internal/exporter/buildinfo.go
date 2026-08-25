package exporter

import (
	"fmt"
	"runtime"
	"strings"
)

// BuildInfo identifies the running build. Version and Revision arrive from -X at
// link time; an -X carrying an empty value writes that empty string over the
// default the Go code declares.
type BuildInfo struct {
	Version   string
	Revision  string
	GoVersion string
}

// NewBuildInfo returns what the linker left behind, with the blanks filled.
func NewBuildInfo(version, revision string) BuildInfo {
	return BuildInfo{Version: version, Revision: revision}.normalized()
}

// String renders the build for a person to read. It normalizes, so a caller
// holding a zero BuildInfo prints a build rather than a line of gaps.
func (b BuildInfo) String() string {
	b = b.normalized()
	return fmt.Sprintf("%s (revision %s, %s)", b.Version, b.Revision, b.GoVersion)
}

// normalized fills the blanks. GoVersion is always the runtime's, whatever the
// caller set: the toolchain knows it and the caller does not.
func (b BuildInfo) normalized() BuildInfo {
	b.Version = orDefault(b.Version, "dev")
	b.Revision = orDefault(b.Revision, "unknown")
	b.GoVersion = runtime.Version()
	return b
}

// orDefault is def when nothing usable is left of s. Invalid UTF-8 goes first:
// prometheus panics on a label value carrying it, the registry catches that and
// serves a scrape with every metric of this collector missing, and these two are
// the only labels the exporter does not take from a JSON reply, where the decoder
// substitutes U+FFFD on the way in. The substitute is then trimmed like any
// other padding: a label reading "�" says as little as an empty one.
func orDefault(s, def string) string {
	if s = strings.Trim(strings.ToValidUTF8(s, "�"), " \t\r\n\v\f�"); s != "" {
		return s
	}
	return def
}
