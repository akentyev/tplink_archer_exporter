package exporter

import (
	"fmt"
	"maps"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// What the linker can leave behind has to be normalized before it is a label:
// version="" in the exposition reads as a build that answered.

const (
	buildInfoName = "tplink_exporter_build_info"
	buildInfoHelp = "The build this exporter is running; the value is always 1."
)

// testBuild is what the collectors in these tests report, collector_test.go's
// goldens included.
var testBuild = BuildInfo{Version: "2026.8.0", Revision: "1a2b3c4"}

// buildInfoGolden is the exposition the metric must produce for a version and a
// revision. go_version is read off the toolchain rather than written into a
// literal because it is the one label no caller can set.
func buildInfoGolden(version, revision string) string {
	return fmt.Sprintf("# HELP %[1]s %[2]s\n# TYPE %[1]s gauge\n%[1]s{go_version=%[3]q,revision=%[4]q,version=%[5]q} 1\n",
		buildInfoName, buildInfoHelp, runtime.Version(), revision, version)
}

// gathererWithBuild registers a collector reporting b on a pedantic registry,
// which holds Collect to what Describe announced and refuses two series that
// share a name and a label set.
func gathererWithBuild(t *testing.T, st State, maxAge time.Duration, b BuildInfo) prometheus.Gatherer {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(NewCollector(&stubSource{st: st}, maxAge, b)); err != nil {
		t.Fatalf("a registry refused the collector: %v", err)
	}
	return reg
}

// buildSeries is one series of the build metric.
type buildSeries struct {
	labels map[string]string
	value  float64
}

// buildInfoSeries reads the build metric out of a scrape with no golden to
// compare against, so a test can state what must not be there: an empty label
// value, a second series.
func buildInfoSeries(t *testing.T, g prometheus.Gatherer) []buildSeries {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatalf("gathering failed: %v", err)
	}
	var out []buildSeries
	for _, mf := range mfs {
		if mf.GetName() != buildInfoName {
			continue
		}
		if typ := mf.GetType().String(); typ != "GAUGE" {
			t.Errorf("%s is published as a %s; it is a constant 1 and nothing about it resets", buildInfoName, typ)
		}
		for _, m := range mf.GetMetric() {
			s := buildSeries{labels: map[string]string{}, value: m.GetGauge().GetValue()}
			for _, lp := range m.GetLabel() {
				s.labels[lp.GetName()] = lp.GetValue()
			}
			out = append(out, s)
		}
	}
	return out
}

// theBuildSeries holds the metric to the single series it is and returns it.
func theBuildSeries(t *testing.T, g prometheus.Gatherer) buildSeries {
	t.Helper()
	got := buildInfoSeries(t, g)
	if len(got) != 1 {
		t.Fatalf("a scrape carried %d %s series, want 1: one process runs one build", len(got), buildInfoName)
	}
	return got[0]
}

// seriesCount is how many series of one metric a scrape carries.
func seriesCount(t *testing.T, g prometheus.Gatherer, name string) int {
	t.Helper()
	n, err := testutil.GatherAndCount(g, name)
	if err != nil {
		t.Fatalf("gathering %s failed: %v", name, err)
	}
	return n
}

// What the linker can leave behind, and what each of those has to become before
// it is a label.
func TestNewBuildInfoNormalizesWhatTheLinkerLeft(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		version, revision         string
		wantVersion, wantRevision string
	}{
		{
			name:    "-X carried both values",
			version: "2026.8.0", revision: "1a2b3c4",
			wantVersion: "2026.8.0", wantRevision: "1a2b3c4",
		},
		{
			name:    "no -X at all",
			version: "", revision: "",
			wantVersion: "dev", wantRevision: "unknown",
		},
		{
			name:    "a trailing newline on the version and spaces for a revision",
			version: " 2026.8.0\n", revision: "  ",
			wantVersion: "2026.8.0", wantRevision: "unknown",
		},
		{
			// ToValidUTF8 leaves one replacement rune behind, which is no more
			// of a version than an empty string is.
			name:    "nothing but invalid bytes",
			version: "\xff\xfe", revision: "\xc0",
			wantVersion: "dev", wantRevision: "unknown",
		},
		{
			name:    "--build-arg REVISION= with nothing after it",
			version: "2026.8.0", revision: "",
			wantVersion: "2026.8.0", wantRevision: "unknown",
		},
		{
			name:    "--build-arg VERSION= with nothing after it",
			version: "", revision: "1a2b3c4",
			wantVersion: "dev", wantRevision: "1a2b3c4",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := NewBuildInfo(tc.version, tc.revision)

			if got.Version != tc.wantVersion {
				t.Errorf("NewBuildInfo(%q, %q).Version = %q, want %q",
					tc.version, tc.revision, got.Version, tc.wantVersion)
			}
			if got.Revision != tc.wantRevision {
				t.Errorf("NewBuildInfo(%q, %q).Revision = %q, want %q",
					tc.version, tc.revision, got.Revision, tc.wantRevision)
			}
			if got.GoVersion != runtime.Version() {
				t.Errorf("NewBuildInfo(%q, %q).GoVersion = %q, want %q: the toolchain knows the runtime, "+
					"the caller does not", tc.version, tc.revision, got.GoVersion, runtime.Version())
			}
			// NewCollector normalizes again over what NewBuildInfo produced.
			if again := got.normalized(); again != got {
				t.Errorf("normalized() turned an already normalized %+v into %+v", got, again)
			}
		})
	}
}

// The case the whole step exists for: an empty label value is a series that says
// nothing while looking like a reading.
func TestEmptyLinkerValuesNeverBecomeEmptyLabels(t *testing.T) {
	got := NewBuildInfo("", "")
	if got.Version == "" || got.Revision == "" || got.GoVersion == "" {
		t.Fatalf(`NewBuildInfo("", "") = %+v; an empty field is an empty label value`, got)
	}
	if got.Version != "dev" || got.Revision != "unknown" {
		t.Errorf(`NewBuildInfo("", "") = %+v, want dev and unknown`, got)
	}

	s := theBuildSeries(t, gathererWithBuild(t, fullState(), 0, got))
	for name, value := range s.labels {
		if value == "" {
			t.Errorf(`%s carries %s=""; nothing empty may reach a label`, buildInfoName, name)
		}
	}
	want := map[string]string{"version": "dev", "revision": "unknown", "go_version": runtime.Version()}
	if !maps.Equal(s.labels, want) {
		t.Errorf("%s carries %v, want %v", buildInfoName, s.labels, want)
	}
}

// go_version is not the caller's to set: a BuildInfo carrying one is a claim
// about a runtime, and the toolchain that built the binary is what knows it.
func TestGoVersionIsTheToolchainsWhateverTheCallerSet(t *testing.T) {
	b := BuildInfo{Version: "2026.8.0", Revision: "1a2b3c4", GoVersion: "go0.0.0"}

	if got := b.normalized().GoVersion; got != runtime.Version() {
		t.Errorf("normalized() kept GoVersion %q, want %q", got, runtime.Version())
	}
	if got := theBuildSeries(t, gathererWithBuild(t, fullState(), 0, b)).labels["go_version"]; got != runtime.Version() {
		t.Errorf("go_version=%q, want %q: the collector normalizes what it is handed", got, runtime.Version())
	}
}

// Name, help, type, labels and value together.
func TestBuildInfoExposition(t *testing.T) {
	g := gathererWithBuild(t, fullState(), 0, testBuild)

	want := buildInfoGolden(testBuild.Version, testBuild.Revision)
	if err := testutil.GatherAndCompare(g, strings.NewReader(want), buildInfoName); err != nil {
		t.Errorf("the build metric is not what the descriptor promises:\n%v", err)
	}
	if got := theBuildSeries(t, g).value; got != 1 {
		t.Errorf("%s = %v, want 1: the labels carry the build and the value carries nothing", buildInfoName, got)
	}
}

// The build outlives what the snapshot does not: which exporter is running is an
// answer that cannot go stale, and it is the answer wanted most when the router
// metrics are gone.
func TestBuildInfoIsServedWhateverTheSnapshot(t *testing.T) {
	stale := fullState()
	stale.Snapshot.TakenAt = time.Now().Add(-time.Hour).Truncate(time.Second)

	for _, tc := range []struct {
		name         string
		st           State
		maxAge       time.Duration
		beside, gone []string
	}{
		{
			name:   "before the first cycle",
			st:     State{EndpointErrors: map[string]uint64{}},
			maxAge: 5 * time.Minute,
			beside: []string{"tplink_up"},
			gone:   []string{"tplink_snapshot_timestamp_seconds", "tplink_firmware_info", "tplink_client_info"},
		},
		{
			name:   "an hour-old snapshot against a five-minute maxAge",
			st:     stale,
			maxAge: 5 * time.Minute,
			beside: []string{"tplink_up", "tplink_snapshot_timestamp_seconds"},
			gone:   []string{"tplink_firmware_info", "tplink_client_info"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gathererWithBuild(t, tc.st, tc.maxAge, testBuild)

			want := buildInfoGolden(testBuild.Version, testBuild.Revision)
			if err := testutil.GatherAndCompare(g, strings.NewReader(want), buildInfoName); err != nil {
				t.Errorf("%s: the build is not served:\n%v", tc.name, err)
			}
			for _, name := range tc.beside {
				if seriesCount(t, g, name) == 0 {
					t.Errorf("%s: %s is missing, and the build is published beside it", tc.name, name)
				}
			}
			for _, name := range tc.gone {
				if n := seriesCount(t, g, name); n != 0 {
					t.Errorf("%s: %s carried %d series; the readings stop here and the build does not",
						tc.name, name, n)
				}
			}
		})
	}
}

// A zero BuildInfo is what a caller that has no build to report passes, and the
// labels still have to say something.
func TestZeroBuildInfoIsNormalizedByTheCollector(t *testing.T) {
	g := gathererWithBuild(t, fullState(), 0, BuildInfo{})

	want := buildInfoGolden("dev", "unknown")
	if err := testutil.GatherAndCompare(g, strings.NewReader(want), buildInfoName); err != nil {
		t.Errorf("a zero BuildInfo did not reach the labels as dev and unknown:\n%v", err)
	}
	for name, value := range theBuildSeries(t, g).labels {
		if value == "" {
			t.Errorf(`%s carries %s=""; a zero BuildInfo cannot reach the labels`, buildInfoName, name)
		}
	}
}

// One build is one series for the life of the process. A label rebuilt per
// scrape would churn, and a series that churns is one nothing can join on.
func TestBuildInfoIsTheSameSeriesEveryScrape(t *testing.T) {
	g := gathererWithBuild(t, fullState(), 0, testBuild)

	first := theBuildSeries(t, g)
	second := theBuildSeries(t, g)
	if !maps.Equal(first.labels, second.labels) {
		t.Errorf("the second scrape carried %v against the first one's %v", second.labels, first.labels)
	}
	if first.value != 1 || second.value != 1 {
		t.Errorf("the build metric read %v then %v, want 1 both times", first.value, second.value)
	}
}

// String is what -version prints and what the landing page shows. It normalizes
// for the same reason the collector does: main funnels every build through
// NewBuildInfo, but nothing in the type stops another caller from holding a zero
// value, and a line of gaps reads as a build that answered.
func TestStringNamesABuildFromAZeroValue(t *testing.T) {
	got := BuildInfo{}.String()

	if want := "dev (revision unknown, " + runtime.Version() + ")"; got != want {
		t.Errorf("BuildInfo{}.String() = %q, want %q", got, want)
	}
	for _, gap := range []string{"  ", "(revision ,", ", )"} {
		if strings.Contains(got, gap) {
			t.Errorf("BuildInfo{}.String() = %q, which carries an empty value at %q", got, gap)
		}
	}
}

// A build argument is the only label value that can arrive as invalid UTF-8;
// orDefault is what keeps it out of the scrape.
func TestInvalidUTF8InABuildArgumentCannotEmptyTheScrape(t *testing.T) {
	g := gathererWithBuild(t, fullState(), 0, BuildInfo{Version: "2026.8.0\xff", Revision: "\xff\xfe"})

	for name, value := range theBuildSeries(t, g).labels {
		if !utf8.ValidString(value) {
			t.Errorf("%s carries %s=%q, which is not valid UTF-8", buildInfoName, name, value)
		}
	}
	if n := seriesCount(t, g, "tplink_firmware_info"); n == 0 {
		t.Error("the router metrics are gone from the scrape: a build argument took them with it")
	}
}
