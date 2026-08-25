package main

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/akentyev/tplink_archer_exporter/internal/exporter"
)

// Nothing inside the package can tell what the linker wrote, so the cases below
// build a binary and ask it.

// versionLine is what -version prints, from the contract:
//
//	tplink_exporter 2026.8.0 (revision 1a2b3c4, go1.26.6)
//
// The child is built by the go on PATH, which is normally the toolchain that
// built this test, and then runtime.Version() matches. A test binary compiled by
// one toolchain and run under another would not match.
func versionLine(version, revision string) string {
	return fmt.Sprintf("tplink_exporter %s (revision %s, %s)\n", version, revision, runtime.Version())
}

// buildExporter links the binary with the version and revision given. An empty
// pair is passed as -X main.version= with nothing after it, which is what an
// empty --build-arg produces.
func buildExporter(t *testing.T, version, revision string) string {
	t.Helper()
	return goBuild(t, "-ldflags", fmt.Sprintf("-X main.version=%s -X main.revision=%s", version, revision))
}

// goBuild compiles the package under test. go test runs in the package
// directory, so "." is the exporter itself.
func goBuild(t *testing.T, args ...string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tplink_exporter")
	args = append(append([]string{"build"}, args...), "-o", bin, ".")
	cmd := exec.Command("go", args...)
	// The binary is built to be run here, so a GOOS or GOARCH exported in the
	// developer's shell must not reach it: cross-building would leave the run
	// below reporting a format error and nothing about the cause.
	cmd.Env = append(os.Environ(), "GOOS=", "GOARCH=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return bin
}

// runVersion runs the binary with -version and nothing else, and returns what
// each stream carried; a non-zero exit fails the test. Every TPLINK_ variable is
// dropped from the child's environment, so the developer's own shell cannot
// decide the result; extra puts back what a case wants there. extra goes last
// because os/exec keeps the last of two entries naming the same variable.
func runVersion(t *testing.T, bin string, extra ...string) (stdout, stderr string) {
	t.Helper()
	env := append(cleanEnv(), extra...)

	cmd := exec.Command(bin, "-version")
	cmd.Env = env
	var out, errs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errs

	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		t.Fatalf("-version exited with %d, want 0\nstdout: %q\nstderr: %q",
			exit.ExitCode(), out.String(), errs.String())
	}
	if err != nil {
		t.Fatalf("running %s -version: %v", bin, err)
	}
	return out.String(), errs.String()
}

// cleanEnv is the environment with every TPLINK_ variable taken out.
func cleanEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if key, _, _ := strings.Cut(kv, "="); !strings.HasPrefix(key, "TPLINK_") {
			env = append(env, kv)
		}
	}
	return env
}

// The seam with values in it: they reach the binary, they reach stdout, and
// nothing else is written anywhere.
func TestVersionFlagPrintsTheLinkedBuild(t *testing.T) {
	bin := buildExporter(t, "t2026.8.0", "deadbee")
	want := versionLine("t2026.8.0", "deadbee")

	t.Run("stdout carries what the linker wrote", func(t *testing.T) {
		stdout, stderr := runVersion(t, bin)
		if stdout != want {
			t.Errorf("-version printed %q, want %q", stdout, want)
		}
		if stderr != "" {
			t.Errorf("-version wrote %q to stderr; the answer goes to stdout, where a shell reads it", stderr)
		}
	})

	// The version is answered before the environment is parsed: what is fatal to
	// a poll is nothing to a question.
	t.Run("a broken TPLINK_INTERVAL does not reach it", func(t *testing.T) {
		stdout, stderr := runVersion(t, bin, "TPLINK_INTERVAL=abc")
		if stdout != want {
			t.Errorf("TPLINK_INTERVAL=abc left -version printing %q, want %q", stdout, want)
		}
		if stderr != "" {
			t.Errorf("TPLINK_INTERVAL=abc made -version write %q to stderr and it must exit before "+
				"the environment is read at all", stderr)
		}
	})
}

// An empty --build-arg reaches the linker as -X main.version=; the binary must
// still name a build.
func TestVersionFlagWithEmptyLinkerValues(t *testing.T) {
	bin := buildExporter(t, "", "")

	stdout, stderr := runVersion(t, bin)
	if want := versionLine("dev", "unknown"); stdout != want {
		t.Errorf("an empty -X printed %q, want %q", stdout, want)
	}
	// What an empty value renders as, if one gets through.
	for _, gap := range []string{"tplink_exporter  (", "(revision ,"} {
		if strings.Contains(stdout, gap) {
			t.Errorf("-version printed %q, which carries an empty value at %q", stdout, gap)
		}
	}
	if stderr != "" {
		t.Errorf("-version wrote %q to stderr", stderr)
	}
}

// -version is answered before -host is required and before the password is read,
// so a container can be asked what it is without being configured. Built plainly:
// no -X at all is what go build and go run leave behind.
func TestVersionFlagNeedsNoHostOrPassword(t *testing.T) {
	bin := goBuild(t)

	stdout, stderr := runVersion(t, bin)
	if want := versionLine("dev", "unknown"); stdout != want {
		t.Errorf("a build with no -X printed %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("-version wrote %q to stderr; with no -host the exporter's own error goes there, and "+
			"the exit code goes with it", stderr)
	}
}

// buildInfo is what the program reads those two variables through.
func TestBuildInfoReadsThePackageVariables(t *testing.T) {
	if version != "dev" || revision != "unknown" {
		t.Errorf("the package variables start at %q and %q, want dev and unknown: go run and a plain "+
			"go build leave them as they are", version, revision)
	}

	was, wasRevision := version, revision
	t.Cleanup(func() { version, revision = was, wasRevision })

	for _, tc := range []struct {
		name                                         string
		version, revision, wantVersion, wantRevision string
	}{
		{
			name: "a linked build", version: "2026.8.0", revision: "1a2b3c4",
			wantVersion: "2026.8.0", wantRevision: "1a2b3c4",
		},
		{
			name:    "a version that needs trimming and a revision that was never set",
			version: " 2026.8.0\n", revision: "",
			wantVersion: "2026.8.0", wantRevision: "unknown",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			version, revision = tc.version, tc.revision

			got := buildInfo()
			if got.Version != tc.wantVersion {
				t.Errorf("version = %q left buildInfo().Version at %q, want %q", tc.version, got.Version, tc.wantVersion)
			}
			if got.Revision != tc.wantRevision {
				t.Errorf("revision = %q left buildInfo().Revision at %q, want %q", tc.revision, got.Revision, tc.wantRevision)
			}
			if got.GoVersion != runtime.Version() {
				t.Errorf("buildInfo().GoVersion = %q, want %q", got.GoVersion, runtime.Version())
			}
		})
	}
}

// -version is declared in bindFlags with the rest, and it is the one flag with no
// environment variable behind it.
func TestVersionFlagIsDeclaredWithNoEnvironmentVariable(t *testing.T) {
	var row flagSpec
	for _, spec := range flagTable {
		if spec.flag == "version" {
			row = spec
		}
	}
	if row.flag == "" {
		t.Fatal("no -version row in flagTable; README's Configuration table documents the flag")
	}
	if row.env != "" {
		t.Errorf("the -version row names %s; README leaves that column a dash", row.env)
	}

	clearEnv(t)
	t.Setenv("TPLINK_VERSION", "true")
	fs, o, e := bind(t)
	parse(t, fs)

	f := fs.Lookup("version")
	if f == nil {
		t.Fatal("bindFlags declares no -version; every flag is declared there, or the next one goes " +
			"unwired the way -session-renew did")
	}
	if f.DefValue != "false" {
		t.Errorf("-version defaults to %q; a default of true prints and exits instead of starting", f.DefValue)
	}
	if strings.Contains(f.Usage, "TPLINK_") {
		t.Errorf("-version is described as %q; it reads no environment variable", f.Usage)
	}
	if o.Version {
		t.Error("TPLINK_VERSION=true set options.Version; the flag has no environment fallback, and a " +
			"container that carried that variable would print and exit instead of polling")
	}
	if len(e.errs) != 0 {
		t.Errorf("declaring the flags recorded %v", e.errs)
	}
}

// The landing page names the build, escaped: those values come from build
// arguments.
func TestLandingPageCarriesTheBuild(t *testing.T) {
	b := exporter.BuildInfo{Version: "2026.8.0<script>", Revision: "1a2b3c4", GoVersion: runtime.Version()}

	rec := httptest.NewRecorder()
	landing(time.Minute, b)(rec, httptest.NewRequest("GET", "/", nil))
	body := rec.Body.String()

	if want := "<p>" + html.EscapeString(buildLine(b)) + "</p>"; !strings.Contains(body, want) {
		t.Errorf("the landing page does not carry the line -version prints, as its own paragraph:\nwant %s\n%s",
			want, body)
	}
	if strings.Contains(body, "<script>") {
		t.Errorf("the landing page carries a build argument as markup:\n%s", body)
	}
}
