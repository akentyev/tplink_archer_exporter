package main

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The linker says nothing about an -X naming a symbol that is not there: a
// binary built with -X main.Version=2026.8.0 reports dev, exactly as if no
// build argument had been passed. version_test.go writes its own -X flags and so
// cannot see a typo in the Dockerfile, and no test builds the image. This reads
// the Dockerfile instead.
const dockerfilePath = "../../Dockerfile"

// Referenced so that renaming either variable stops this file compiling: the
// Dockerfile names them as text, which no compiler checks.
var _ = [...]*string{&version, &revision}

var (
	ldflagSymbol = regexp.MustCompile(`-X (main\.[A-Za-z_][A-Za-z0-9_]*)=`)
	buildStage   = regexp.MustCompile(`(?m)^FROM .* AS build\b`)
	nextStage    = regexp.MustCompile(`(?m)^FROM `)
	buildImage   = regexp.MustCompile(`FROM [^\n]*\bgolang:([0-9][0-9.]*)-`)
	goDirective  = regexp.MustCompile(`(?m)^go ([0-9][0-9.]*)$`)
)

func TestDockerfileLinksTheVariablesThisPackageDeclares(t *testing.T) {
	var got []string
	for _, m := range ldflagSymbol.FindAllStringSubmatch(dockerfile(t), -1) {
		got = append(got, m[1])
	}
	slices.Sort(got)

	want := []string{"main.revision", "main.version"}
	if !slices.Equal(got, want) {
		t.Errorf("%s links %v, want %v: a name that matches no symbol links nothing and leaves the image reporting dev and unknown",
			dockerfilePath, got, want)
	}
}

// The link has to consume the arguments, not merely sit below them: ${VERSIN}
// leaves ARG VERSION declared and unread, and single quotes leave ${VERSION}
// unexpanded into the label. Both build, and both lie.
func TestDockerfileLinksWhatTheBuildArgumentsCarry(t *testing.T) {
	stage := buildStageBody(t)

	if !strings.Contains(stage, `-ldflags="`) {
		t.Errorf("the build stage of %s does not open -ldflags with a double quote; in single quotes the shell leaves ${VERSION} to be linked as text",
			dockerfilePath)
	}
	for _, want := range []string{"-X main.version=${VERSION}", "-X main.revision=${REVISION}"} {
		if !strings.Contains(stage, want) {
			t.Errorf("the build stage of %s does not carry %q: a name that matches no ARG expands to nothing and the build argument is lost without a word",
				dockerfilePath, want)
		}
	}
}

// ARG is per-stage. The pair declared in the final stage feeds the OCI labels
// and does not reach the compiler.
func TestDockerfileDeclaresTheBuildArgumentsItLinks(t *testing.T) {
	stage := buildStageBody(t)
	link := strings.Index(stage, "-X main.version=")
	if link < 0 {
		t.Fatalf("the build stage of %s does not link main.version at all", dockerfilePath)
	}

	for _, arg := range []string{"ARG VERSION", "ARG REVISION"} {
		switch at := strings.Index(stage, arg); {
		case at < 0:
			t.Errorf("the build stage of %s has no %s: the pair in the final stage feeds the labels and never reaches the compiler",
				dockerfilePath, arg)
		case at > link:
			t.Errorf("the build stage of %s declares %s after the go build that expands it, where it expands to nothing",
				dockerfilePath, arg)
		}
	}
}

func stripComments(body string) string {
	var kept []string
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

func dockerfile(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("%s: %v", dockerfilePath, err)
	}
	return string(raw)
}

// buildStageBody is the stage that compiles, from its FROM to the next one,
// with comment lines dropped: a linker flag inside one builds nothing.
func buildStageBody(t *testing.T) string {
	t.Helper()
	body := stripComments(dockerfile(t))
	start := buildStage.FindStringIndex(body)
	if start == nil {
		t.Fatalf("%s has no stage named build", dockerfilePath)
	}
	body = body[start[1]:]
	if end := nextStage.FindStringIndex(body); end != nil {
		body = body[:end[0]]
	}
	return body
}

// The build stage says it pins the patch release go.mod asks for, and until now
// nothing held it to that. The floor is load-bearing: net.ParseMAC reads bare
// twelve hex only from 1.26.
func TestDockerfileBuildsOnTheToolchainGoModAsksFor(t *testing.T) {
	image := buildImage.FindStringSubmatch(dockerfile(t))
	if image == nil {
		t.Fatalf("%s names no golang image to build with", dockerfilePath)
	}

	raw, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("go.mod: %v", err)
	}
	directive := goDirective.FindStringSubmatch(string(raw))
	if directive == nil {
		t.Fatal("go.mod carries no go directive")
	}

	if image[1] != directive[1] {
		t.Errorf("%s builds on Go %s while go.mod asks for %s: the two are pinned to each other by a comment and nothing else",
			dockerfilePath, image[1], directive[1])
	}
}
