package exporter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

// grafana/tplink-archer.json is shipped for other people to import. What breaks
// an import elsewhere is not malformed JSON but a datasource uid from the
// Grafana the file was exported from: it resolves nowhere else and every query
// under it comes back empty. These tests read the structure and the datasource
// references; nothing here parses PromQL.
//
// go test runs with the working directory set to the package source directory,
// so the path is relative to internal/exporter, not to the module root.
const dashboardPath = "../../grafana/tplink-archer.json"

const (
	// The __inputs entry Grafana's import dialog asks for, and the templating
	// variable that consumes it. Every query in the file goes through the
	// variable, so the input is bound once and read 100+ times.
	datasourceInput = "DS_PROMETHEUS"
	datasourceVar   = "datasource"
)

// What a datasource reference may point at. The first two are the dashboard's
// own indirection, the rest are Grafana's built-in datasources:
//
//	${datasource}     the templating variable
//	${DS_PROMETHEUS}  the import input, before the variable is resolved
//	-- Grafana --     the built-in annotation store
//	-- Mixed --       one panel querying several datasources
//	-- Dashboard --   a panel reusing another panel's result
//	__expr__          server-side expressions: reduce, math, threshold
var allowedDatasourceUIDs = []string{
	"${datasource}",
	"${" + datasourceInput + "}",
	"-- Grafana --",
	"-- Mixed --",
	"-- Dashboard --",
	"__expr__",
}

// datasourceRef is one datasource reference and where it sits.
type datasourceRef struct {
	path  string // JSON path of the datasource field: panels[12].targets[0].datasource
	uid   string // what it points at; empty when the value carries no uid
	value any    // the value as decoded, for a failure that has to show it
}

// datasourceRefs collects every value under a "datasource" key, wherever it
// sits: annotations, templating, panels, the targets inside them, and panels
// nested in a collapsed row. Keying on the field name rather than on the shape
// of the object keeps the dashboard's own uid and a libraryPanel uid out of the
// result. Map keys are walked in sorted order so a failure reads the same way
// twice.
func datasourceRefs(node any, path string) []datasourceRef {
	var out []datasourceRef
	switch n := node.(type) {
	case map[string]any:
		for _, key := range slices.Sorted(maps.Keys(n)) {
			child := childPath(path, key)
			if key == "datasource" {
				out = append(out, datasourceRef{path: child, uid: refUID(n[key]), value: n[key]})
			}
			out = append(out, datasourceRefs(n[key], child)...)
		}
	case []any:
		for i, v := range n {
			out = append(out, datasourceRefs(v, fmt.Sprintf("%s[%d]", path, i))...)
		}
	}
	return out
}

// refUID is the uid a datasource reference points at. The current schema writes
// {"type": ..., "uid": ...}; a bare string is the pre-9 shape, where the string
// itself names the datasource. Anything else carries no uid.
func refUID(v any) string {
	switch ref := v.(type) {
	case map[string]any:
		uid, _ := ref["uid"].(string)
		return uid
	case string:
		return ref
	}
	return ""
}

// unboundRefs is every reference that will not resolve in a Grafana other than
// the one the file was exported from.
func unboundRefs(refs []datasourceRef) []datasourceRef {
	var bad []datasourceRef
	for _, r := range refs {
		if !slices.Contains(allowedDatasourceUIDs, r.uid) {
			bad = append(bad, r)
		}
	}
	return bad
}

func childPath(path, field string) string {
	if path == "" {
		return field
	}
	return path + "." + field
}

// asJSON renders a decoded value the way the file writes it, so a failure can
// be found by searching for the text it prints.
func asJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// loadDashboard reads and decodes grafana/tplink-archer.json.
func loadDashboard(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatalf("%s: %v", dashboardPath, err)
	}
	return decodeJSON(t, dashboardPath, raw)
}

// decodeJSON decodes one JSON object and nothing after it. Numbers stay
// json.Number so a failure prints the digits the file carries.
func decodeJSON(t *testing.T, what string, raw []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("%s does not parse as JSON: %v", what, err)
	}
	// Decode stops at the end of the first value. A second call must hit EOF, or
	// the file carries text past the dashboard that Grafana's importer rejects.
	switch err := dec.Decode(new(any)); {
	case err == nil:
		t.Fatalf("%s holds a second JSON value after the dashboard object", what)
	case !errors.Is(err, io.EOF):
		t.Fatalf("%s carries text after the dashboard object: %v", what, err)
	}

	obj, ok := doc.(map[string]any)
	if !ok {
		t.Fatalf("%s decodes to %T; a dashboard is a JSON object", what, doc)
	}
	return obj
}

// Assertion 1: the file parses as JSON.
func TestDashboardParsesAsJSON(t *testing.T) {
	if doc := loadDashboard(t); len(doc) == 0 {
		t.Fatalf("%s parses to an empty object; the file is JSON and nothing else", dashboardPath)
	}
}

// Assertion 2: __inputs declares DS_PROMETHEUS as a Prometheus datasource. It is
// what the import dialog asks the importer to pick.
func TestDashboardDeclaresThePrometheusInput(t *testing.T) {
	doc := loadDashboard(t)

	inputs, ok := doc["__inputs"].([]any)
	if !ok {
		t.Fatalf("%s has no __inputs list (%s): an export without one asks the importer for nothing, and every ${%s} in the file stays a literal",
			dashboardPath, asJSON(doc["__inputs"]), datasourceInput)
	}

	var names []string
	found := false
	for i, raw := range inputs {
		in, ok := raw.(map[string]any)
		if !ok {
			t.Errorf("__inputs[%d] is %s, not an object", i, asJSON(raw))
			continue
		}
		name, _ := in["name"].(string)
		names = append(names, name)
		if name != datasourceInput {
			continue
		}
		found = true
		// Anything else renders a free-text box, and ${DS_PROMETHEUS} is
		// substituted with whatever the importer typed into it.
		if got, _ := in["type"].(string); got != "datasource" {
			t.Errorf(`__inputs[%d] %s has type %q, want "datasource": the import dialog offers a datasource picker only for that`,
				i, datasourceInput, got)
		}
		if got, _ := in["pluginId"].(string); got != "prometheus" {
			t.Errorf(`__inputs[%d] %s has pluginId %q, want "prometheus": the import dialog offers the datasources of that plugin, and no other type answers PromQL`,
				i, datasourceInput, got)
		}
	}
	if !found {
		t.Errorf("__inputs carries %v and no %s: the import dialog asks for no datasource, and the variable bound to that input has nothing to take",
			names, datasourceInput)
	}
}

// Assertion 3: the templating variable consumes the input. Without it the input
// is declared and nobody reads it.
func TestDashboardVariableConsumesThePrometheusInput(t *testing.T) {
	doc := loadDashboard(t)

	templating, ok := doc["templating"].(map[string]any)
	if !ok {
		t.Fatalf("%s has no templating object (%s): the %s input is declared and nothing consumes it",
			dashboardPath, asJSON(doc["templating"]), datasourceInput)
	}
	list, ok := templating["list"].([]any)
	if !ok {
		t.Fatalf("templating.list is %s, not a list of variables", asJSON(templating["list"]))
	}

	var names []string
	for i, raw := range list {
		v, ok := raw.(map[string]any)
		if !ok {
			t.Errorf("templating.list[%d] is %s, not an object", i, asJSON(raw))
			continue
		}
		name, _ := v["name"].(string)
		names = append(names, name)
		if name != datasourceVar {
			continue
		}

		if got, _ := v["type"].(string); got != "datasource" {
			t.Errorf(`templating.list[%d] %s has type %q, want "datasource": only a datasource variable holds a datasource uid, and the panels use this one as if it did`,
				i, datasourceVar, got)
		}
		// query names the plugin the variable's picker offers. Another plugin
		// there and the panels send PromQL to whatever the picker lands on.
		if got, _ := v["query"].(string); got != "prometheus" {
			t.Errorf(`templating.list[%d] %s selects from plugin %q, want "prometheus"`, i, datasourceVar, got)
		}
		current, ok := v["current"].(map[string]any)
		if !ok {
			t.Errorf("templating.list[%d] %s has current = %s, not an object", i, datasourceVar, asJSON(v["current"]))
			return
		}
		want := "${" + datasourceInput + "}"
		if got, _ := current["value"].(string); got != want {
			t.Errorf("templating.list[%d] %s is currently %s, want value %q: the import writes the picked datasource here, and a variable holding anything else pins the dashboard to one Grafana",
				i, datasourceVar, asJSON(current), want)
		}
		return
	}
	t.Errorf("templating.list carries %v and no variable named %s: every ${%s} reference in the panels resolves to nothing",
		names, datasourceVar, datasourceVar)
}

// Assertion 4: no reference anywhere in the tree is a raw uid.
func TestDashboardPinsNoRawDatasourceUID(t *testing.T) {
	refs := datasourceRefs(loadDashboard(t), "")
	if len(refs) == 0 {
		t.Fatalf("%s carries no datasource reference at all: either the panels lost their queries or the walk stopped short, and this test proves nothing either way",
			dashboardPath)
	}

	for _, bad := range unboundRefs(refs) {
		t.Errorf("%s carries uid %q in %s; want one of %s. A uid outside that set is the one the exporting Grafana gave its own datasource, and every query under it imports bound to nothing",
			bad.path, bad.uid, asJSON(bad.value), strings.Join(allowedDatasourceUIDs, ", "))
	}
}

// Assertion 5: the top-level id is null. "Export for sharing" nulls it; a
// numeric id is a dashboard copied out of the browser, and it collides on
// import.
func TestDashboardIDIsNull(t *testing.T) {
	doc := loadDashboard(t)

	id, ok := doc["id"]
	if !ok {
		t.Fatalf(`%s has no top-level id: "export for sharing" writes "id": null, and this file is what that export produced`, dashboardPath)
	}
	if id != nil {
		t.Errorf("%s carries id %v, want null: that is the id the dashboard held in the Grafana it was copied out of, and it collides on import",
			dashboardPath, id)
	}
}

// The walk is what assertion 4 rests on: one that missed a subtree would report
// a clean file whatever the file held. These documents are written here rather
// than read from grafana/, so a rule with a hole in it fails on a case the real
// dashboard does not happen to carry.
func TestDashboardDatasourceWalkSeesEveryReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
		want []string // every reference as "path=uid", in the order the walk reports
		bad  []string // paths of the references that will not bind elsewhere
	}{
		{
			name: "a panel and the target under it",
			doc:  `{"panels":[{"datasource":{"type":"prometheus","uid":"${datasource}"},"targets":[{"datasource":{"type":"prometheus","uid":"PBFA97CFB590B2093"}}]}]}`,
			want: []string{
				"panels[0].datasource=${datasource}",
				"panels[0].targets[0].datasource=PBFA97CFB590B2093",
			},
			bad: []string{"panels[0].targets[0].datasource"},
		},
		{
			name: "a panel inside a collapsed row",
			doc:  `{"panels":[{"type":"row","panels":[{"targets":[{"datasource":{"type":"prometheus","uid":"P1234"}}]}]}]}`,
			want: []string{"panels[0].panels[0].targets[0].datasource=P1234"},
			bad:  []string{"panels[0].panels[0].targets[0].datasource"},
		},
		{
			name: "annotations and templating, outside panels entirely",
			doc:  `{"annotations":{"list":[{"datasource":{"type":"grafana","uid":"-- Grafana --"}}]},"templating":{"list":[{"datasource":{"type":"prometheus","uid":"${datasource}"},"name":"instance"}]}}`,
			want: []string{
				"annotations.list[0].datasource=-- Grafana --",
				"templating.list[0].datasource=${datasource}",
			},
		},
		{
			name: "the built-in datasources and the input itself",
			doc:  `{"panels":[{"datasource":{"uid":"-- Mixed --"}},{"datasource":{"uid":"-- Dashboard --"}},{"datasource":{"uid":"${DS_PROMETHEUS}"}}]}`,
			want: []string{
				"panels[0].datasource=-- Mixed --",
				"panels[1].datasource=-- Dashboard --",
				"panels[2].datasource=${DS_PROMETHEUS}",
			},
		},
		{
			// Grafana before 9 wrote the datasource as a string naming it, and a
			// name is as local to one Grafana as a uid.
			name: "the pre-9 string shape",
			doc:  `{"panels":[{"datasource":"Prometheus"},{"datasource":"${datasource}"}]}`,
			want: []string{
				"panels[0].datasource=Prometheus",
				"panels[1].datasource=${datasource}",
			},
			bad: []string{"panels[0].datasource"},
		},
		{
			// Both bind to whatever the importing Grafana calls default, not to
			// the datasource the importer picked.
			name: "references carrying no uid",
			doc:  `{"panels":[{"datasource":null},{"datasource":{"type":"prometheus"}}]}`,
			want: []string{"panels[0].datasource=", "panels[1].datasource="},
			bad:  []string{"panels[0].datasource", "panels[1].datasource"},
		},
		{
			// Grafana's own expression datasource: reduce, math, threshold. It
			// resolves in every Grafana, so the rule must not call it foreign.
			name: "a server-side expression",
			doc:  `{"panels":[{"targets":[{"datasource":{"type":"__expr__","uid":"__expr__"}},{"datasource":{"uid":"__expr_"}}]}]}`,
			want: []string{
				"panels[0].targets[0].datasource=__expr__",
				"panels[0].targets[1].datasource=__expr_",
			},
			bad: []string{"panels[0].targets[1].datasource"},
		},
		{
			name: "uids that are not datasource references",
			doc:  `{"uid":"tplink-archer","panels":[{"libraryPanel":{"uid":"a1b2c3","name":"shared"}}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refs := datasourceRefs(decodeJSON(t, tc.name, []byte(tc.doc)), "")

			if got := refLines(refs); !slices.Equal(got, tc.want) {
				t.Errorf("the walk found\n\t%v\nwant\n\t%v", got, tc.want)
			}
			var badPaths []string
			for _, r := range unboundRefs(refs) {
				badPaths = append(badPaths, r.path)
			}
			if !slices.Equal(badPaths, tc.bad) {
				t.Errorf("the rule rejected %v, want %v", badPaths, tc.bad)
			}
		})
	}
}

// refLines renders references as "path=uid", the shape the table writes them in.
func refLines(refs []datasourceRef) []string {
	var out []string
	for _, r := range refs {
		out = append(out, r.path+"="+r.uid)
	}
	return out
}
