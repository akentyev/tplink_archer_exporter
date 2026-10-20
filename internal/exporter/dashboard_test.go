package exporter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/akentyev/tplink_archer_exporter/internal/push"
)

// grafana/tplink-archer.json is shipped for other people to import. What breaks
// an import elsewhere is not malformed JSON but a datasource uid from the
// Grafana the file was exported from: it resolves nowhere else and every query
// under it comes back empty. These tests read the structure, the datasource
// references and the metric names; no PromQL is parsed — a metric name is
// matched as text, wherever a string carries one.
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

func TestDashboardParsesAsJSON(t *testing.T) {
	if doc := loadDashboard(t); len(doc) == 0 {
		t.Fatalf("%s parses to an empty object; the file is JSON and nothing else", dashboardPath)
	}
}

// The import dialog asks the importer to pick what __inputs declares.
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

// Without the variable the input is declared and nobody reads it.
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

// "Export for sharing" nulls the top-level id; a numeric one is a dashboard
// copied out of the browser, and it collides on import.
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

// metricName matches a metric name in a string. Every name this exporter
// publishes is tplink_ followed by lowercase, digits and underscore.
var metricName = regexp.MustCompile(`\btplink_[a-z0-9_]+\b`)

// Metrics published and deliberately not drawn, and why. A reason is
// required: an empty one does not count as an entry.
var metricsWithoutAPanel = map[string]string{
	"tplink_cpu_cores":         "the count is the number of tplink_cpu_core_usage_ratio series",
	"tplink_router_clock_info": "a TP-Link timezone index is not an offset and names no location",
}

// publishedMetricNames is every tplink_ name a scrape can carry: what the
// collector announces through Describe, and the delivery metrics
// internal/push registers into the same snapshot registry.
func publishedMetricNames(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for name := range describedMetrics(t) {
		names[name] = true
	}
	for _, name := range push.MetricNames() {
		names[name] = true
	}
	return names
}

// dashboardMetricNames maps every metric name the file mentions to the JSON
// paths mentioning it. Only string values are read; the keys are Grafana's
// schema, never a metric name.
func dashboardMetricNames(doc any) map[string][]string {
	names := map[string][]string{}
	collectMetricNames(doc, "", names)
	return names
}

// collectMetricNames walks the decoded file; sorted keys, as in datasourceRefs.
func collectMetricNames(node any, path string, into map[string][]string) {
	switch n := node.(type) {
	case map[string]any:
		for _, key := range slices.Sorted(maps.Keys(n)) {
			collectMetricNames(n[key], childPath(path, key), into)
		}
	case []any:
		for i, v := range n {
			collectMetricNames(v, fmt.Sprintf("%s[%d]", path, i), into)
		}
	case string:
		for _, name := range metricName.FindAllString(n, -1) {
			into[name] = append(into[name], path)
		}
	}
}

func TestDashboardNamesOnlyPublishedMetrics(t *testing.T) {
	found := dashboardMetricNames(loadDashboard(t))
	if len(found) == 0 {
		t.Fatalf("%s names no tplink_ metric at all: either the panels lost their queries or the walk stopped short, and this test proves nothing either way",
			dashboardPath)
	}

	published := publishedMetricNames(t)
	for _, name := range slices.Sorted(maps.Keys(found)) {
		if published[name] {
			continue
		}
		t.Errorf("%s asks for %s in %s, and the exporter publishes no such metric: the panel comes back empty and Grafana reports no error",
			dashboardPath, name, strings.Join(found[name], ", "))
	}
}

// A hole in the walk fails this test: the names it missed read as undrawn.
func TestDashboardDrawsEveryPublishedMetric(t *testing.T) {
	found := dashboardMetricNames(loadDashboard(t))
	published := publishedMetricNames(t)

	for _, name := range slices.Sorted(maps.Keys(published)) {
		if len(found[name]) > 0 || metricsWithoutAPanel[name] != "" {
			continue
		}
		t.Errorf("the exporter publishes %s and %s never names it: either nobody drew it, or a panel lost its query. Draw it, or put the name in metricsWithoutAPanel with the reason",
			name, dashboardPath)
	}

	for _, name := range slices.Sorted(maps.Keys(metricsWithoutAPanel)) {
		switch {
		case len(found[name]) > 0:
			t.Errorf("metricsWithoutAPanel says %s is drawn nowhere and %s draws it in %s: take the entry out",
				name, dashboardPath, strings.Join(found[name], ", "))
		case !published[name]:
			t.Errorf("metricsWithoutAPanel keeps %s and the exporter publishes no such metric: it was renamed or dropped, and the entry outlived it",
				name)
		}
	}
}

// forEachTarget calls fn on every target in file order, the panels nested in a
// row included, with the panel it sits in and the target's JSON path.
func forEachTarget(panels any, path string, fn func(panel, target map[string]any, path string)) {
	list, _ := panels.([]any)
	for i, raw := range list {
		panel, _ := raw.(map[string]any)
		panelPath := fmt.Sprintf("%s[%d]", path, i)
		targets, _ := panel["targets"].([]any)
		for j, raw := range targets {
			target, _ := raw.(map[string]any)
			fn(panel, target, fmt.Sprintf("%s.targets[%d]", panelPath, j))
		}
		forEachTarget(panel["panels"], panelPath+".panels", fn)
	}
}

// Every label this drops can change between cycles: ip on a new lease, iface,
// guest, via and type as the firmware reports them. Two series in one lookback
// window fail the join on the duplicate, in a range query too: VictoriaMetrics
// v1.153.0 without staleness markers merges a one-off change there, not one
// that alternates. An alternating hostname gives two series, no error.
const clientInfoJoin = "max by (mac, instance, hostname) (tplink_client_info{"

func TestDashboardJoinsAggregateClientInfo(t *testing.T) {
	checked := 0
	forEachTarget(loadDashboard(t)["panels"], "panels", func(panel, target map[string]any, path string) {
		expr, _ := target["expr"].(string)
		if !strings.Contains(expr, "group_left") || !strings.Contains(expr, "tplink_client_info") {
			return
		}
		checked++
		if strings.Count(expr, "tplink_client_info") != strings.Count(expr, clientInfoJoin) {
			t.Errorf("panel %s %q joins on tplink_client_info outside %s...}) in %s.expr; write every mention through that aggregation: every label it drops can change between cycles (ip on a new lease, iface, guest, via and type as the firmware reports them), and two series in one lookback window fail the join on the duplicate, in a range query as much as in an instant one",
				asJSON(panel["id"]), panel["title"], clientInfoJoin, path)
		}
	})
	if checked == 0 {
		t.Fatalf("%s has no target joining on tplink_client_info: either the panels lost their queries or the walk stopped short, and this test proves nothing either way",
			dashboardPath)
	}
}

// PromQL allows whitespace between a function name and its parenthesis, and an
// aggregation's by or without clause before its arguments. topk_max and the
// other _* variants are MetricsQL's.
var (
	rankCall     = regexp.MustCompile(`\b(?:topk|bottomk)(?:_[a-z]+)?\s*(?:(?:by|without)\s*)?\(`)
	orderedStart = regexp.MustCompile(`^\s*(?:(?:topk|bottomk)(?:_[a-z]+)?|sort|sort_desc)\s*\(`)
)

// oneCall reports whether expr is a single call orderedStart names, with
// nothing after its closing parenthesis. A by or without clause fails it: no
// grouped ranking was measured. Parentheses inside a string do not count; a
// backquoted string takes no escapes.
func oneCall(expr string) bool {
	if !orderedStart.MatchString(expr) {
		return false
	}
	depth, quote := 0, byte(0)
	for i := 0; i < len(expr); i++ {
		switch c := expr[i]; {
		case quote != 0 && quote != '`' && c == '\\':
			i++
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return strings.TrimSpace(expr[i+1:]) == ""
			}
		}
	}
	return false
}

// A panel drawn from an instant query shows the series in the order the query
// returns them. VictoriaMetrics, the dashboard's datasource, sorts them by
// labels unless the whole expr is one call to topk, bottomk, one of their _*
// variants, sort or sort_desc. Measured on v1.153.0: the rule is
// VictoriaMetrics', not PromQL's.
func TestDashboardRankedInstantPanelsKeepTheirOrder(t *testing.T) {
	checked := 0
	forEachTarget(loadDashboard(t)["panels"], "panels", func(panel, target map[string]any, path string) {
		expr, _ := target["expr"].(string)
		instant, _ := target["instant"].(bool)
		if !instant || !rankCall.MatchString(expr) {
			return
		}
		checked++
		if !oneCall(expr) {
			t.Errorf("panel %s %q ranks with topk or bottomk in %s.expr, and the expr is not a single call to topk, bottomk, one of their _* variants, sort or sort_desc: VictoriaMetrics returns an instant query's series sorted by labels unless one of those calls is the whole expr, and the panel draws them in that order",
				asJSON(panel["id"]), panel["title"], path)
		}
	})
	if checked == 0 {
		t.Fatalf("%s has no instant target calling topk, bottomk or one of their _* variants: either the panels lost their queries or the walk stopped short, and this test proves nothing either way",
			dashboardPath)
	}
}

// The dashboard carries one ranked instant target, and a rule with a hole in it
// passes on that one. The shapes it has to tell apart are written here.
func TestDashboardOrderRuleReadsTheWholeExpr(t *testing.T) {
	const (
		x    = `increase(tplink_client_traffic_bytes_total{instance=~"$instance"}[24h])`
		tail = `, "mac_tail", "$1", "mac", ".*:([0-9a-f]{2}:[0-9a-f]{2})")`
	)
	for _, tc := range []struct {
		name    string
		expr    string
		ranks   bool // rankCall matches, so the dashboard test checks the expr
		ordered bool // what oneCall answers
	}{
		// Measured on VictoriaMetrics v1.153.0 with panel 29's join in place of
		// x: ordered is whether the series came back in value order.
		{"topk", "topk(10, label_replace(" + x + tail + ")", true, true},
		{"topk_max", "topk_max(10, label_replace(" + x + tail + ")", true, true},
		{"sort_desc around label_replace around topk", "sort_desc(label_replace(topk(10, " + x + ")" + tail + ")", true, true},
		{"label_replace around topk", "label_replace(topk(10, " + x + ")" + tail, true, false},
		{"label_replace around topk_max", "label_replace(topk_max(10, " + x + ")" + tail, true, false},
		{"a comparison after topk", "topk(10, label_replace(" + x + tail + ") > 0", true, false},
		{"arithmetic after topk", "topk(10, label_replace(" + x + tail + ") * 8", true, false},
		{"or vector(0) after topk", "topk(10, label_replace(" + x + tail + ") or vector(0)", true, false},

		// How the text is read; not measured.
		{"whitespace around the call", " topk (10, " + x + ")\n", true, true},
		{"bottomk", "bottomk(3, " + x + ")", true, true},
		{"a by clause before the arguments", "topk by (instance) (10, " + x + ")", true, false},
		{"a by clause after the arguments", "topk(10, " + x + ") by (instance)", true, false},
		{"sort_by_label around topk", "sort_by_label(topk(10, " + x + `), "mac")`, true, false},
		{"a parenthesis in a double-quoted string", "topk(10, label_replace(" + x + `, "tail", ")", "mac", ".*"))`, true, true},
		{"a parenthesis after an escaped quote", "topk(10, label_replace(" + x + `, "tail", "\")", "mac", ".*"))`, true, true},
		{"a parenthesis in a single-quoted string", "topk(10, label_replace(" + x + `, 'tail', ')', 'mac', '.*'))`, true, true},
		{"a parenthesis in a backquoted string", "topk(10, label_replace(" + x + ", `tail`, `)`, `mac`, `.*`))", true, true},
		{"a backslash ending a backquoted string", "topk(10, label_replace(" + x + ", `tail`, `\\`, `mac`, `.*`))", true, true},
		{"an unclosed call", "topk(10, " + x, true, false},
		{"a parenthesis too many", "topk(10, " + x + "))", true, false},
		{"sort_desc without a ranking", "sort_desc(" + x + ")", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rankCall.MatchString(tc.expr); got != tc.ranks {
				t.Errorf("rankCall matches %q: %v, want %v", tc.expr, got, tc.ranks)
			}
			if got := oneCall(tc.expr); got != tc.ordered {
				t.Errorf("oneCall(%q) = %v, want %v", tc.expr, got, tc.ordered)
			}
		})
	}
}
