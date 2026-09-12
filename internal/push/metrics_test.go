package push

import (
	"slices"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// The metrics have different types, so registration cannot be driven off the
// list and a name can be registered without being listed. Nothing but this
// guard keeps MetricNames true.
func TestMetricNamesAreWhatNewPushMetricsRegisters(t *testing.T) {
	reg := prometheus.NewRegistry()
	if _, err := newPushMetrics(reg); err != nil {
		t.Fatalf("newPushMetrics: %v", err)
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := make([]string, 0, len(families))
	for _, f := range families {
		got = append(got, f.GetName())
	}

	want := MetricNames()
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("the registry holds\n\t%v\nand MetricNames says\n\t%v\nA name registered and not listed is invisible to every check that reads the list; one listed and not registered is a panel drawn against nothing",
			got, want)
	}
}
