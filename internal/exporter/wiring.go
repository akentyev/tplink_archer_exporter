package exporter

import "github.com/akentyev/tplink_archer_exporter/internal/tpapi"

// The real client has to satisfy Router, or the interface is fiction. Checked
// at compile time so a signature drift fails the build, not a live run.
var _ Router = (*tpapi.Client)(nil)
