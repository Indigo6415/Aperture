package domainscan

import (
	"context"
	"testing"
)

// TestModulesHaveUniqueIDsAndNames checks the module registry: every module has
// a non-empty ID and name, and no two share an ID, since the UI keys results by it.
func TestModulesHaveUniqueIDsAndNames(t *testing.T) {
	mods := Modules()
	if len(mods) == 0 {
		t.Fatal("no domain-scan modules registered")
	}
	seen := map[string]bool{}
	for _, m := range mods {
		if m.ID == "" || m.Name == "" {
			t.Errorf("module %+v has an empty ID or name", m)
		}
		if seen[m.ID] {
			t.Errorf("duplicate module ID %q", m.ID)
		}
		seen[m.ID] = true
	}
}

// TestRunScanStreamingRejectsEmptyTarget makes sure a blank target is refused up
// front rather than fanned out across every module.
func TestRunScanStreamingRejectsEmptyTarget(t *testing.T) {
	if _, err := RunScanStreaming(context.Background(), "", Options{}, func(ModuleResult) {}); err == nil {
		t.Fatal("expected an error for an empty target")
	}
}
