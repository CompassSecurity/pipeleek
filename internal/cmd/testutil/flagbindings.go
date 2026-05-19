package testutil

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// AssertAllFlagsHaveBindings ensures every CLI flag has a binding entry,
// and every binding entry references an existing CLI flag.
func AssertAllFlagsHaveBindings(t *testing.T, cmd *cobra.Command, bindings map[string]string, allowedUnresolvedBindings ...string) {
	t.Helper()

	ignored := map[string]struct{}{
		"help": {},
	}
	allowed := make(map[string]struct{}, len(allowedUnresolvedBindings))
	for _, name := range allowedUnresolvedBindings {
		allowed[name] = struct{}{}
	}

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag == nil {
			return
		}
		if _, skip := ignored[flag.Name]; skip {
			return
		}
		if _, ok := bindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})

	for name := range bindings {
		if _, ok := ignored[name]; ok {
			continue
		}
		if _, ok := allowed[name]; ok {
			continue
		}
		if cmd.Flags().Lookup(name) == nil && cmd.PersistentFlags().Lookup(name) == nil && cmd.InheritedFlags().Lookup(name) == nil {
			t.Errorf("flagBindings contains %q but no such CLI flag exists", name)
		}
	}
}
