package rules

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRulesCommand(t *testing.T) {
	root := NewRulesCmd()
	cmd, args, err := root.Find([]string{"download"})
	require.NoError(t, err)
	require.Empty(t, args)
	require.Equal(t, "download", cmd.Name())
	require.Equal(t, reflect.ValueOf(RunDownload).Pointer(), reflect.ValueOf(cmd.RunE).Pointer())
	require.Equal(t, "rules.yml", cmd.Flags().Lookup("output").DefValue)
	require.Equal(t, "false", cmd.Flags().Lookup("force").DefValue)
	require.Error(t, cmd.Args(cmd, []string{"unexpected"}))
}
