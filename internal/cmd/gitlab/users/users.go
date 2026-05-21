package users

import "github.com/spf13/cobra"

func NewUsersRootCmd() *cobra.Command {
	return newUsersRootCmd(true)
}

func NewUnauthenticatedUsersRootCmd() *cobra.Command {
	return newUsersRootCmd(false)
}

func newUsersRootCmd(includeTokenFlag bool) *cobra.Command {
	usersCmd := &cobra.Command{
		Use:   "users",
		Short: "GitLab user related commands",
		Long:  "Commands to enumerate GitLab users.",
	}

	if includeTokenFlag {
		usersCmd.AddCommand(NewEnumCmd())
	} else {
		usersCmd.AddCommand(NewUnauthenticatedEnumCmd())
	}

	return usersCmd
}
