package users

import "github.com/spf13/cobra"

func NewUsersRootCmd() *cobra.Command {
	usersCmd := &cobra.Command{
		Use:   "users",
		Short: "GitLab user related commands",
		Long:  "Commands to enumerate GitLab users.",
	}

	usersCmd.AddCommand(NewEnumCmd())

	return usersCmd
}
