package secureFiles

import (
	"io"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func NewSecureFilesCmd() *cobra.Command {
	secureFilesCmd := &cobra.Command{
		Use:     "secureFiles",
		Short:   "Print CI/CD secure files",
		Long:    "Fetch and print all CI/CD secure files for projects your token has access to.",
		Example: `pipeleek gl secureFiles --token glpat-xxxxxxxxxxx --gitlab https://gitlab.mydomain.com`,
		Run:     FetchSecureFiles,
	}
	secureFilesCmd.Flags().StringP("gitlab", "g", "", "GitLab instance URL")
	secureFilesCmd.Flags().StringP("token", "t", "", "GitLab API Token")

	return secureFilesCmd
}

func FetchSecureFiles(cmd *cobra.Command, args []string) {
	if err := config.AutoBindFlags(cmd, map[string]string{
		"gitlab": "gitlab.url",
		"token":  "gitlab.token",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
	}

	if err := config.RequireConfigKeys("gitlab.url", "gitlab.token"); err != nil {
		log.Fatal().Err(err).Msg("required configuration missing")
	}

	gitlabUrl := config.GetString("gitlab.url")
	gitlabApiToken := config.GetString("gitlab.token")

	if err := config.ValidateURL(gitlabUrl, "GitLab URL"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab URL")
	}
	if err := config.ValidateToken(gitlabApiToken, "GitLab API Token"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab API Token")
	}

	runFetchSecureFiles(gitlabUrl, gitlabApiToken)
}

func runFetchSecureFiles(gitlabUrl, gitlabApiToken string) {
	log.Info().Msg("Fetching secure files")

	git, err := util.GetGitlabClient(gitlabApiToken, gitlabUrl)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating gitlab client")
	}

	projectOpts := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
		MinAccessLevel: gitlab.Ptr(gitlab.MaintainerPermissions),
		OrderBy:        gitlab.Ptr("last_activity_at"),
	}

	err = util.IterateProjects(git, projectOpts, func(project *gitlab.Project) error {
		log.Debug().Str("project", project.WebURL).Msg("Fetch project secure files")
		listOpts := &gitlab.ListProjectSecureFilesOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    1,
			},
		}
		files, resp, err := git.SecureFiles.ListProjectSecureFiles(project.ID, listOpts)
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			log.Error().Stack().Err(err).Int("status", status).Str("project", project.WebURL).Msg("Failed fetching secure files list")
			return nil
		}

		for _, file := range files {
			reader, resp, err := git.SecureFiles.DownloadSecureFile(project.ID, file.ID)
			if err != nil {
				status := 0
				if resp != nil {
					status = resp.StatusCode
				}
				log.Error().Stack().Err(err).Int("status", status).Str("project", project.WebURL).Int64("fileId", file.ID).Msg("Failed fetching secure file")
				continue
			}

			secureFile, err := io.ReadAll(reader)
			if err != nil {
				log.Error().Stack().Err(err).Str("project", project.WebURL).Int64("fileId", file.ID).Msg("Failed reading secure file")
				continue
			}

			if len(secureFile) > 100 {
				secureFile = secureFile[:100]
			}
			log.Warn().
				Str("project", project.WebURL).
				Str("name", file.Name).
				Bytes("content", secureFile).
				Msg("Secure file")
		}
		return nil
	})
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed iterating projects")
	}

	log.Info().Msg("Fetched all secure files")
}
