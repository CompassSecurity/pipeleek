package util

import gitlab "gitlab.com/gitlab-org/api/client-go"

// ListAllUsers pages through /api/v4/users and returns all users found.
// It returns the last API response on error to allow callers to inspect HTTP status codes.
func ListAllUsers(git *gitlab.Client) ([]*gitlab.User, *gitlab.Response, error) {
	allUsers := make([]*gitlab.User, 0)
	page := int64(1)

	for page != -1 {
		users, resp, err := git.Users.ListUsers(&gitlab.ListUsersOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    page,
			},
		})
		if err != nil {
			return nil, resp, err
		}

		for _, user := range users {
			if user != nil {
				allUsers = append(allUsers, user)
			}
		}

		if resp != nil && resp.NextPage > 0 {
			page = resp.NextPage
		} else {
			page = -1
		}
	}

	return allUsers, nil, nil
}
