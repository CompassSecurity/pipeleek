package scan

import (
	"fmt"
	"net/url"
	"strings"
)

func normalizeProjectSlug(value, defaultVCS string) (string, error) {
	parts := strings.Split(strings.Trim(value, " /"), "/")
	if len(parts) == 2 {
		return fmt.Sprintf("%s/%s/%s", defaultVCS, parts[0], parts[1]), nil
	}
	if len(parts) == 3 {
		return strings.Join(parts, "/"), nil
	}
	return "", fmt.Errorf("invalid project selector %q (expected org/repo or vcs/org/repo)", value)
}

func belongsToOrg(projectSlug, org string) bool {
	parts := strings.Split(projectSlug, "/")
	return len(parts) >= 3 && strings.EqualFold(parts[1], org)
}

func normalizedOrgName(org string) string {
	trimmed := strings.Trim(strings.TrimSpace(org), "/")
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return trimmed
}

func toFilterSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(strings.ToLower(value))
		if trimmed == "" {
			continue
		}
		out[trimmed] = struct{}{}
	}
	return out
}

func matchesFilter(filter map[string]struct{}, value string) bool {
	if len(filter) == 0 {
		return true
	}
	_, ok := filter[strings.ToLower(strings.TrimSpace(value))]
	return ok
}

func vcsFromURL(raw string) string {
	value := strings.ToLower(raw)
	switch {
	case strings.Contains(value, "bitbucket"):
		return "bitbucket"
	case strings.Contains(value, "github"):
		return "github"
	default:
		return ""
	}
}

func normalizeVCSName(vcs string) string {
	switch strings.ToLower(strings.TrimSpace(vcs)) {
	case "github", "gh":
		return "github"
	case "bitbucket", "bb":
		return "bitbucket"
	case "circleci":
		return "circleci"
	default:
		return strings.ToLower(strings.TrimSpace(vcs))
	}
}

func projectSlugFromV1(item v1ProjectItem, defaultVCS string) (string, bool) {
	vcs := normalizeVCSName(item.VCSType)
	if vcs == "circleci" {
		if slug, ok := circleciUUIDSlug(item.VCSURL); ok {
			return slug, true
		}
	}

	org := strings.TrimSpace(item.Username)
	repo := strings.TrimSpace(item.Reponame)
	if org == "" || repo == "" {
		return "", false
	}

	if vcs == "" {
		vcs = normalizeVCSName(vcsFromURL(item.VCSURL))
	}
	if vcs == "" {
		vcs = normalizeVCSName(defaultVCS)
	}
	if vcs == "" {
		vcs = "github"
	}

	normalized, err := normalizeProjectSlug(fmt.Sprintf("%s/%s/%s", vcs, org, repo), defaultVCS)
	if err != nil {
		return "", false
	}

	return normalized, true
}

func circleciUUIDSlug(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false
	}
	trimmed = strings.TrimPrefix(trimmed, "https://")
	trimmed = strings.TrimPrefix(trimmed, "http://")
	trimmed = strings.TrimPrefix(trimmed, "//")
	trimmed = strings.TrimPrefix(trimmed, "circleci.com/")
	trimmed = strings.Trim(trimmed, "/")

	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return "", false
	}

	orgID := strings.TrimSpace(parts[0])
	projectID := strings.TrimSpace(parts[1])
	if orgID == "" || projectID == "" {
		return "", false
	}

	return fmt.Sprintf("circleci/%s/%s", orgID, projectID), true
}

func vcsSlugCandidates(vcs string) []string {
	v := strings.ToLower(strings.TrimSpace(vcs))
	switch v {
	case "gh", "github":
		return []string{"github", "gh"}
	case "bb", "bitbucket":
		return []string{"bitbucket", "bb"}
	case "gitlab", "gl":
		return []string{"gitlab", "gl"}
	case "":
		return []string{"github", "gh", "bitbucket", "bb"}
	default:
		return []string{v}
	}
}

func uniqueStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		key := strings.TrimSpace(value)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

func orgSlugCandidates(value, defaultVCS string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}

	candidates := []string{trimmed}

	// Support org/project URLs like:
	// https://app.circleci.com/pipelines/github/storybookjs/storybook
	if parsed, err := url.Parse(trimmed); err == nil && parsed.Host != "" {
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(parts) >= 3 && parts[0] == "pipelines" {
			vcs := normalizeVCSName(parts[1])
			org := strings.TrimSpace(parts[2])
			if vcs != "" && org != "" {
				candidates = append(candidates, fmt.Sprintf("%s/%s", vcs, org), org)
			}
		}
	}

	orgName := normalizedOrgName(trimmed)
	if orgName != "" && !strings.EqualFold(orgName, trimmed) {
		candidates = append(candidates, orgName)
	}

	if !strings.Contains(orgName, "/") && orgName != "" {
		for _, vcsSlug := range vcsSlugCandidates(defaultVCS) {
			candidates = append(candidates, fmt.Sprintf("%s/%s", vcsSlug, orgName))
		}
	}

	return uniqueStrings(candidates)
}

func orgDiscoveryHint(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	if parsed, err := url.Parse(trimmed); err == nil && parsed.Host != "" {
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(parts) >= 4 && parts[0] == "pipelines" {
			vcs := normalizeVCSName(parts[1])
			org := strings.TrimSpace(parts[2])
			repo := strings.TrimSpace(parts[3])
			if vcs != "" && org != "" && repo != "" {
				return fmt.Sprintf("--org appears to be a project URL; use --project %s/%s/%s instead", vcs, org, repo)
			}
		}
	}

	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) == 3 && normalizeVCSName(parts[0]) != "" {
		return fmt.Sprintf("--org appears to be a project selector; use --project %s instead", strings.Join(parts, "/"))
	}

	return "org-wide discovery requires token visibility to that CircleCI org; if discovery fails, scan explicit projects with --project"
}
