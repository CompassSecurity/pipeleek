package enum

import (
	"html/template"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func filterKey(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, " ", "-")
	v = strings.ReplaceAll(v, "/", "-")
	v = strings.ReplaceAll(v, "_", "-")
	for strings.Contains(v, "--") {
		v = strings.ReplaceAll(v, "--", "-")
	}
	return strings.Trim(v, "-")
}

type htmlProjectRow struct {
	Name                 string
	URL                  string
	Visibility           string
	GroupAccessLevel     string
	ProjectAccessLevel   string
	EffectiveAccessLevel string
	InheritedFromGroup   bool
	MembersAccessible    bool
	MembersCount         int
	MemberUsernames      string
	Members              []htmlMemberRow
}

type htmlGroupRow struct {
	Name              string
	URL               string
	Visibility        string
	AccessLevel       string
	MembersAccessible bool
	MembersCount      int
	MemberUsernames   string
	Members           []htmlMemberRow
}

type htmlMemberRow struct {
	Display     string
	AccessLevel string
	URL         string
}

type htmlUserRow struct {
	Name     string
	Username string
	Email    string
	State    string
	URL      string
}

type htmlReportView struct {
	PipeleekLogoPath string
	GitLabURL        string
	GeneratedAt      string
	MinAccessLevel   string
	UserName         string
	UserUsername     string
	UserEmail        string
	TokenName        string
	TokenScopes      string
	UsersCount       int
	GroupsCount      int
	ProjectsCount    int
	UsersEnumerated  bool
	Users            []htmlUserRow
	Groups           []htmlGroupRow
	Projects         []htmlProjectRow
}

const enumReportTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Pipeleek GitLab Enumeration Report</title>
  <style>
    :root {
      --bg: #ffffff;
      --surface: #ffffff;
      --ink: #2b2b2b;
      --muted: #5f6368;
      --line: #e3e6df;
      --accent: #406b36;
      --accent-light: #b9cf7e;
      --accent-dark: #2a4a25;
      --ok: #406b36;
      --warn: #8a5a22;
    }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: "Roboto", "Helvetica Neue", Arial, sans-serif;
      line-height: 1.4;
      padding-top: 4.25rem;
    }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .top-nav {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 1000;
      border-bottom: 1px solid rgba(42, 74, 37, 0.25);
      background: var(--accent);
      color: #ffffff;
      box-shadow: 0 1px 4px rgba(42, 74, 37, 0.18);
    }
    .top-nav-inner {
      max-width: 1200px;
      margin: 0 auto;
      padding: .75rem 1rem;
      display: flex;
      gap: .75rem;
      flex-wrap: wrap;
      align-items: center;
    }
    .top-nav-title {
      color: #ffffff;
      font-weight: 700;
      font-size: 1rem;
      letter-spacing: .01em;
      margin-right: .5rem;
    }
    .top-nav-brand {
      display: inline-flex;
      align-items: center;
      justify-content: flex-start;
      height: 3rem;
      flex: 0 0 auto;
    }
    .top-nav-brand img {
      width: auto;
      height: 3rem;
      display: block;
    }
    .top-nav-link {
      display: inline-block;
      border: 1px solid rgba(255, 255, 255, 0.24);
      background: rgba(255, 255, 255, 0.08);
      color: #ffffff;
      border-radius: 999px;
      padding: .3rem .7rem;
      font-size: .88rem;
      font-weight: 600;
      text-decoration: none;
    }
    .top-nav-link:hover {
      text-decoration: none;
      background: rgba(255, 255, 255, 0.16);
    }
    .top-nav-spacer {
      flex: 1 1 auto;
    }
    .top-nav-toggle {
      appearance: none;
      cursor: pointer;
      font-family: inherit;
    }
    .top-nav-toggle[aria-pressed="true"] {
      background: rgba(255, 255, 255, 0.24);
      border-color: rgba(255, 255, 255, 0.4);
    }
    main { margin: 1rem auto 2rem auto; padding: 0 1rem; }
    .main-default { max-width: 1200px; }
    .main-wide { max-width: calc(100vw - 1rem); }
    h1, h2 { margin: 0 0 .75rem 0; scroll-margin-top: 5.25rem; font-weight: 400; color: #3c4043; }
    h1 { font-size: 2.1rem; }
    h2 { font-size: 1.35rem; }
    .card {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 1rem 1.25rem;
      margin-bottom: 1rem;
      box-shadow: 0 1px 2px rgba(60, 64, 67, 0.1);
    }
    .meta { color: var(--muted); font-size: .95rem; }
    .summary-row {
      margin-top: .55rem;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: .5rem;
      font-size: .98rem;
    }
    .summary-row-label {
      font-weight: 700;
      color: var(--accent-dark);
    }
    .summary-row-value {
      display: inline-flex;
      align-items: center;
      padding: .16rem .55rem;
      border-radius: 999px;
      background: #f3f6ef;
      border: 1px solid #c8d6b2;
      color: var(--accent-dark);
      font-weight: 700;
    }
    .wrap { overflow-wrap: anywhere; word-break: break-word; }
    .kpi { display: inline-block; min-width: 10rem; margin-right: 1rem; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: .45rem .5rem; border-bottom: 1px solid var(--line); }
    td { overflow-wrap: anywhere; }
    th { font-weight: 700; color: var(--muted); }
    .tag { font-weight: 600; padding: .1rem .4rem; border-radius: 999px; font-size: .8rem; }
    .tag-yes { background: #edf3df; color: var(--ok); }
    .tag-no { background: #fff3dd; color: var(--warn); }
    .vis-tag { font-weight: 700; padding: .12rem .48rem; border-radius: 999px; font-size: .78rem; letter-spacing: .02em; text-transform: lowercase; }
    .vis-private { background: #efe7cf; color: #6a4b1f; border: 1px solid #d9c48f; }
    .vis-internal { background: #fff3dd; color: #8a5a22; border: 1px solid #efc77c; }
    .vis-public { background: #edf3df; color: #406b36; border: 1px solid #b9cf7e; }
    .vis-unknown { background: #eef2e7; color: #5a6954; border: 1px solid #d2dec0; }
    .legend { color: var(--muted); font-size: .9rem; }
    .filter-row {
      display: flex;
      gap: .6rem;
      flex-wrap: wrap;
      align-items: end;
      margin: .75rem 0 1rem 0;
    }
    .filter-field {
      min-width: 16rem;
      flex: 1;
    }
    .control-btn {
      appearance: none;
      border: 1px solid #c8d6b2;
      background: #f7f9f4;
      color: var(--accent-dark);
      border-radius: 8px;
      padding: .35rem .65rem;
      cursor: pointer;
      font-size: .9rem;
      font-weight: 600;
    }
    .control-btn:hover {
      background: #eef4e4;
    }
    .back-to-top {
      position: fixed;
      right: 1rem;
      bottom: 1rem;
      z-index: 1001;
      border: 1px solid #2a4a25;
      background: #406b36;
      color: #ffffff;
      border-radius: 999px;
      padding: .45rem .9rem;
      font-size: .85rem;
      font-weight: 700;
      cursor: pointer;
      box-shadow: 0 10px 24px rgba(64, 107, 54, 0.28);
      opacity: 0;
      transform: translateY(8px);
      pointer-events: none;
      transition: opacity 120ms ease-out, transform 120ms ease-out;
    }
    .back-to-top.visible {
      opacity: 1;
      transform: translateY(0);
      pointer-events: auto;
    }
    .back-to-top:hover {
      background: #2a4a25;
    }
    .member-details {
      width: 100%;
    }
    .member-details summary {
      cursor: pointer;
      color: var(--accent-dark);
      font-weight: 600;
      outline: none;
    }
    .member-list {
      margin: .4rem 0 0 0;
      padding-left: 1.1rem;
      color: var(--ink);
    }
    .member-list li {
      margin: .2rem 0;
      display: flex;
      justify-content: space-between;
      gap: .75rem;
    }
    .member-level {
      color: var(--muted);
      font-size: .84rem;
      white-space: nowrap;
    }
    .kpi strong {
      color: var(--accent-dark);
    }
    .summary-row {
      padding: .15rem 0 .4rem 0;
      border-top: 1px solid transparent;
      border-bottom: 1px solid var(--line);
    }
  </style>
</head>
<body>
  <nav class="top-nav" aria-label="Report navigation">
    <div class="top-nav-inner">
      <a class="top-nav-brand" href="#summary-section" aria-label="Pipeleek report top">
        <img src="{{ .PipeleekLogoPath }}" alt="Pipeleek" />
      </a>
      <span class="top-nav-title">Pipeleek</span>
      <a class="top-nav-link" href="#summary-section">Summary</a>
      <a class="top-nav-link" href="#users-section">Users</a>
      <a class="top-nav-link" href="#groups-section">Groups</a>
      <a class="top-nav-link" href="#projects-section">Projects</a>
      <span class="top-nav-spacer"></span>
      <button id="toggle-full-width" class="top-nav-link top-nav-toggle" type="button" aria-pressed="false">Expand cards</button>
    </div>
  </nav>

  <main id="report-main" class="main-default">
    <section class="card" id="summary-section">
      <h1>GitLab Enumeration Report</h1>
      <div class="meta">Target: {{ .GitLabURL }} | Generated: {{ .GeneratedAt }}</div>
      <div class="summary-row">
        <span class="summary-row-label">Minimum access level:</span>
        <span class="summary-row-value">{{ .MinAccessLevel }}</span>
      </div>
      <div style="margin-top:.8rem">
        <span class="kpi"><strong>User:</strong> {{ .UserName }} ({{ .UserUsername }})</span>
        <span class="kpi"><strong>Email:</strong> {{ .UserEmail }}</span>
        <span class="kpi"><strong>Related Users:</strong> {{ .UsersCount }}</span>
        <span class="kpi"><strong>Groups:</strong> {{ .GroupsCount }}</span>
        <span class="kpi"><strong>Projects:</strong> {{ .ProjectsCount }}</span>
      </div>
      <div style="margin-top:.5rem" class="meta"><strong>Token:</strong> {{ .TokenName }} | <strong>Scopes:</strong> <span class="wrap">{{ .TokenScopes }}</span></div>
    </section>

    <section class="card" id="users-section">
      <h2>Users</h2>
      {{ if .UsersEnumerated }}
      <p class="legend">Users are scoped to members discovered from the enumerated groups and projects only.</p>
      <div class="filter-row" id="users-filters">
        <label style="min-width:16rem;flex:1;">
          <span class="legend">Search users</span><br />
          <input id="users-filter-query" type="search" placeholder="username, name, email" class="control-btn" style="width:100%;padding:.35rem .55rem;" />
        </label>
        <button id="users-filter-reset" class="control-btn" type="button">Reset filters</button>
      </div>
      <p id="users-visible-count" class="legend"></p>
      <table>
        <thead>
          <tr><th>User</th><th>Email</th><th>State</th></tr>
        </thead>
        <tbody id="users-tbody">
          {{ range .Users }}
          <tr data-text="{{ lower .Username }} {{ lower .Name }} {{ lower .Email }} {{ lower .State }}">
            <td>
              {{ if .URL }}
              <a href="{{ .URL }}" target="_blank" rel="noopener noreferrer">{{ .Username }}</a>
              {{ else }}
              {{ .Username }}
              {{ end }}
              <div class="legend">{{ .Name }}</div>
            </td>
            <td>{{ .Email }}</td>
            <td>{{ .State }}</td>
          </tr>
          {{ end }}
        </tbody>
      </table>
      {{ else }}
      <p class="legend">Users enrichment is disabled. Run with <strong>--users</strong> to include members from enumerated groups and projects.</p>
      {{ end }}
    </section>

    <section class="card" id="groups-section">
      <h2>Groups</h2>
      <div class="filter-row" id="group-filters">
        <label>
          <span class="legend">Access</span><br />
          <select id="groups-filter-access" class="control-btn" style="padding:.35rem .45rem;">
            <option value="all">All</option>
            <option value="owner">Owner</option>
            <option value="maintainer">Maintainer</option>
            <option value="developer">Developer</option>
            <option value="reporter">Reporter</option>
            <option value="guest">Guest</option>
            <option value="none">No access</option>
          </select>
        </label>
        <label>
          <span class="legend">Visibility</span><br />
          <select id="groups-filter-visibility" class="control-btn" style="padding:.35rem .45rem;">
            <option value="all">All</option>
            <option value="private">Private</option>
            <option value="internal">Internal</option>
            <option value="public">Public</option>
          </select>
        </label>
        <label style="min-width:16rem;flex:1;">
          <span class="legend">Search group</span><br />
          <input id="groups-filter-query" type="search" placeholder="security-team" class="control-btn" style="width:100%;padding:.35rem .55rem;" />
        </label>
        <label class="filter-field">
          <span class="legend">Member username</span><br />
          <input id="groups-filter-username" type="search" placeholder="alice" class="control-btn" style="width:100%;padding:.35rem .55rem;" />
        </label>
        <button id="groups-filter-reset" class="control-btn" type="button">Reset filters</button>
      </div>
      <p id="groups-visible-count" class="legend"></p>
      <table>
        <thead>
          <tr><th>Name</th><th>Visibility</th><th>Access</th><th>Members</th></tr>
        </thead>
        <tbody id="groups-tbody">
          {{ range .Groups }}
          <tr data-access="{{ filterKey .AccessLevel }}" data-visibility="{{ filterKey .Visibility }}" data-text="{{ lower .Name }} {{ lower .URL }}" data-members="{{ lower .MemberUsernames }}">
            <td><a href="{{ .URL }}" target="_blank" rel="noopener noreferrer">{{ .Name }}</a></td>
            <td><span class="vis-tag {{ visibilityClass .Visibility }}">{{ visibilityText .Visibility }}</span></td>
            <td>{{ .AccessLevel }}</td>
            <td>
              {{ if .MembersAccessible }}
              <details class="member-details">
                <summary>{{ .MembersCount }} member(s)</summary>
                {{ if .Members }}
                <ul class="member-list">
                  {{ range .Members }}
                  <li>
                    {{ if .URL }}
                    <a href="{{ .URL }}" target="_blank" rel="noopener noreferrer">{{ .Display }}</a>
                    {{ else }}
                    <span>{{ .Display }}</span>
                    {{ end }}
                    <span class="member-level">{{ .AccessLevel }}</span>
                  </li>
                  {{ end }}
                </ul>
                {{ else }}
                <div class="legend">No members returned by API.</div>
                {{ end }}
              </details>
              {{ else }}
              N/A
              {{ end }}
            </td>
          </tr>
          {{ end }}
        </tbody>
      </table>
    </section>

    <section class="card" id="projects-section">
      <h2>Projects</h2>
      <p class="legend">Inherited means direct project membership is lower than group membership and effective access comes from group scope.</p>
      <div class="filter-row" id="project-filters">
        <label>
          <span class="legend">Effective access</span><br />
          <select id="projects-filter-effective" class="control-btn" style="padding:.35rem .45rem;">
            <option value="all">All</option>
            <option value="owner">Owner</option>
            <option value="maintainer">Maintainer</option>
            <option value="developer">Developer</option>
            <option value="reporter">Reporter</option>
            <option value="guest">Guest</option>
            <option value="none">No access</option>
          </select>
        </label>
        <label>
          <span class="legend">Visibility</span><br />
          <select id="projects-filter-visibility" class="control-btn" style="padding:.35rem .45rem;">
            <option value="all">All</option>
            <option value="private">Private</option>
            <option value="internal">Internal</option>
            <option value="public">Public</option>
          </select>
        </label>
        <label>
          <span class="legend">Inherited</span><br />
          <select id="projects-filter-inherited" class="control-btn" style="padding:.35rem .45rem;">
            <option value="all">All</option>
            <option value="yes">Yes</option>
            <option value="no">No</option>
          </select>
        </label>
        <label style="min-width:16rem;flex:1;">
          <span class="legend">Search project</span><br />
          <input id="projects-filter-query" type="search" placeholder="security-tools" class="control-btn" style="width:100%;padding:.35rem .55rem;" />
        </label>
        <label class="filter-field">
          <span class="legend">Member username</span><br />
          <input id="projects-filter-username" type="search" placeholder="alice" class="control-btn" style="width:100%;padding:.35rem .55rem;" />
        </label>
        <button id="projects-filter-reset" class="control-btn" type="button">Reset filters</button>
      </div>
      <p id="projects-visible-count" class="legend"></p>
      <table>
        <thead>
          <tr><th>Name</th><th>Visibility</th><th>Group access</th><th>Project access</th><th>Effective access</th><th>Inherited</th><th>Members</th></tr>
        </thead>
        <tbody id="projects-tbody">
          {{ range .Projects }}
          <tr data-effective="{{ filterKey .EffectiveAccessLevel }}" data-visibility="{{ filterKey .Visibility }}" data-inherited="{{ if .InheritedFromGroup }}yes{{ else }}no{{ end }}" data-text="{{ lower .Name }} {{ lower .URL }}" data-members="{{ lower .MemberUsernames }}">
            <td><a href="{{ .URL }}" target="_blank" rel="noopener noreferrer">{{ .Name }}</a></td>
            <td><span class="vis-tag {{ visibilityClass .Visibility }}">{{ visibilityText .Visibility }}</span></td>
            <td>{{ .GroupAccessLevel }}</td>
            <td>{{ .ProjectAccessLevel }}</td>
            <td>{{ .EffectiveAccessLevel }}</td>
            <td>
              {{ if .InheritedFromGroup }}
              <span class="tag tag-yes">yes</span>
              {{ else }}
              <span class="tag tag-no">no</span>
              {{ end }}
            </td>
            <td>
              {{ if .MembersAccessible }}
              <details class="member-details">
                <summary>{{ .MembersCount }} member(s)</summary>
                {{ if .Members }}
                <ul class="member-list">
                  {{ range .Members }}
                  <li>
                    {{ if .URL }}
                    <a href="{{ .URL }}" target="_blank" rel="noopener noreferrer">{{ .Display }}</a>
                    {{ else }}
                    <span>{{ .Display }}</span>
                    {{ end }}
                    <span class="member-level">{{ .AccessLevel }}</span>
                  </li>
                  {{ end }}
                </ul>
                {{ else }}
                <div class="legend">No members returned by API.</div>
                {{ end }}
              </details>
              {{ else }}
              N/A
              {{ end }}
            </td>
          </tr>
          {{ end }}
        </tbody>
      </table>
    </section>
  </main>

  <button id="back-to-top" class="back-to-top" type="button" aria-label="Back to top">Top</button>

  <script>
    const backToTopBtn = document.getElementById('back-to-top');
    const reportMain = document.getElementById('report-main');
    const toggleFullWidthBtn = document.getElementById('toggle-full-width');
    const usersTableBody = document.getElementById('users-tbody');
    const usersFilterQuery = document.getElementById('users-filter-query');
    const usersFilterReset = document.getElementById('users-filter-reset');
    const usersVisibleCount = document.getElementById('users-visible-count');

    const groupsTableBody = document.getElementById('groups-tbody');
    const groupsFilterAccess = document.getElementById('groups-filter-access');
    const groupsFilterVisibility = document.getElementById('groups-filter-visibility');
    const groupsFilterQuery = document.getElementById('groups-filter-query');
    const groupsFilterUsername = document.getElementById('groups-filter-username');
    const groupsFilterReset = document.getElementById('groups-filter-reset');
    const groupsVisibleCount = document.getElementById('groups-visible-count');

    const projectsTableBody = document.getElementById('projects-tbody');
    const projectsFilterEffective = document.getElementById('projects-filter-effective');
    const projectsFilterVisibility = document.getElementById('projects-filter-visibility');
    const projectsFilterInherited = document.getElementById('projects-filter-inherited');
    const projectsFilterQuery = document.getElementById('projects-filter-query');
    const projectsFilterUsername = document.getElementById('projects-filter-username');
    const projectsFilterReset = document.getElementById('projects-filter-reset');
    const projectsVisibleCount = document.getElementById('projects-visible-count');

    const rows = (tbody) => Array.from(tbody?.querySelectorAll('tr') || []);
    const normalize = (v) => (v || '').trim().toLowerCase();

    const setFullWidth = (enabled) => {
      if (!reportMain || !toggleFullWidthBtn) {
        return;
      }
      reportMain.classList.toggle('main-wide', enabled);
      reportMain.classList.toggle('main-default', !enabled);
      toggleFullWidthBtn.setAttribute('aria-pressed', enabled ? 'true' : 'false');
      toggleFullWidthBtn.textContent = enabled ? 'Use normal width' : 'Expand cards';
    };

    const matchesAccessLike = (value, filterValue) => {
      if (filterValue === 'all') {
        return true;
      }
      if (filterValue === 'none') {
        return value === 'no-access' || value === 'unknown';
      }
      return value === filterValue;
    };

    const setVisibleCount = (el, label, visible, total) => {
      if (!el) {
        return;
      }
      el.textContent = label + ': ' + visible + ' / ' + total;
    };

    const matchesMemberUsername = (rowMembers, filterValue) => {
      if (filterValue === '') {
        return true;
      }
      return rowMembers.includes(filterValue);
    };

    const applyUsersFilters = () => {
      const query = normalize(usersFilterQuery?.value);

      const items = rows(usersTableBody);
      let visible = 0;
      for (const row of items) {
        const rowText = row.dataset.text || '';
        const show = query === '' || rowText.includes(query);

        row.style.display = show ? '' : 'none';
        if (show) {
          visible += 1;
        }
      }

      setVisibleCount(usersVisibleCount, 'Visible users', visible, items.length);
    };

    const applyGroupsFilters = () => {
      const access = groupsFilterAccess?.value || 'all';
      const visibility = groupsFilterVisibility?.value || 'all';
      const query = normalize(groupsFilterQuery?.value);
      const username = normalize(groupsFilterUsername?.value);

      const items = rows(groupsTableBody);
      let visible = 0;
      for (const row of items) {
        const rowAccess = row.dataset.access || '';
        const rowVisibility = row.dataset.visibility || '';
        const rowText = row.dataset.text || '';
        const rowMembers = row.dataset.members || '';
        const details = row.querySelector('details.member-details');

        const show = matchesAccessLike(rowAccess, access) &&
          (visibility === 'all' || visibility === rowVisibility) &&
          (query === '' || rowText.includes(query)) &&
          matchesMemberUsername(rowMembers, username);

        row.style.display = show ? '' : 'none';
        if (details) {
          details.open = show && username !== '' && rowMembers.includes(username);
        }
        if (show) {
          visible += 1;
        }
      }

      setVisibleCount(groupsVisibleCount, 'Visible groups', visible, items.length);
    };

    const applyProjectsFilters = () => {
      const effective = projectsFilterEffective?.value || 'all';
      const visibility = projectsFilterVisibility?.value || 'all';
      const inherited = projectsFilterInherited?.value || 'all';
      const query = normalize(projectsFilterQuery?.value);
      const username = normalize(projectsFilterUsername?.value);

      const items = rows(projectsTableBody);
      let visible = 0;
      for (const row of items) {
        const rowEffective = row.dataset.effective || '';
        const rowVisibility = row.dataset.visibility || '';
        const rowInherited = row.dataset.inherited || '';
        const rowText = row.dataset.text || '';
        const rowMembers = row.dataset.members || '';
        const details = row.querySelector('details.member-details');

        const show = matchesAccessLike(rowEffective, effective) &&
          (visibility === 'all' || visibility === rowVisibility) &&
          (inherited === 'all' || inherited === rowInherited) &&
          (query === '' || rowText.includes(query)) &&
          matchesMemberUsername(rowMembers, username);

        row.style.display = show ? '' : 'none';
        if (details) {
          details.open = show && username !== '' && rowMembers.includes(username);
        }
        if (show) {
          visible += 1;
        }
      }

      setVisibleCount(projectsVisibleCount, 'Visible projects', visible, items.length);
    };

    groupsFilterAccess?.addEventListener('change', applyGroupsFilters);
    groupsFilterVisibility?.addEventListener('change', applyGroupsFilters);
    groupsFilterQuery?.addEventListener('input', applyGroupsFilters);
    groupsFilterUsername?.addEventListener('input', applyGroupsFilters);

    usersFilterQuery?.addEventListener('input', applyUsersFilters);
    usersFilterReset?.addEventListener('click', () => {
      if (usersFilterQuery) {
        usersFilterQuery.value = '';
      }
      applyUsersFilters();
    });

    groupsFilterReset?.addEventListener('click', () => {
      if (groupsFilterAccess) {
        groupsFilterAccess.value = 'all';
      }
      if (groupsFilterVisibility) {
        groupsFilterVisibility.value = 'all';
      }
      if (groupsFilterQuery) {
        groupsFilterQuery.value = '';
      }
      if (groupsFilterUsername) {
        groupsFilterUsername.value = '';
      }
      applyGroupsFilters();
    });

    projectsFilterEffective?.addEventListener('change', applyProjectsFilters);
    projectsFilterVisibility?.addEventListener('change', applyProjectsFilters);
    projectsFilterInherited?.addEventListener('change', applyProjectsFilters);
    projectsFilterQuery?.addEventListener('input', applyProjectsFilters);
    projectsFilterUsername?.addEventListener('input', applyProjectsFilters);
    projectsFilterReset?.addEventListener('click', () => {
      if (projectsFilterEffective) {
        projectsFilterEffective.value = 'all';
      }
      if (projectsFilterVisibility) {
        projectsFilterVisibility.value = 'all';
      }
      if (projectsFilterInherited) {
        projectsFilterInherited.value = 'all';
      }
      if (projectsFilterQuery) {
        projectsFilterQuery.value = '';
      }
      if (projectsFilterUsername) {
        projectsFilterUsername.value = '';
      }
      applyProjectsFilters();
    });

    const updateBackToTopVisibility = () => {
      if (!backToTopBtn) {
        return;
      }
      const shouldShow = window.scrollY > 220;
      backToTopBtn.classList.toggle('visible', shouldShow);
    };

    backToTopBtn?.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    window.addEventListener('scroll', updateBackToTopVisibility, { passive: true });

    toggleFullWidthBtn?.addEventListener('click', () => {
      const enabled = !reportMain?.classList.contains('main-wide');
      setFullWidth(Boolean(enabled));
    });

    applyUsersFilters();
    applyGroupsFilters();
    applyProjectsFilters();
    setFullWidth(false);
    updateBackToTopVisibility();
  </script>
</body>
</html>`

// WriteHTMLReport writes a standalone HTML report for the current enum result.
func WriteHTMLReport(result *EnumResult, outputPath string) error {
	cleanOutputPath := filepath.Clean(outputPath)

	view := htmlReportView{
		PipeleekLogoPath: logoPathForReport(cleanOutputPath),
		GitLabURL:        result.GitLabURL,
		GeneratedAt:      result.GeneratedAt.Format("2006-01-02T15:04:05Z"),
		MinAccessLevel:   util.AccessLevelName(gitlab.AccessLevelValue(result.MinAccessLevel)),
		UsersEnumerated:  result.UsersEnumerated,
		UsersCount:       len(result.Users),
		GroupsCount:      len(result.Associations.Groups),
		ProjectsCount:    len(result.Associations.Projects),
	}

	if result.User != nil {
		view.UserName = result.User.Name
		view.UserUsername = result.User.Username
		view.UserEmail = result.User.Email
	}
	if result.Token != nil {
		view.TokenName = result.Token.Name
		view.TokenScopes = strings.Join(result.Token.Scopes, ", ")
	}

	groups := make([]htmlGroupRow, 0, len(result.Associations.Groups))
	for _, group := range result.Associations.Groups {
		members := make([]htmlMemberRow, 0, len(group.Members))
		memberUsernames := make([]string, 0, len(group.Members))
		for _, member := range group.Members {
			members = append(members, htmlMemberRow{
				Display:     memberDisplayName(member),
				AccessLevel: util.AccessLevelName(gitlab.AccessLevelValue(member.AccessLevel)),
				URL:         member.WebURL,
			})
			if strings.TrimSpace(member.Username) != "" {
				memberUsernames = append(memberUsernames, member.Username)
			}
		}

		groups = append(groups, htmlGroupRow{
			Name:              group.Name,
			URL:               group.WebURL,
			Visibility:        group.Visibility,
			AccessLevel:       util.AccessLevelName(gitlab.AccessLevelValue(group.AccessLevels)),
			MembersAccessible: group.MembersAccessible,
			MembersCount:      group.MemberCount,
			MemberUsernames:   strings.Join(memberUsernames, " "),
			Members:           members,
		})
	}
	view.Groups = groups

	projects := make([]htmlProjectRow, 0, len(result.Associations.Projects))
	for _, project := range result.Associations.Projects {
		effective, inherited := effectiveProjectAccessLevels(project.AccessLevels.GroupAccessLevel, project.AccessLevels.ProjectAccessLevel)
		members := make([]htmlMemberRow, 0, len(project.Members))
		memberUsernames := make([]string, 0, len(project.Members))
		for _, member := range project.Members {
			members = append(members, htmlMemberRow{
				Display:     memberDisplayName(member),
				AccessLevel: util.AccessLevelName(gitlab.AccessLevelValue(member.AccessLevel)),
				URL:         member.WebURL,
			})
			if strings.TrimSpace(member.Username) != "" {
				memberUsernames = append(memberUsernames, member.Username)
			}
		}

		projects = append(projects, htmlProjectRow{
			Name:                 project.NameWithNamespace,
			URL:                  project.WebURL,
			Visibility:           project.Visibility,
			GroupAccessLevel:     util.AccessLevelName(gitlab.AccessLevelValue(project.AccessLevels.GroupAccessLevel)),
			ProjectAccessLevel:   util.AccessLevelName(gitlab.AccessLevelValue(project.AccessLevels.ProjectAccessLevel)),
			EffectiveAccessLevel: util.AccessLevelName(gitlab.AccessLevelValue(effective)),
			InheritedFromGroup:   inherited,
			MembersAccessible:    project.MembersAccessible,
			MembersCount:         project.MemberCount,
			MemberUsernames:      strings.Join(memberUsernames, " "),
			Members:              members,
		})
	}
	view.Projects = projects

	users := make([]htmlUserRow, 0, len(result.Users))
	for _, user := range result.Users {
		if user == nil {
			continue
		}
		users = append(users, htmlUserRow{
			Name:     user.Name,
			Username: user.Username,
			Email:    chooseUserEmail(user),
			State:    user.State,
			URL:      user.WebURL,
		})
	}
	view.Users = users

	funcs := template.FuncMap{
		"visibilityClass": visibilityClass,
		"visibilityText":  visibilityText,
		"lower":           strings.ToLower,
		"filterKey":       filterKey,
	}
	tpl, err := template.New("enum-report").Funcs(funcs).Parse(enumReportTemplate)
	if err != nil {
		return err
	}

	if dir := filepath.Dir(cleanOutputPath); dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return err
		}
	}

	// #nosec G304 -- cleanOutputPath is an explicit user-selected report destination provided via CLI/config.
	f, err := os.OpenFile(cleanOutputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	return tpl.Execute(f, view)
}

func visibilityClass(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "private":
		return "vis-private"
	case "internal":
		return "vis-internal"
	case "public":
		return "vis-public"
	default:
		return "vis-unknown"
	}
}

func visibilityText(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "unknown"
	}
	return v
}

func chooseUserEmail(user *gitlab.User) string {
	if user == nil {
		return ""
	}
	if strings.TrimSpace(user.Email) != "" {
		return user.Email
	}
	return user.PublicEmail
}

func memberDisplayName(member TokenAssociationMember) string {
	if strings.TrimSpace(member.Username) != "" {
		if strings.TrimSpace(member.Name) != "" {
			return member.Username + " (" + member.Name + ")"
		}
		return member.Username
	}
	if strings.TrimSpace(member.Name) != "" {
		return member.Name
	}
	if strings.TrimSpace(member.Email) != "" {
		return member.Email
	}
	return "user-" + strconv.FormatInt(member.ID, 10)
}

func logoPathForReport(outputPath string) string {
	const fallbackLogoPath = "docs/pipeleek-anim.svg"

	repoDir, err := os.Getwd()
	if err != nil {
		return fallbackLogoPath
	}

	reportDir := filepath.Dir(outputPath)
	logoAbsPath := filepath.Join(repoDir, "docs", "pipeleek-anim.svg")
	logoRelPath, err := filepath.Rel(reportDir, logoAbsPath)
	if err != nil {
		return fallbackLogoPath
	}

	return filepath.ToSlash(logoRelPath)
}
