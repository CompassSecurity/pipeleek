package webui

import (
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	gitlabenum "github.com/CompassSecurity/pipeleek/pkg/gitlab/enum"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	zerologlog "github.com/rs/zerolog/log"
)

type Finding struct {
	ID         string            `json:"id"`
	Time       string            `json:"time"`
	Type       string            `json:"type"`
	Confidence string            `json:"confidence"`
	RuleName   string            `json:"ruleName"`
	Value      string            `json:"value"`
	URL        string            `json:"url,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
}

type Server struct {
	mu       sync.RWMutex
	findings []Finding
	clients  map[chan string]struct{}
	token    string
	port     string
	url      string
	server   *http.Server
	done     chan struct{}
	once     sync.Once
}

var pageTemplate = strings.Join([]string{
	"<!doctype html>",
	"<html lang=\"en\">",
	"<head>",
	"  <meta charset=\"utf-8\" />",
	"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />",
	"  <title>Pipeleek Findings</title>",
	"  <style>",
	"    :root {",
	"      --bg: #ffffff;",
	"      --surface: #ffffff;",
	"      --ink: #2b2b2b;",
	"      --muted: #5f6368;",
	"      --line: #e3e6df;",
	"      --accent: #406b36;",
	"      --accent-light: #b9cf7e;",
	"      --accent-dark: #2a4a25;",
	"      --low: #d7a785;",
	"      --medium: #c69a2a;",
	"      --high: #d96f46;",
	"      --verified: #a4b97f;",
	"      --danger: #d64b4b;",
	"    }",
	"    * { box-sizing: border-box; }",
	"    html { scroll-behavior: smooth; }",
	"    body {",
	"      margin: 0;",
	"      background: var(--bg);",
	"      color: var(--ink);",
	"      font-family: \"Roboto\", \"Helvetica Neue\", Arial, sans-serif;",
	"      line-height: 1.45;",
	"      padding-top: 4.25rem;",
	"    }",
	"    a { color: var(--accent); text-decoration: none; }",
	"    a:hover { text-decoration: underline; }",
	"    .top-nav {",
	"      position: fixed;",
	"      top: 0; left: 0; right: 0;",
	"      z-index: 1000;",
	"      border-bottom: 1px solid rgba(42, 74, 37, 0.25);",
	"      background: var(--accent);",
	"      color: #ffffff;",
	"      box-shadow: 0 1px 4px rgba(42, 74, 37, 0.18);",
	"    }",
	"    .top-nav-inner {",
	"      max-width: 1200px;",
	"      margin: 0 auto;",
	"      padding: .75rem 1rem;",
	"      display: flex;",
	"      gap: .75rem;",
	"      align-items: center;",
	"      flex-wrap: wrap;",
	"    }",
	"    .top-nav-brand {",
	"      display: inline-flex;",
	"      align-items: center;",
	"      justify-content: flex-start;",
	"      height: 2.1rem;",
	"      flex: 0 0 auto;",
	"      overflow: hidden;",
	"    }",
	"    .top-nav-brand svg {",
	"      width: auto !important;",
	"      height: 2.1rem !important;",
	"      max-height: 2.1rem !important;",
	"      display: block;",
	"    }",
	"    .top-nav-title {",
	"      color: #ffffff;",
	"      font-weight: 700;",
	"      font-size: 1rem;",
	"      letter-spacing: .01em;",
	"      margin-right: .5rem;",
	"    }",
	"    .top-nav-link {",
	"      display: inline-block;",
	"      border: 1px solid rgba(255,255,255,.24);",
	"      background: rgba(255,255,255,.08);",
	"      color: #fff;",
	"      border-radius: 999px;",
	"      padding: .3rem .7rem;",
	"      font-size: .88rem;",
	"      font-weight: 600;",
	"      text-decoration: none;",
	"    }",
	"    .top-nav-link:hover { text-decoration: none; background: rgba(255,255,255,.16); }",
	"    .top-nav-toggle { appearance: none; cursor: pointer; font-family: inherit; }",
	"    .top-nav-toggle[aria-pressed=\"true\"] { background: rgba(255,255,255,.24); border-color: rgba(255,255,255,.4); }",
	"    .top-nav-spacer { flex: 1 1 auto; }",
	"    main { max-width: 1200px; margin: 1rem auto 2rem; padding: 0 1rem; }",
	"    main.main-wide { max-width: calc(100vw - 1rem); }",
	"    .card {",
	"      background: var(--surface);",
	"      min-width: 0;",
	"      border: 1px solid var(--line);",
	"      border-radius: 12px;",
	"      padding: 1rem 1.25rem;",
	"      margin-bottom: 1rem;",
	"      box-shadow: 0 1px 2px rgba(60, 64, 67, 0.1);",
	"    }",
	"    .row { display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; justify-content: space-between; }",
	"    h1 { margin: 0; font-size: 2rem; font-weight: 400; color: #3c4043; }",
	"    .status { display: inline-flex; align-items: center; gap: .45rem; border-radius: 999px; padding: .35rem .75rem; border: 1px solid var(--line); background: #f3f5ef; font-size: .85rem; font-weight: 600; }",
	"    .dot { width: .6rem; height: .6rem; border-radius: 50%; background: #4cae5d; display: inline-block; }",
	"    .dot.offline { background: var(--danger); }",
	"    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: .75rem; }",
	"    .metric { border: 1px solid var(--line); border-radius: 10px; padding: .75rem; background: linear-gradient(180deg, #fff, #f7f9f5); }",
	"    .metric strong { display: block; font-size: 1.45rem; line-height: 1.2; margin-top: .15rem; }",
	"    .metric label { color: var(--muted); font-size: .8rem; }",
	"    .filters { display: flex; flex-wrap: wrap; gap: .75rem; align-items: end; }",
	"    .filter-field { display: flex; flex-direction: column; gap: .35rem; min-width: 150px; }",
	"    .filter-field label { color: var(--muted); font-size: .8rem; font-weight: 600; }",
	"    .filter-picker { position: relative; min-width: 10rem; }",
	"    .filter-trigger { display: flex; align-items: center; justify-content: space-between; gap: .6rem; width: 100%; min-height: 2.4rem; border: 1px solid #c8d6b2; border-radius: 8px; background: #f7f9f4; padding: .35rem .55rem; color: var(--ink); cursor: pointer; text-align: left; }",
	"    .filter-trigger:hover, .filter-trigger[aria-expanded=\"true\"] { background: #edf4e8; }",
	"    .filter-selected { display: flex; align-items: center; gap: .25rem; flex-wrap: wrap; min-width: 0; }",
	"    .filter-options { position: absolute; top: calc(100% + .25rem); left: 0; z-index: 1100; display: grid; gap: .15rem; min-width: 100%; width: max-content; max-width: min(18rem, calc(100vw - 2rem)); padding: .3rem; border: 1px solid var(--line); border-radius: 8px; background: #fff; box-shadow: 0 6px 18px rgba(42,74,37,.16); }",
	"    .filter-options[hidden] { display: none; }",
	"    .filter-option { display: flex; align-items: center; gap: .5rem; width: 100%; border: 0; border-radius: 6px; padding: .38rem .45rem; background: transparent; cursor: pointer; text-align: left; }",
	"    .filter-option:hover, .filter-option[aria-selected=\"true\"], .filter-option:focus-visible { background: #f1f5ed; outline: none; }",
	"    .filter-check { width: .9rem; height: .9rem; flex: 0 0 .9rem; border: 1px solid #9da797; border-radius: 3px; background: #fff; }",
	"    .filter-option[aria-selected=\"true\"] .filter-check { border-color: var(--accent); background: var(--accent); box-shadow: inset 0 0 0 2px #fff; }",
	"    .filter-chevron { width: .45rem; height: .45rem; flex: 0 0 auto; border-right: 2px solid currentColor; border-bottom: 2px solid currentColor; transform: rotate(45deg) translateY(-2px); }",
	"    .control-btn, select, input { border: 1px solid #c8d6b2; border-radius: 8px; background: #f7f9f4; padding: .45rem .65rem; font: inherit; color: var(--ink); }",
	"    .control-btn:hover { background: #edf4e8; }",
	"    table { width: 100%; max-width: 100%; border-collapse: collapse; table-layout: fixed; }",
	"    th, td { min-width: 0; text-align: left; padding: .8rem .7rem; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; word-break: break-word; }",
	"    th { font-size: .8rem; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; color: var(--muted); }",
	"    .badge { display: inline-block; padding: .18rem .5rem; border-radius: 999px; font-size: .8rem; font-weight: 700; letter-spacing: .02em; white-space: nowrap; }",
	"    .badge.low { background: rgba(215,167,133,.18); color: #7d4d2d; }",
	"    .badge.medium { background: rgba(198,154,42,.18); color: #72560d; }",
	"    .badge.high { background: rgba(217,111,70,.18); color: #8d3d1f; }",
	"    .badge.high-verified { background: rgba(164,185,127,.24); color: var(--accent-dark); }",
	"    .badge.unknown { background: rgba(95,99,104,.12); color: var(--muted); }",
	"    .badge.all { background: rgba(95,99,104,.12); color: var(--muted); }",
	"    .badge.type-log { background: rgba(95,99,104,.12); color: #3f454a; }",
	"    .badge.type-archive { background: rgba(64,107,54,.12); color: var(--accent-dark); }",
	"    .badge.type-nested-archive { background: rgba(64,107,54,.18); color: var(--accent-dark); }",
	"    .badge.type-dotenv { background: rgba(123,136,180,.14); color: #405089; }",
	"    .secret { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; white-space: pre-wrap; background: #f7f7f7; border: 1px solid var(--line); border-radius: 6px; padding: .45rem .5rem; display: block; width: 100%; min-width: 0; color: var(--ink); cursor: pointer; transition: border-color .15s ease, background-color .15s ease; }",
	"    .secret:hover { border-color: rgba(64,107,54,.5); background: #f1f6eb; }",
	"    .secret:active { transform: translateY(1px); }",
	"    .muted { color: var(--muted); }",
	"    .details-list { margin: 0; padding-left: 1rem; }",
	"    .details-list a { text-decoration: underline; }",
	"    table th:nth-child(1), table td:nth-child(1) { width: 14%; }",
	"    table th:nth-child(2), table td:nth-child(2) { width: 15%; }",
	"    table th:nth-child(3), table td:nth-child(3) { width: 26%; }",
	"    table th:nth-child(4), table td:nth-child(4) { width: 12%; }",
	"    table th:nth-child(5), table td:nth-child(5) { width: 19%; }",
	"    table th:nth-child(6), table td:nth-child(6) { width: 14%; }",
	"    .details-list li, .details-list a { overflow-wrap: anywhere; word-break: break-word; }",
	"    .findings-table-card { overflow: hidden; }",
	"    #toast { position: fixed; right: 1rem; bottom: 1rem; background: rgba(42,74,37,.96); color: #fff; padding: .7rem .9rem; border-radius: 999px; font-size: .84rem; box-shadow: 0 8px 20px rgba(0,0,0,.2); opacity: 0; pointer-events: none; transform: translateY(8px); transition: opacity .18s ease, transform .18s ease; z-index: 2000; }",
	"    #toast.visible { opacity: 1; transform: translateY(0); }",
	"    @media (max-width: 720px) { main { padding: 0 .5rem; } .top-nav-inner { padding: .6rem .75rem; } h1 { font-size: 1.6rem; } }",
	"  </style>",
	"</head>",
	"<body>",
	"  <nav class=\"top-nav\">",
	"    <div class=\"top-nav-inner\">",
	"      <a class=\"top-nav-brand\" href=\"#top\" aria-label=\"Pipeleek findings top\">",
	"        {{.PipeleekLogo}}",
	"      </a>",
	"      <div class=\"top-nav-spacer\"></div>",
	"      <button id=\"toggle-full-width\" class=\"top-nav-link top-nav-toggle\" type=\"button\" aria-pressed=\"false\">Full width</button>",
	"      <a class=\"top-nav-link\" href=\"/api/findings\" target=\"_blank\" rel=\"noopener noreferrer\">JSON</a>",
	"    </div>",
	"  </nav>",
	"  <main id=\"top\" class=\"main-default\">",
	"    <div class=\"card\">",
	"      <div class=\"row\">",
	"        <h1 style=\"margin:0; font-weight:400; font-size:2rem;\">Live secret findings</h1>",
	"        <div class=\"status\"><span class=\"dot\" id=\"connection-dot\"></span><span id=\"connection-state\">connecting</span></div>",
	"      </div>",
	"    </div>",
	"    <div class=\"card summary\" id=\"summary-cards\"></div>",
	"    <div class=\"card\">",
	"      <div class=\"filters\">",
	"        <div class=\"filter-field\">",
	"          <label id=\"severity-filter-label\">Severity</label>",
	"          <input id=\"severity-filter\" type=\"hidden\" value=\"all\" />",
	"          <div class=\"filter-picker\" id=\"severity-picker\">",
	"            <button class=\"filter-trigger\" id=\"severity-trigger\" type=\"button\" aria-haspopup=\"listbox\" aria-expanded=\"false\" aria-controls=\"severity-options\" aria-labelledby=\"severity-filter-label severity-selected\"><span class=\"filter-selected\" id=\"severity-selected\"></span><span class=\"filter-chevron\" aria-hidden=\"true\"></span></button>",
	"            <div class=\"filter-options\" id=\"severity-options\" role=\"listbox\" aria-multiselectable=\"true\" aria-labelledby=\"severity-filter-label\" hidden>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"all\" aria-selected=\"true\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge all\">all</span></div>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"high-verified\" aria-selected=\"false\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge high-verified\">high-verified</span></div>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"high\" aria-selected=\"false\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge high\">high</span></div>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"medium\" aria-selected=\"false\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge medium\">medium</span></div>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"low\" aria-selected=\"false\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge low\">low</span></div>",
	"            </div>",
	"          </div>",
	"        </div>",
	"        <div class=\"filter-field\">",
	"          <label id=\"type-filter-label\">Type</label>",
	"          <input id=\"type-filter\" type=\"hidden\" value=\"all\" />",
	"          <div class=\"filter-picker\" id=\"type-picker\">",
	"            <button class=\"filter-trigger\" id=\"type-trigger\" type=\"button\" aria-haspopup=\"listbox\" aria-expanded=\"false\" aria-controls=\"type-options\" aria-labelledby=\"type-filter-label type-selected\"><span class=\"filter-selected\" id=\"type-selected\"></span><span class=\"filter-chevron\" aria-hidden=\"true\"></span></button>",
	"            <div class=\"filter-options\" id=\"type-options\" role=\"listbox\" aria-multiselectable=\"true\" aria-labelledby=\"type-filter-label\" hidden>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"all\" aria-selected=\"true\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge all\">all</span></div>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"log\" aria-selected=\"false\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge type-log\">log</span></div>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"archive\" aria-selected=\"false\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge type-archive\">archive</span></div>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"nested-archive\" aria-selected=\"false\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge type-nested-archive\">nested-archive</span></div>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"dotenv\" aria-selected=\"false\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge type-dotenv\">dotenv</span></div>",
	"            </div>",
	"          </div>",
	"        </div>",
	"        <div class=\"filter-field\" style=\"flex:1; min-width:220px;\">",
	"          <label for=\"search-filter\">Search</label>",
	"          <input id=\"search-filter\" type=\"search\" placeholder=\"rule, secret, url, job, build\" />",
	"        </div>",
	"        <button class=\"control-btn\" id=\"reset-filters\" type=\"button\">Reset</button>",
	"        <button class=\"control-btn\" id=\"export-csv\" type=\"button\">Export CSV</button>",
	"      </div>",
	"    </div>",
	"    <div class=\"card findings-table-card\">",
	"      <table>",
	"        <thead><tr><th>Severity</th><th>Rule</th><th>Secret</th><th>Type</th><th>Details</th><th>Time</th></tr></thead>",
	"        <tbody id=\"findings-body\"></tbody>",
	"      </table>",
	"    </div>",
	"  </main>",
	"  <div id=\"toast\" aria-live=\"polite\">Secret copied to clipboard</div>",
	"  <script>",
	"    const state = { all: [], severity: ['all'], type: ['all'], search: '' };",
	"    const severityFilter = document.getElementById('severity-filter');",
	"    const typeFilter = document.getElementById('type-filter');",
	"    const searchFilter = document.getElementById('search-filter');",
	"    const resetButton = document.getElementById('reset-filters');",
	"    const exportCSVButton = document.getElementById('export-csv');",
	"    const tableBody = document.getElementById('findings-body');",
	"    const summaryCards = document.getElementById('summary-cards');",
	"    const connectionState = document.getElementById('connection-state');",
	"    const connectionDot = document.getElementById('connection-dot');",
	"    const toast = document.getElementById('toast');",
	"    const normalize = function(value) { return (value || '').toLowerCase(); };",
	"    function severityClass(value) { return String(value || 'unknown').toLowerCase().replace(/\\s+/g, '-'); }",
	"    function typeClass(value) { return String(value || 'log').toLowerCase().replace(/\\s+/g, '-'); }",
	"    function showToast(message) { toast.textContent = message; toast.classList.add('visible'); clearTimeout(showToast.timeout); showToast.timeout = setTimeout(function() { toast.classList.remove('visible'); }, 1200); }",
	"    function formatTimestamp(value) {",
	"      if (!value) return '—';",
	"      var date = new Date(value);",
	"      if (Number.isNaN(date.getTime())) return value;",
	"      return date.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });",
	"    }",
	"    function renderSummary() {",
	"      var counts = { low: 0, medium: 0, high: 0, 'high-verified': 0 };",
	"      state.all.forEach(function(item) { var key = normalize(item.confidence || 'unknown'); if (key in counts) counts[key] += 1; });",
	"      var cards = ['high-verified', 'high', 'medium', 'low'].map(function(key) { var label = key.charAt(0).toUpperCase() + key.slice(1); return '<div class=\"metric\"><label>' + label + '</label><strong>' + (counts[key] || 0) + '</strong></div>'; }).join('');",
	"      summaryCards.innerHTML = cards;",
	"    }",
	"    function filteredFindings() {",
	"      var query = normalize(searchFilter.value);",
	"      return state.all.filter(function(item) { var severity = normalize(item.confidence); var kind = normalize(item.type); var matchesSeverity = state.severity.indexOf('all') >= 0 || state.severity.indexOf(severity) >= 0; var matchesType = state.type.indexOf('all') >= 0 || state.type.indexOf(kind) >= 0; var haystack = normalize([item.ruleName, item.value, item.url, item.type, JSON.stringify(item.details || {})].join(' ')); var matchesQuery = !query || haystack.indexOf(query) >= 0; return matchesSeverity && matchesType && matchesQuery; }).sort(function(a, b) { return new Date(b.time).getTime() - new Date(a.time).getTime(); });",
	"    }",
	"    function renderRows() {",
	"      var list = filteredFindings();",
	"      if (!list.length) { tableBody.innerHTML = '<tr><td colspan=\"6\" class=\"muted\">No findings match the current filters.</td></tr>'; return; }",
	"      tableBody.innerHTML = list.map(function(item) { var details = Object.entries(item.details || {}).map(function(entry) { var value = entry[1]; if (entry[0] === 'url') { return '<li><strong>url</strong>: <a href=\"' + value + '\" target=\"_blank\" rel=\"noopener noreferrer\">' + value + '</a></li>'; } return '<li><strong>' + entry[0] + '</strong>: ' + value + '</li>'; }).join(''); var secretValue = item.value || ''; var secretBlock = secretValue ? '<div class=\"secret\" data-copy=\"' + secretValue.replace(/\"/g, '&quot;') + '\" tabindex=\"0\" role=\"button\" aria-label=\"Copy secret to clipboard\">' + secretValue.replace(/[<>]/g, '') + '</div>' : '<span class=\"muted\">—</span>'; var confidence = (item.confidence || 'unknown').toLowerCase(); var typeName = (item.type || 'log'); var confidenceBadge = '<span class=\"badge ' + severityClass(confidence) + '\">' + (item.confidence || 'unknown') + '</span>'; var typeBadge = '<span class=\"badge type-' + typeClass(typeName) + '\">' + typeName + '</span>'; var renderedDetails = details || (item.url ? '<li><strong>url</strong>: <a href=\"' + item.url + '\" target=\"_blank\" rel=\"noopener noreferrer\">' + item.url + '</a></li>' : ''); var row = '<tr><td>' + confidenceBadge + '</td><td>' + (item.ruleName || '—') + '</td><td>' + secretBlock + '</td><td>' + typeBadge + '</td><td>' + (renderedDetails ? '<ul class=\"details-list\">' + renderedDetails + '</ul>' : '<span class=\"muted\">—</span>') + '</td><td>' + formatTimestamp(item.time) + '</td></tr>'; return row; }).join('');",
	"      tableBody.querySelectorAll('[data-copy]').forEach(function(node) { node.addEventListener('click', function() { var value = node.getAttribute('data-copy') || ''; if (!value) { return; } navigator.clipboard.writeText(value).then(function() { showToast('Secret copied to clipboard'); }).catch(function() { showToast('Copy failed'); }); }); node.addEventListener('keydown', function(event) { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); node.click(); } }); });",
	"    }",
	"    function exportCSV() {",
	"      var findings = filteredFindings();",
	"      fetch('/api/export.csv', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(findings) }).then(function(response) { if (!response.ok) throw new Error('export'); return response.blob(); }).then(function(blob) { var url = URL.createObjectURL(blob); var link = document.createElement('a'); link.href = url; link.download = 'pipeleek-findings.csv'; document.body.appendChild(link); link.click(); link.remove(); window.setTimeout(function() { URL.revokeObjectURL(url); }, 0); showToast('Exported ' + findings.length + ' findings to CSV'); }).catch(function() { showToast('CSV export failed'); });",
	"    }",
	"    function applyFilters() { state.severity = severityFilter.value.split(',').filter(Boolean); state.type = typeFilter.value.split(',').filter(Boolean); state.search = searchFilter.value; renderRows(); }",
	"    function setupFilterPicker(id, input) {",
	"      var picker = document.getElementById(id);",
	"      var trigger = picker.querySelector('.filter-trigger');",
	"      var selected = picker.querySelector('.filter-selected');",
	"      var menu = picker.querySelector('[role=\"listbox\"]');",
	"      var options = Array.prototype.slice.call(menu.querySelectorAll('[role=\"option\"]'));",
	"      function values() { return input.value.split(',').filter(Boolean); }",
	"      function update(values) {",
	"        if (!values.length) values = ['all'];",
	"        if (values.indexOf('all') >= 0) values = ['all'];",
	"        input.value = values.join(',');",
	"        selected.textContent = '';",
	"        options.forEach(function(option) { var value = option.getAttribute('data-value'); var active = values.indexOf(value) >= 0; option.setAttribute('aria-selected', active ? 'true' : 'false'); if (active) selected.appendChild(option.querySelector('.badge').cloneNode(true)); });",
	"      }",
	"      function close(restoreFocus) { menu.hidden = true; trigger.setAttribute('aria-expanded', 'false'); if (restoreFocus) trigger.focus(); }",
	"      function open(index) { menu.hidden = false; trigger.setAttribute('aria-expanded', 'true'); options[index].focus(); }",
	"      function toggle(option) {",
	"        var value = option.getAttribute('data-value');",
	"        var next = values();",
	"        if (value === 'all') next = ['all']; else { next = next.filter(function(item) { return item !== 'all'; }); if (next.indexOf(value) >= 0) next = next.filter(function(item) { return item !== value; }); else next.push(value); }",
	"        update(next);",
	"        applyFilters();",
	"      }",
	"      trigger.addEventListener('click', function() { if (menu.hidden) { var active = options.findIndex(function(option) { return values().indexOf(option.getAttribute('data-value')) >= 0; }); open(Math.max(active, 0)); } else { close(false); } });",
	"      trigger.addEventListener('keydown', function(event) { if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); open(event.key === 'ArrowUp' ? options.length - 1 : 0); } });",
	"      menu.addEventListener('click', function(event) { var option = event.target.closest('[role=\"option\"]'); if (option) { toggle(option); option.focus(); } });",
	"      menu.addEventListener('keydown', function(event) { var current = options.indexOf(document.activeElement); if (event.key === 'Escape') { event.preventDefault(); close(true); } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp' || event.key === 'Home' || event.key === 'End') { event.preventDefault(); var next = event.key === 'Home' ? 0 : event.key === 'End' ? options.length - 1 : (current + (event.key === 'ArrowDown' ? 1 : -1) + options.length) % options.length; options[next].focus(); } else if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); if (options[current]) toggle(options[current]); } });",
	"      document.addEventListener('click', function(event) { if (!picker.contains(event.target)) close(false); });",
	"      update(values());",
	"      return { reset: function() { update(['all']); } };",
	"    }",
	"    var severityPicker = setupFilterPicker('severity-picker', severityFilter);",
	"    var typePicker = setupFilterPicker('type-picker', typeFilter);",
	"    function resetFilters() { severityPicker.reset(); typePicker.reset(); searchFilter.value = ''; applyFilters(); }",
	"    var mainContent = document.getElementById('top');",
	"    var fullWidthButton = document.getElementById('toggle-full-width');",
	"    fullWidthButton.addEventListener('click', function() { var enabled = !mainContent.classList.contains('main-wide'); mainContent.classList.toggle('main-wide', enabled); mainContent.classList.toggle('main-default', !enabled); fullWidthButton.setAttribute('aria-pressed', enabled ? 'true' : 'false'); fullWidthButton.textContent = enabled ? 'Normal width' : 'Full width'; });",
	"    function loadFindings() { return fetch('/api/findings', { credentials: 'same-origin' }).then(function(response) { if (!response.ok) { throw new Error('network'); } return response.json(); }).then(function(data) { state.all = Array.isArray(data) ? data : []; renderSummary(); renderRows(); }); }",
	"    searchFilter.addEventListener('input', applyFilters);",
	"    resetButton.addEventListener('click', resetFilters);",
	"    exportCSVButton.addEventListener('click', exportCSV);",
	"    var source = new EventSource('/events');",
	"    source.onopen = function() { connectionState.textContent = 'live'; connectionDot.classList.remove('offline'); };",
	"    source.addEventListener('finding', function(event) { var item = JSON.parse(event.data); var list = state.all.filter(function(entry) { return entry.id !== item.id; }); list.push(item); state.all = list; renderSummary(); renderRows(); });",
	"    source.addEventListener('done', function() { connectionState.textContent = 'complete'; connectionDot.classList.add('offline'); });",
	"    source.onerror = function() { connectionState.textContent = 'reconnecting'; connectionDot.classList.add('offline'); };",
	"    loadFindings().catch(function() { connectionState.textContent = 'auth required'; connectionDot.classList.add('offline'); });",
	"  </script>",
	"</body>",
	"</html>",
}, "")

func StartIfEnabled(enabled bool) *Server {
	if !enabled {
		return nil
	}
	server, err := Start()
	if err != nil {
		zerologlog.Error().Err(err).Msg("Failed to start findings web UI")
		return nil
	}
	return server
}

func Start() (*Server, error) {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(tokenBytes)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	server := &Server{
		clients: make(map[chan string]struct{}),
		token:   token,
		done:    make(chan struct{}),
		port:    fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port),
	}
	server.url = fmt.Sprintf("http://127.0.0.1:%s/?token=%s", server.port, server.token)
	server.server = &http.Server{
		Handler: server.handler(),
	}

	go func() {
		if err := server.server.Serve(listener); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			zerologlog.Error().Err(err).Msg("Findings web UI listener exited")
		}
	}()

	logging.RegisterHitSink(server.handleHit)
	zerologlog.Info().Str("url", server.url).Str("token", token).Msg("Findings web UI started")
	return server, nil
}

func (s *Server) Close() error {
	s.once.Do(func() {
		close(s.done)
		if s.server != nil {
			_ = s.server.Close()
		}
	})
	return nil
}

func (s *Server) Wait() {
	if s == nil {
		return
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case <-s.done:
	case <-sigCh:
		_ = s.Close()
	}
}

func (s *Server) handleHit(record logging.HitRecord) {
	finding := Finding{
		ID:         fmt.Sprintf("%s-%s", record.Time.Format(time.RFC3339Nano), record.Value),
		Time:       record.Time.Format(time.RFC3339),
		Type:       record.Type,
		Confidence: record.Confidence,
		RuleName:   record.RuleName,
		Value:      record.Value,
		Details:    make(map[string]string),
	}
	if finding.Type == "" {
		finding.Type = "log"
	}
	if record.Fields != nil {
		for key, val := range record.Fields {
			switch key {
			case "type", "confidence", "ruleName", "value", "_hit":
				continue
			}
			if v := fmt.Sprint(val); v != "" && v != "<nil>" {
				finding.Details[key] = v
				if key == "url" {
					finding.URL = v
				}
			}
		}
	}
	if finding.URL == "" {
		if v, ok := record.Fields["url"]; ok {
			finding.URL = fmt.Sprint(v)
		}
	}

	s.mu.Lock()
	s.findings = append(s.findings, finding)
	payload, err := json.Marshal(finding)
	if err == nil {
		for ch := range s.clients {
			select {
			case ch <- "event: finding\ndata: " + string(payload) + "\n\n":
			default:
			}
		}
	}
	s.mu.Unlock()
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/api/findings", s.requireAuth(s.handleFindings))
	mux.HandleFunc("/api/export.csv", s.requireAuth(s.handleExportCSV))
	mux.HandleFunc("/events", s.requireAuth(s.handleEvents))
	return mux
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isAuthorized(r) {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))
			return
		}
		next(w, r)
	}
}

func (s *Server) isAuthorized(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.URL != nil && r.URL.Query().Get("token") == s.token {
		return true
	}
	if c, err := r.Cookie("pipeleek-webui-token"); err == nil && c.Value == s.token {
		return true
	}
	return false
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthorized(r) {
		if r.URL != nil && r.URL.RawQuery != "" && strings.Contains(r.URL.RawQuery, "token=") {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if q := r.URL.Query().Get("token"); q != "" && q == s.token {
		http.SetCookie(w, &http.Cookie{Name: "pipeleek-webui-token", Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	view := struct {
		PipeleekLogo template.HTML
	}{PipeleekLogo: gitlabenum.PipeleekLogoHTML()}
	if err := template.Must(template.New("page").Parse(pageTemplate)).Execute(w, view); err != nil {
		zerologlog.Error().Err(err).Msg("Failed to render findings UI")
	}
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	s.mu.RLock()
	findings := append([]Finding(nil), s.findings...)
	s.mu.RUnlock()
	if err := json.NewEncoder(w).Encode(findings); err != nil {
		zerologlog.Error().Err(err).Msg("Failed to encode findings JSON")
	}
}

func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var findings []Finding
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20))
	if err := decoder.Decode(&findings); err != nil {
		http.Error(w, "Invalid findings data", http.StatusBadRequest)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		http.Error(w, "Invalid findings data", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="pipeleek-findings.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if _, err := w.Write([]byte{0xef, 0xbb, 0xbf}); err != nil {
		return
	}

	writer := csv.NewWriter(w)
	writer.UseCRLF = true
	if err := writer.Write([]string{"Severity", "Rule", "Secret", "Type", "Details", "Time"}); err != nil {
		zerologlog.Error().Err(err).Msg("Failed to write findings CSV header")
		return
	}
	for _, finding := range findings {
		keys := make([]string, 0, len(finding.Details))
		for key := range finding.Details {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		details := make([]string, 0, len(keys))
		for _, key := range keys {
			details = append(details, key+": "+finding.Details[key])
		}
		if len(details) == 0 && finding.URL != "" {
			details = append(details, "url: "+finding.URL)
		}
		record := []string{
			protectCSVFormula(finding.Confidence),
			protectCSVFormula(finding.RuleName),
			protectCSVFormula(finding.Value),
			protectCSVFormula(finding.Type),
			protectCSVFormula(strings.Join(details, "; ")),
			protectCSVFormula(finding.Time),
		}
		if err := writer.Write(record); err != nil {
			zerologlog.Error().Err(err).Msg("Failed to write findings CSV record")
			return
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		zerologlog.Error().Err(err).Msg("Failed to flush findings CSV")
	}
}

func protectCSVFormula(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if len(trimmed) > 0 && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}
	ch := make(chan string, 32)
	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
	}()

	if _, err := w.Write([]byte("\n")); err != nil {
		return
	}
	flusher.Flush()

	s.mu.RLock()
	for _, finding := range s.findings {
		payload, _ := json.Marshal(finding)
		_, _ = fmt.Fprintf(w, "event: finding\ndata: %s\n\n", string(payload))
		flusher.Flush()
	}
	s.mu.RUnlock()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case msg := <-ch:
			if _, err := fmt.Fprint(w, msg); err != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
