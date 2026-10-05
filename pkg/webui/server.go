package webui

import (
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
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
	ID              string            `json:"id"`
	Time            string            `json:"time"`
	TimestampMillis int64             `json:"timestampMillis"`
	Type            string            `json:"type"`
	Confidence      string            `json:"confidence"`
	RuleName        string            `json:"ruleName"`
	Value           string            `json:"value"`
	URL             string            `json:"url,omitempty"`
	Details         map[string]string `json:"details,omitempty"`
}

// ScanContext describes the target and effective settings for one scan.
type ScanContext struct {
	TargetURL string
	Options   []ScanOption
}

// ScanOption is a non-positional scan flag and its effective value.
type ScanOption struct {
	Name  string
	Value string
}

type Server struct {
	mu                sync.RWMutex
	findings          []Finding
	clients           map[chan string]struct{}
	nextID            uint64
	token             string
	port              string
	url               string
	server            *http.Server
	done              chan struct{}
	once              sync.Once
	startedAt         time.Time
	completedAt       time.Time
	completed         bool
	scanContext       ScanContext
	unregisterHitSink func()
}

var pageTemplate = strings.Join([]string{
	"<!doctype html>",
	"<html lang=\"en\">",
	"<head>",
	"  <meta charset=\"utf-8\" />",
	"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />",
	"  <link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\" />",
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
	"    .header-copy { min-width: 0; }",
	"    .elapsed-time { display: block; font-size: .875rem; font-variant-numeric: tabular-nums; }",
	"    .scan-context { display: grid; gap: .75rem; }",
	"    .scan-context-target { display: grid; gap: .2rem; min-width: 0; }",
	"    .scan-context-label { color: var(--muted); font-size: .8rem; font-weight: 600; }",
	"    .scan-context-target code { overflow-wrap: anywhere; }",
	"    .scan-options { display: flex; flex-wrap: wrap; gap: .5rem; }",
	"    .scan-option { display: inline-flex; flex-wrap: wrap; align-items: baseline; gap: .4rem; min-width: 0; padding: .35rem .6rem; border: 1px solid #dce5d2; border-radius: 7px; background: linear-gradient(180deg, #fff, #f4f7f0); box-shadow: 0 1px 2px rgba(42,74,37,.06); }",
	"    .scan-option-name { color: var(--accent-dark); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .78rem; font-weight: 700; }",
	"    .scan-option-value { color: var(--ink); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .82rem; overflow-wrap: anywhere; }",
	"    h1 { margin: 0; font-size: 2rem; font-weight: 400; color: #3c4043; }",
	"    .status { display: inline-flex; align-items: center; gap: .45rem; border-radius: 999px; padding: .35rem .75rem; border: 1px solid var(--line); background: #f3f5ef; font-size: .85rem; font-weight: 600; }",
	"    .dot { width: .6rem; height: .6rem; border-radius: 50%; background: #4cae5d; display: inline-block; }",
	"    .dot.offline { background: var(--danger); }",
	"    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: .75rem; }",
	"    .metric { border: 1px solid var(--line); border-radius: 10px; padding: .75rem; background: linear-gradient(180deg, #fff, #f7f9f5); }",
	"    .metric strong { display: block; font-size: 1.45rem; line-height: 1.2; margin-top: .15rem; }",
	"    .metric label { color: var(--muted); font-size: .8rem; }",
	"    .filters { display: flex; flex-wrap: wrap; gap: .75rem; align-items: flex-start; }",
	"    .filters > .control-btn { align-self: flex-start; margin-top: 1.5rem; }",
	"    .filter-field { display: flex; flex-direction: column; gap: .35rem; min-width: 150px; }",
	"    .filter-field label { color: var(--muted); font-size: .8rem; font-weight: 600; }",
	"    .notification-field { min-width: 12rem; }",
	"    .notification-status { min-height: 1.2em; font-size: .8rem; }",
	"    .single-select-picker .filter-check { border-radius: 50%; }",
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
	"    .empty-state { padding: 2rem 1rem; text-align: center; }",
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
	"    </div>",
	"  </nav>",
	"  <main id=\"top\" class=\"main-default\">",
	"    <div class=\"card\">",
	"      <div class=\"row\">",
	"        <div class=\"header-copy\">",
	"          <h1 style=\"margin:0; font-weight:400; font-size:2rem;\">Live secret findings</h1>",
	"          <span id=\"elapsed-time\" class=\"muted elapsed-time\" aria-live=\"off\">Elapsed 00:00:00</span>",
	"        </div>",
	"        <div class=\"status\"><span class=\"dot\" id=\"connection-dot\"></span><span id=\"connection-state\">connecting</span></div>",
	"      </div>",
	"    </div>",
	"    {{if .ScanContext.TargetURL}}",
	"    <section class=\"card scan-context\" aria-label=\"Scan context\">",
	"      <div class=\"scan-context-target\"><span class=\"scan-context-label\">Target instance</span><code>{{.ScanContext.TargetURL}}</code></div>",
	"      {{if .ScanContext.Options}}",
	"      <div><div class=\"scan-context-label\">Effective scan flags</div><div class=\"scan-options\">",
	"        {{range .ScanContext.Options}}<div class=\"scan-option\"><span class=\"scan-option-name\">{{.Name}}</span><span class=\"scan-option-value\">{{.Value}}</span></div>{{end}}",
	"      </div></div>",
	"      {{end}}",
	"    </section>",
	"    {{end}}",
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
	"        <div class=\"filter-field notification-field\">",
	"          <label id=\"notification-threshold-label\">Notify from</label>",
	"          <input id=\"notification-threshold\" type=\"hidden\" value=\"high-verified\" />",
	"          <div class=\"filter-picker single-select-picker\" id=\"notification-threshold-picker\">",
	"            <button class=\"filter-trigger\" id=\"notification-threshold-trigger\" type=\"button\" aria-haspopup=\"listbox\" aria-expanded=\"false\" aria-controls=\"notification-threshold-options\" aria-labelledby=\"notification-threshold-label notification-threshold-selected\"><span class=\"filter-selected\" id=\"notification-threshold-selected\"></span><span class=\"filter-chevron\" aria-hidden=\"true\"></span></button>",
	"            <div class=\"filter-options\" id=\"notification-threshold-options\" role=\"listbox\" aria-multiselectable=\"false\" aria-labelledby=\"notification-threshold-label\" hidden>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"high-verified\" aria-selected=\"true\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge high-verified\">high-verified</span></div>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"high\" aria-selected=\"false\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge high\">high and above</span></div>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"medium\" aria-selected=\"false\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge medium\">medium and above</span></div>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"low\" aria-selected=\"false\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge low\">low and above</span></div>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"any\" aria-selected=\"false\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge all\">Any finding</span></div>",
	"              <div class=\"filter-option\" role=\"option\" tabindex=\"-1\" data-value=\"none\" aria-selected=\"false\"><span class=\"filter-check\" aria-hidden=\"true\"></span><span class=\"badge all\">None</span></div>",
	"            </div>",
	"          </div>",
	"          <button class=\"control-btn\" id=\"enable-notifications\" type=\"button\" hidden>Enable notifications</button>",
	"          <span id=\"notification-status\" class=\"muted notification-status\" role=\"status\"></span>",
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
	"    const state = { all: [], severity: ['all'], type: ['all'], search: '', completed: {{.Completed}}, notificationsReady: false };",
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
	"    const notificationThreshold = document.getElementById('notification-threshold');",
	"    const enableNotificationsButton = document.getElementById('enable-notifications');",
	"    const notificationStatus = document.getElementById('notification-status');",
	"    var notificationsSince = Date.now();",
	"    var activeNotifications = [];",
	"    const elapsedTime = document.getElementById('elapsed-time');",
	"    var elapsedBase = {{.ElapsedMillis}};",
	"    var elapsedStartedAt = Date.now();",
	"    function updateElapsedTime() { var totalSeconds = Math.floor(Math.max(0, elapsedBase + (state.completed ? 0 : Date.now() - elapsedStartedAt)) / 1000); var hours = Math.floor(totalSeconds / 3600); var minutes = Math.floor((totalSeconds % 3600) / 60); var seconds = totalSeconds % 60; elapsedTime.textContent = 'Elapsed ' + [hours, minutes, seconds].map(function(value) { return String(value).padStart(2, '0'); }).join(':'); }",
	"    const normalize = function(value) { return (value || '').toLowerCase(); };",
	"    function updateNotificationStatus() { if (!('Notification' in window)) { enableNotificationsButton.hidden = true; notificationStatus.textContent = 'Browser notifications are not supported.'; return; } if (Notification.permission === 'granted') { enableNotificationsButton.hidden = true; notificationStatus.textContent = notificationThreshold.value === 'none' ? 'Notifications are off.' : 'Browser notifications enabled.'; return; } if (Notification.permission === 'denied') { enableNotificationsButton.hidden = true; notificationStatus.textContent = 'Notifications are blocked in browser settings.'; return; } enableNotificationsButton.hidden = notificationThreshold.value === 'none'; notificationStatus.textContent = notificationThreshold.value === 'none' ? 'Notifications are off.' : 'Allow notifications for matching findings.'; }",
	"    function requestNotificationPermission() { if (!('Notification' in window)) { updateNotificationStatus(); return; } try { Notification.requestPermission().then(updateNotificationStatus).catch(updateNotificationStatus); } catch (_) { updateNotificationStatus(); } }",
	"    function meetsNotificationThreshold(confidence) { var threshold = notificationThreshold.value; if (threshold === 'none') return false; if (threshold === 'any') return true; var levels = ['high-verified', 'high', 'medium', 'low']; var findingLevel = levels.indexOf(normalize(confidence)); return findingLevel >= 0 && findingLevel <= levels.indexOf(threshold); }",
	"    function closeActiveNotifications() { activeNotifications.forEach(function(notification) { notification.close(); }); activeNotifications = []; }",
	"    function notifyFinding(item) { var findingTime = Number(item.timestampMillis); if (!state.notificationsReady || (findingTime > 0 && findingTime < notificationsSince) || !('Notification' in window) || Notification.permission !== 'granted' || !meetsNotificationThreshold(item.confidence)) return; try { var title = item.confidence === 'high-verified' ? 'Verified credential found' : 'Credential finding detected'; var notification = new Notification(title, { body: 'Confidence: ' + (item.confidence || 'unknown') + '. Open Pipeleek to review.' }); activeNotifications.push(notification); notification.onclose = function() { activeNotifications = activeNotifications.filter(function(openNotification) { return openNotification !== notification; }); }; notification.onclick = function() { window.focus(); notification.close(); }; } catch (_) {} }",
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
	"      summaryCards.replaceChildren();",
	"      ['high-verified', 'high', 'medium', 'low'].forEach(function(key) { var metric = document.createElement('div'); metric.className = 'metric'; var label = document.createElement('label'); label.textContent = key.charAt(0).toUpperCase() + key.slice(1); var count = document.createElement('strong'); count.textContent = String(counts[key] || 0); metric.append(label, count); summaryCards.appendChild(metric); });",
	"    }",
	"    function filteredFindings() {",
	"      var query = normalize(searchFilter.value);",
	"      return state.all.filter(function(item) { var severity = normalize(item.confidence); var kind = normalize(item.type); var matchesSeverity = state.severity.indexOf('all') >= 0 || state.severity.indexOf(severity) >= 0; var matchesType = state.type.indexOf('all') >= 0 || state.type.indexOf(kind) >= 0; var haystack = normalize([item.ruleName, item.value, item.url, item.type, JSON.stringify(item.details || {})].join(' ')); var matchesQuery = !query || haystack.indexOf(query) >= 0; return matchesSeverity && matchesType && matchesQuery; }).sort(function(a, b) { return new Date(b.time).getTime() - new Date(a.time).getTime(); });",
	"    }",
	"    function appendDetailValue(parent, key, value) {",
	"      var item = document.createElement('li'); var label = document.createElement('strong'); label.textContent = key; item.append(label, document.createTextNode(': '));",
	"      if (key.toLowerCase() === 'url') { var parsed; try { parsed = new URL(value); } catch (_) {} if (parsed && (parsed.protocol === 'http:' || parsed.protocol === 'https:')) { var link = document.createElement('a'); link.href = parsed.href; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = value; item.appendChild(link); } else { item.appendChild(document.createTextNode(value)); } } else { item.appendChild(document.createTextNode(value)); }",
	"      parent.appendChild(item);",
	"    }",
	"    function renderRows() {",
	"      var list = filteredFindings(); var fragment = document.createDocumentFragment();",
	"      if (!list.length) { var emptyRow = document.createElement('tr'); var emptyCell = document.createElement('td'); emptyCell.colSpan = 6; emptyCell.className = 'muted empty-state'; emptyCell.textContent = state.all.length ? 'No findings match the current filters.' : state.completed ? 'No findings were detected.' : 'No findings yet. Results will appear here as the scan runs.'; emptyRow.appendChild(emptyCell); fragment.appendChild(emptyRow); tableBody.replaceChildren(fragment); return; }",
	"      list.forEach(function(item) {",
	"        var row = document.createElement('tr'); var confidence = (item.confidence || 'unknown').toLowerCase(); var typeName = item.type || 'log';",
	"        var severityCell = document.createElement('td'); var severityBadge = document.createElement('span'); severityBadge.className = 'badge ' + severityClass(confidence); severityBadge.textContent = item.confidence || 'unknown'; severityCell.appendChild(severityBadge); row.appendChild(severityCell);",
	"        var ruleCell = document.createElement('td'); ruleCell.textContent = item.ruleName || '—'; row.appendChild(ruleCell);",
	"        var secretCell = document.createElement('td'); if (item.value) { var secretButton = document.createElement('button'); secretButton.type = 'button'; secretButton.className = 'secret'; secretButton.dataset.copy = item.value; secretButton.setAttribute('aria-label', 'Copy secret to clipboard'); secretButton.textContent = item.value; secretCell.appendChild(secretButton); } else { var noSecret = document.createElement('span'); noSecret.className = 'muted'; noSecret.textContent = '—'; secretCell.appendChild(noSecret); } row.appendChild(secretCell);",
	"        var typeCell = document.createElement('td'); var typeBadge = document.createElement('span'); typeBadge.className = 'badge type-' + typeClass(typeName); typeBadge.textContent = typeName; typeCell.appendChild(typeBadge); row.appendChild(typeCell);",
	"        var detailsCell = document.createElement('td'); var detailEntries = Object.entries(item.details || {}); if (detailEntries.length === 0 && item.url) detailEntries.push(['url', item.url]); if (detailEntries.length) { var detailList = document.createElement('ul'); detailList.className = 'details-list'; detailEntries.forEach(function(entry) { appendDetailValue(detailList, entry[0], String(entry[1])); }); detailsCell.appendChild(detailList); } else { var noDetails = document.createElement('span'); noDetails.className = 'muted'; noDetails.textContent = '—'; detailsCell.appendChild(noDetails); } row.appendChild(detailsCell);",
	"        var timeCell = document.createElement('td'); timeCell.textContent = formatTimestamp(item.time); row.appendChild(timeCell); fragment.appendChild(row);",
	"      });",
	"      tableBody.replaceChildren(fragment);",
	"    }",
	"    tableBody.addEventListener('click', function(event) { var button = event.target.closest('button[data-copy]'); if (!button) return; navigator.clipboard.writeText(button.dataset.copy || '').then(function() { showToast('Secret copied to clipboard'); }).catch(function() { showToast('Copy failed'); }); });",
	"    function exportCSV() {",
	"      var findings = filteredFindings();",
	"      fetch('/api/export.csv', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(findings) }).then(function(response) { if (!response.ok) throw new Error('export'); return response.blob(); }).then(function(blob) { var url = URL.createObjectURL(blob); var link = document.createElement('a'); link.href = url; link.download = 'pipeleek-findings.csv'; document.body.appendChild(link); link.click(); link.remove(); window.setTimeout(function() { URL.revokeObjectURL(url); }, 0); showToast('Exported ' + findings.length + ' findings to CSV'); }).catch(function() { showToast('CSV export failed'); });",
	"    }",
	"    function applyFilters() { state.severity = severityFilter.value.split(',').filter(Boolean); state.type = typeFilter.value.split(',').filter(Boolean); state.search = searchFilter.value; renderRows(); }",
	"    function setupFilterPicker(id, input, allowMultiple, onChange) {",
	"      var picker = document.getElementById(id);",
	"      var trigger = picker.querySelector('.filter-trigger');",
	"      var selected = picker.querySelector('.filter-selected');",
	"      var menu = picker.querySelector('[role=\"listbox\"]');",
	"      var options = Array.prototype.slice.call(menu.querySelectorAll('[role=\"option\"]'));",
	"      function values() { return input.value.split(',').filter(Boolean); }",
	"      function update(values) {",
	"        if (!values.length) values = [allowMultiple === false ? options[0].getAttribute('data-value') : 'all'];",
	"        if (allowMultiple === false) values = [values[0]]; else if (values.indexOf('all') >= 0) values = ['all'];",
	"        input.value = values.join(',');",
	"        selected.textContent = '';",
	"        options.forEach(function(option) { var value = option.getAttribute('data-value'); var active = values.indexOf(value) >= 0; option.setAttribute('aria-selected', active ? 'true' : 'false'); if (active) selected.appendChild(option.querySelector('.badge').cloneNode(true)); });",
	"      }",
	"      function close(restoreFocus) { menu.hidden = true; trigger.setAttribute('aria-expanded', 'false'); if (restoreFocus) trigger.focus(); }",
	"      function open(index) { menu.hidden = false; trigger.setAttribute('aria-expanded', 'true'); options[index].focus(); }",
	"      function toggle(option) {",
	"        var value = option.getAttribute('data-value');",
	"        if (allowMultiple === false) { update([value]); close(true); if (onChange) onChange(); return; }",
	"        var next = values();",
	"        if (value === 'all') next = ['all']; else { next = next.filter(function(item) { return item !== 'all'; }); if (next.indexOf(value) >= 0) next = next.filter(function(item) { return item !== value; }); else next.push(value); }",
	"        update(next);",
	"        if (onChange) onChange(); else applyFilters();",
	"      }",
	"      trigger.addEventListener('click', function() { if (menu.hidden) { var active = options.findIndex(function(option) { return values().indexOf(option.getAttribute('data-value')) >= 0; }); open(Math.max(active, 0)); } else { close(false); } });",
	"      trigger.addEventListener('keydown', function(event) { if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); open(event.key === 'ArrowUp' ? options.length - 1 : 0); } });",
	"      menu.addEventListener('click', function(event) { var option = event.target.closest('[role=\"option\"]'); if (option) { toggle(option); if (!menu.hidden) option.focus(); } });",
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
	"    searchFilter.addEventListener('input', applyFilters);",
	"    resetButton.addEventListener('click', resetFilters);",
	"    exportCSVButton.addEventListener('click', exportCSV);",
	"    var notificationThresholdPicker = setupFilterPicker('notification-threshold-picker', notificationThreshold, false, function() { notificationsSince = Date.now(); closeActiveNotifications(); updateNotificationStatus(); if (notificationThreshold.value !== 'none' && 'Notification' in window && Notification.permission === 'default') requestNotificationPermission(); });",
	"    updateNotificationStatus();",
	"    if (notificationThreshold.value !== 'none' && 'Notification' in window && Notification.permission === 'default') requestNotificationPermission();",
	"    enableNotificationsButton.addEventListener('click', requestNotificationPermission);",
	"    renderSummary();",
	"    renderRows();",
	"    updateElapsedTime();",
	"    var elapsedTimer = state.completed ? null : window.setInterval(updateElapsedTime, 1000);",
	"    var source = new EventSource('/events');",
	"    source.onopen = function() { state.notificationsReady = false; connectionState.textContent = 'live'; connectionDot.classList.remove('offline'); };",
	"    source.addEventListener('finding', function(event) { var item = JSON.parse(event.data); var notify = state.notificationsReady; var list = state.all.filter(function(entry) { return entry.id !== item.id; }); list.push(item); state.all = list; renderSummary(); renderRows(); if (notify) notifyFinding(item); });",
	"    source.addEventListener('replay-complete', function() { state.notificationsReady = true; });",
	"    source.addEventListener('done', function(event) { var completion = JSON.parse(event.data); elapsedBase = Math.max(0, Number(completion.elapsedMillis) || 0); state.completed = true; updateElapsedTime(); window.clearInterval(elapsedTimer); connectionState.textContent = 'complete'; connectionDot.classList.add('offline'); renderRows(); source.close(); });",
	"    source.onerror = function() { if (connectionState.textContent !== 'complete') { connectionState.textContent = 'reconnecting'; connectionDot.classList.add('offline'); } };",
	"  </script>",
	"</body>",
	"</html>",
}, "")

func StartIfEnabled(enabled bool) *Server {
	return StartWithContextIfEnabled(enabled, ScanContext{})
}

// StartWithContextIfEnabled starts the findings UI with scan context when enabled.
func StartWithContextIfEnabled(enabled bool, scanContext ScanContext) *Server {
	if !enabled {
		return nil
	}

	server, err := StartWithContext(scanContext)
	if err != nil {
		zerologlog.Error().Err(err).Msg("Failed to start findings web UI")
		return nil
	}
	return server
}

func Start() (*Server, error) {
	return StartWithContext(ScanContext{})
}

// StartWithContext starts a findings UI server and attaches sanitized scan context.
func StartWithContext(scanContext ScanContext) (*Server, error) {
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
		clients:     make(map[chan string]struct{}),
		token:       token,
		done:        make(chan struct{}),
		port:        fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port),
		startedAt:   time.Now(),
		scanContext: sanitizeScanContext(scanContext),
	}
	server.url = fmt.Sprintf("http://127.0.0.1:%s/?token=%s", server.port, server.token)
	server.server = &http.Server{
		Handler:           server.handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if err := server.server.Serve(listener); err != nil {
			if errors.Is(err, http.ErrServerClosed) {
				zerologlog.Info().Err(err).Msg("Findings web UI listener stopped")
				return
			}
			if !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
				zerologlog.Error().Err(err).Msg("Findings web UI listener exited")
			}
		}
	}()

	server.unregisterHitSink = logging.RegisterHitSink(server.handleHit)
	zerologlog.Info().Str("url", server.url).Str("token", token).Msg("Findings web UI started")
	return server, nil
}

func (s *Server) Close() error {
	s.once.Do(func() {
		if s.unregisterHitSink != nil {
			s.unregisterHitSink()
		}
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
	s.Complete()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case <-s.done:
	case <-sigCh:
		_ = s.Close()
	}
}

func (s *Server) Complete() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return
	}
	s.completed = true
	s.completedAt = time.Now()
	doneEvent := s.doneEventLocked()
	for client := range s.clients {
		select {
		case client <- doneEvent:
		default:
			delete(s.clients, client)
			close(client)
		}
	}
}

func (s *Server) elapsedMillisAtLocked(endTime time.Time) int64 {
	if s.startedAt.IsZero() {
		return 0
	}
	elapsed := endTime.Sub(s.startedAt).Milliseconds()
	if elapsed < 0 {
		return 0
	}
	return elapsed
}

func (s *Server) doneEventLocked() string {
	payload, _ := json.Marshal(struct {
		ElapsedMillis int64 `json:"elapsedMillis"`
	}{ElapsedMillis: s.elapsedMillisAtLocked(s.completedAt)})
	return "event: done\ndata: " + string(payload) + "\n\n"
}

func (s *Server) handleHit(record logging.HitRecord) {
	s.mu.Lock()
	s.nextID++
	finding := Finding{
		ID:              fmt.Sprintf("%d", s.nextID),
		Time:            record.Time.Format(time.RFC3339),
		TimestampMillis: record.Time.UnixMilli(),
		Type:            record.Type,
		Confidence:      record.Confidence,
		RuleName:        record.RuleName,
		Value:           record.Value,
		Details:         make(map[string]string),
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

	s.findings = append(s.findings, finding)
	payload, err := json.Marshal(finding)
	if err == nil {
		for ch := range s.clients {
			select {
			case ch <- "event: finding\ndata: " + string(payload) + "\n\n":
			default:
				delete(s.clients, ch)
				close(ch)
			}
		}
	}
	s.mu.Unlock()
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/favicon.svg", s.requireAuth(s.handleFavicon))
	mux.HandleFunc("/api/export.csv", s.requireAuth(s.handleExportCSV))
	mux.HandleFunc("/events", s.requireAuth(s.handleEvents))
	return mux
}

func (s *Server) handleFavicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.WriteString(w, string(gitlabenum.PipeleekLogoHTML()))
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
	s.handleRootAt(w, r, time.Now())
}

func (s *Server) handleRootAt(w http.ResponseWriter, r *http.Request, now time.Time) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !s.isAuthorized(r) {
		if r.URL != nil && r.URL.RawQuery != "" && strings.Contains(r.URL.RawQuery, "token=") {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if q := r.URL.Query().Get("token"); q != "" && q == s.token {
		http.SetCookie(w, &http.Cookie{Name: "pipeleek-webui-token", Value: s.token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	s.mu.RLock()
	completed := s.completed
	endTime := now
	if completed && !s.completedAt.IsZero() {
		endTime = s.completedAt
	}
	elapsedMillis := s.elapsedMillisAtLocked(endTime)
	s.mu.RUnlock()
	view := struct {
		PipeleekLogo  template.HTML
		ElapsedMillis int64
		Completed     bool
		ScanContext   ScanContext
	}{
		PipeleekLogo:  gitlabenum.PipeleekLogoHTML(),
		ElapsedMillis: elapsedMillis,
		Completed:     completed,
		ScanContext:   sanitizeScanContext(s.scanContext),
	}
	if err := template.Must(template.New("page").Parse(pageTemplate)).Execute(w, view); err != nil {
		zerologlog.Error().Err(err).Msg("Failed to render findings UI")
	}
}

func sanitizeScanContext(scanContext ScanContext) ScanContext {
	scanContext.TargetURL = sanitizeTargetURL(scanContext.TargetURL)
	options := make([]ScanOption, len(scanContext.Options))
	for i, option := range scanContext.Options {
		options[i] = option
		if isSensitiveOption(option.Name) {
			options[i].Value = "[redacted]"
		}
	}
	scanContext.Options = options
	return scanContext
}

func sanitizeTargetURL(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "Unavailable"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String()
}

func isSensitiveOption(name string) bool {
	normalized := strings.ToLower(strings.TrimLeft(name, "-"))
	if strings.Contains(normalized, "secrets-verification") {
		return false
	}
	for _, marker := range []string{
		"token", "cookie", "password", "passwd", "credential", "authorization",
		"secret", "api-key", "api_key", "apikey", "private-key", "private_key",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
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
	if !s.completed {
		s.clients[ch] = struct{}{}
	}
	findings := append([]Finding(nil), s.findings...)
	completed := s.completed
	doneEvent := ""
	if completed {
		doneEvent = s.doneEventLocked()
	}
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

	for _, finding := range findings {
		payload, _ := json.Marshal(finding)
		if _, err := fmt.Fprintf(w, "event: finding\ndata: %s\n\n", string(payload)); err != nil {
			return
		}
		flusher.Flush()
	}
	if _, err := fmt.Fprint(w, "event: replay-complete\ndata: complete\n\n"); err != nil {
		return
	}
	flusher.Flush()
	if completed {
		_, _ = fmt.Fprint(w, doneEvent)
		flusher.Flush()
		return
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
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
