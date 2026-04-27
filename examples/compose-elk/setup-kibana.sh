#!/bin/bash
# Setup Kibana data view for Pipeleek logs (idempotent)

set -e

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
DATA_VIEW_NAME="pipeleek-logs"
INDEX_PATTERN="pipeleek-logs-*"
KIBANA_VERSION="8.13.4"

echo "Setting up Kibana data view..."

# Remove existing data view if it exists (idempotent)
echo "Checking for existing data view..."
existing=$(curl -s -X GET "$KIBANA_URL/api/saved_objects/index-pattern/$DATA_VIEW_NAME" \
  -H "kbn-xsrf: true" 2>/dev/null || echo "")
if echo "$existing" | grep -q '"id":"pipeleek-logs"' 2>/dev/null; then
  echo "  Found existing data view, removing..."
  curl -s -X DELETE "$KIBANA_URL/api/saved_objects/index-pattern/$DATA_VIEW_NAME" \
    -H "kbn-xsrf: true" >/dev/null
  sleep 1
fi

# Create data view with retry logic
echo "Creating data view for $INDEX_PATTERN..."
MAX_RETRIES=10
for attempt in $(seq 1 $MAX_RETRIES); do
  response=$(curl -s -w "\n%{http_code}" -X POST \
    "$KIBANA_URL/api/saved_objects/index-pattern/$DATA_VIEW_NAME" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d '{
      "attributes": {
        "title": "'"$INDEX_PATTERN"'",
        "timeFieldName": "@timestamp",
        "fields": "[]"
      }
    }')
  
  http_code=$(echo "$response" | tail -n 1)
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
    if echo "$body" | grep -q '"id":"pipeleek-logs"'; then
      echo "  ✓ Data view created successfully"
      break
    fi
  fi
  
  if [ $attempt -lt $MAX_RETRIES ]; then
    echo "  Attempt $attempt/$MAX_RETRIES failed (HTTP $http_code), retrying in 2s..."
    sleep 2
  else
    echo "  ✗ Failed to create data view after $MAX_RETRIES attempts"
    echo "  Last response: $body"
    echo "  Note: You can manually run setup-kibana.sh later or create the data view in Kibana UI"
    exit 1
  fi
done

# Set as default data view
echo "Setting as default data view..."
curl -s -X POST "$KIBANA_URL/api/saved_objects/config/$KIBANA_VERSION" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{"attributes":{"defaultIndex":"'"$DATA_VIEW_NAME"'"}}' >/dev/null

upsert_saved_object() {
  local object_type="$1"
  local object_id="$2"
  local payload="$3"
  local max_retries=10

  for attempt in $(seq 1 "$max_retries"); do
    response=$(curl -s -w "\n%{http_code}" -X POST \
      "$KIBANA_URL/api/saved_objects/$object_type/$object_id?overwrite=true" \
      -H "kbn-xsrf: true" \
      -H "Content-Type: application/json" \
      -d "$payload")

    http_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
      return 0
    fi

    if [ "$attempt" -lt "$max_retries" ]; then
      echo "  Attempt $attempt/$max_retries for $object_type/$object_id failed (HTTP $http_code), retrying in 2s..."
      sleep 2
    else
      echo "  ✗ Failed to create $object_type/$object_id after $max_retries attempts"
      echo "  Last response: $body"
      return 1
    fi
  done
}

echo "Creating prebuilt saved search (last 100 scan entries)..."
search_payload='{
  "attributes": {
    "title": "Pipeleek - Last 100 Scan Entries",
    "description": "Latest 100 hit events, filterable by platform and severity",
    "columns": ["@timestamp", "scan_job", "confidence", "level", "ruleName", "url", "message"],
    "sort": [["@timestamp", "desc"]],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"query\":{\"language\":\"kuery\",\"query\":\"level:hit\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\",\"size\":100}"
    }
  },
  "references": [
    {
      "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
      "type": "index-pattern",
      "id": "pipeleek-logs"
    }
  ]
}'
upsert_saved_object "search" "pipeleek-search-last100" "$search_payload"

echo "Creating prebuilt saved search (latest 100 log entries, no filter)..."
raw_logs_search_payload='{
  "attributes": {
    "title": "Pipeleek - Latest 100 Log Entries",
    "description": "Latest 100 log entries sorted by newest first with no fixed query filter",
    "columns": ["@timestamp", "level", "scan_job", "scan.platform", "scan.confidence", "message"],
    "sort": [["@timestamp", "desc"]],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"query\":{\"language\":\"kuery\",\"query\":\"\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\",\"size\":100}"
    }
  },
  "references": [
    {
      "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
      "type": "index-pattern",
      "id": "pipeleek-logs"
    }
  ]
}'
upsert_saved_object "search" "pipeleek-search-logs-last100" "$raw_logs_search_payload"

echo "Creating metric visualization for high hits..."
high_metric_payload='{
  "attributes": {
    "title": "Pipeleek - High Hits",
    "description": "Count of hit events with high confidence",
    "visState": "{\"title\":\"Pipeleek - High Hits\",\"type\":\"metrics\",\"params\":{\"id\":\"pipeleek-high-hits-panel\",\"type\":\"metric\",\"series\":[{\"id\":\"pipeleek-high-hits-series\",\"split_mode\":\"everything\",\"metrics\":[{\"id\":\"pipeleek-high-hits-count\",\"type\":\"count\"}],\"label\":\"High Hits\",\"color\":\"#F59E0B\",\"formatter\":\"number\",\"chart_type\":\"line\",\"line_width\":\"1\",\"point_size\":\"1\",\"fill\":\"0.5\"}],\"time_field\":\"@timestamp\",\"index_pattern\":\"pipeleek-logs-*\",\"default_index_pattern\":\"pipeleek-logs-*\",\"default_timefield\":\"@timestamp\",\"filter\":{\"language\":\"kuery\",\"query\":\"level:hit and confidence:high\"},\"interval\":\"auto\",\"time_range_mode\":\"entire_time_range\",\"isModelInvalid\":false}}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"query\":{\"language\":\"kuery\",\"query\":\"\"},\"filter\":[]}"
    }
  }
}'
upsert_saved_object "visualization" "pipeleek-vis-high-count" "$high_metric_payload"

echo "Creating metric visualization for high-verified hits..."
high_verified_metric_payload='{
  "attributes": {
    "title": "Pipeleek - High-Verified Hits",
    "description": "Count of hit events with high-verified confidence",
    "visState": "{\"title\":\"Pipeleek - High-Verified Hits\",\"type\":\"metrics\",\"params\":{\"id\":\"pipeleek-high-verified-panel\",\"type\":\"metric\",\"series\":[{\"id\":\"pipeleek-high-verified-series\",\"split_mode\":\"everything\",\"metrics\":[{\"id\":\"pipeleek-high-verified-count\",\"type\":\"count\"}],\"label\":\"High-Verified Hits\",\"color\":\"#DC2626\",\"formatter\":\"number\",\"chart_type\":\"line\",\"line_width\":\"1\",\"point_size\":\"1\",\"fill\":\"0.5\"}],\"time_field\":\"@timestamp\",\"index_pattern\":\"pipeleek-logs-*\",\"default_index_pattern\":\"pipeleek-logs-*\",\"default_timefield\":\"@timestamp\",\"filter\":{\"language\":\"kuery\",\"query\":\"level:hit and confidence:\\\"high-verified\\\"\"},\"interval\":\"auto\",\"time_range_mode\":\"entire_time_range\",\"isModelInvalid\":false}}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"query\":{\"language\":\"kuery\",\"query\":\"\"},\"filter\":[]}"
    }
  }
}'
upsert_saved_object "visualization" "pipeleek-vis-high-verified-count" "$high_verified_metric_payload"

echo "Creating time-series visualization for ingestion volume..."
intake_timeseries_payload='{
  "attributes": {
    "title": "Pipeleek - Log Intake Over Time",
    "description": "Count of ingested log events over time",
    "visState": "{\"title\":\"Pipeleek - Log Intake Over Time\",\"type\":\"histogram\",\"params\":{\"addLegend\":false,\"addTooltip\":true,\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true},\"title\":{\"text\":\"Time\"}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true},\"title\":{\"text\":\"Log Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"stacked\",\"data\":{\"id\":\"1\",\"label\":\"Log Count\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":false,\"showCircles\":false}],\"grid\":{\"categoryLines\":false,\"style\":{\"color\":\"#eee\"}},\"times\":[],\"addTimeMarker\":false,\"dimensions\":{\"x\":{\"accessor\":\"2\",\"format\":\"date\",\"params\":{}},\"y\":[{\"accessor\":\"1\",\"format\":{\"id\":\"number\"}}]}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"schema\":\"segment\",\"params\":{\"field\":\"@timestamp\",\"useNormalizedEsInterval\":false,\"min_doc_count\":1,\"extended_bounds\":{},\"interval\":\"10m\",\"drop_partials\":false,\"time_zone\":\"UTC\"}}]}",
    "uiStateJSON": "{\"vis\":{\"colors\":{\"Log Count\":\"#0EA5E9\"}}}",
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"query\":{\"language\":\"kuery\",\"query\":\"\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"
    }
  },
  "references": [
    {
      "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
      "type": "index-pattern",
      "id": "pipeleek-logs"
    }
  ]
}'
upsert_saved_object "visualization" "pipeleek-vis-intake-timeseries" "$intake_timeseries_payload"

echo "Creating pie chart for hits vs hit artifacts..."
hits_vs_artifacts_pie_payload='{
  "attributes": {
    "title": "Pipeleek - Hits by Asset Type",
    "description": "Hit split by asset type (for example log vs artifact)",
    "visState": "{\"title\":\"Pipeleek - Hits by Asset Type\",\"type\":\"pie\",\"params\":{\"addLegend\":true,\"addTooltip\":true,\"isDonut\":true,\"legendPosition\":\"right\",\"labels\":{\"show\":true,\"values\":true}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"scan.asset_type\",\"size\":5,\"order\":\"desc\",\"orderBy\":\"1\",\"missingBucket\":true,\"missingBucketLabel\":\"unknown\"}}]}",
    "uiStateJSON": "{\"vis\":{\"colors\":{\"artifact\":\"#7C3AED\",\"log\":\"#0EA5E9\",\"unknown\":\"#94A3B8\"}}}",
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"query\":{\"language\":\"kuery\",\"query\":\"level:hit\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"
    }
  },
  "references": [
    {
      "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
      "type": "index-pattern",
      "id": "pipeleek-logs"
    }
  ]
}'
upsert_saved_object "visualization" "pipeleek-vis-hits-vs-artifacts-pie" "$hits_vs_artifacts_pie_payload"

echo "Creating pie chart for hit confidence ratings..."
ratings_pie_payload='{
  "attributes": {
    "title": "Pipeleek - Hits by Confidence",
    "description": "Hit count grouped by confidence rating",
    "visState": "{\"title\":\"Pipeleek - Hits by Confidence\",\"type\":\"pie\",\"params\":{\"addLegend\":true,\"addTooltip\":true,\"isDonut\":true,\"legendPosition\":\"right\",\"labels\":{\"show\":true,\"values\":true}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"confidence\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\",\"missingBucket\":true,\"missingBucketLabel\":\"unknown\"}}]}",
    "uiStateJSON": "{\"vis\":{\"colors\":{\"high-verified\":\"#DC2626\",\"high\":\"#F59E0B\",\"medium\":\"#22C55E\",\"low\":\"#38BDF8\",\"unknown\":\"#94A3B8\"}}}",
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"query\":{\"language\":\"kuery\",\"query\":\"level:hit\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"
    }
  },
  "references": [
    {
      "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
      "type": "index-pattern",
      "id": "pipeleek-logs"
    }
  ]
}'
upsert_saved_object "visualization" "pipeleek-vis-ratings-pie" "$ratings_pie_payload"

echo "Creating prebuilt dashboard..."
dashboard_payload='{
  "attributes": {
    "title": "Pipeleek - Hit Monitoring",
    "description": "High/high-verified counters, log intake over time, pie charts for hit distributions, latest 100 scan entries, and latest 100 raw log entries. Use dashboard filters for scan.platform and scan.confidence.",
    "hits": 0,
    "optionsJSON": "{\"useMargins\":true,\"hidePanelTitles\":false}",
    "panelsJSON": "[{\"type\":\"visualization\",\"panelIndex\":\"1\",\"gridData\":{\"x\":0,\"y\":0,\"w\":12,\"h\":8,\"i\":\"1\"},\"embeddableConfig\":{},\"panelRefName\":\"panel_1\",\"version\":\"8.13.4\"},{\"type\":\"visualization\",\"panelIndex\":\"2\",\"gridData\":{\"x\":12,\"y\":0,\"w\":12,\"h\":8,\"i\":\"2\"},\"embeddableConfig\":{},\"panelRefName\":\"panel_2\",\"version\":\"8.13.4\"},{\"type\":\"visualization\",\"panelIndex\":\"3\",\"gridData\":{\"x\":24,\"y\":0,\"w\":24,\"h\":8,\"i\":\"3\"},\"embeddableConfig\":{\"timeRange\":{\"from\":\"now-4h\",\"to\":\"now\"}},\"panelRefName\":\"panel_3\",\"version\":\"8.13.4\"},{\"type\":\"visualization\",\"panelIndex\":\"4\",\"gridData\":{\"x\":0,\"y\":8,\"w\":24,\"h\":12,\"i\":\"4\"},\"embeddableConfig\":{},\"panelRefName\":\"panel_4\",\"version\":\"8.13.4\"},{\"type\":\"visualization\",\"panelIndex\":\"5\",\"gridData\":{\"x\":24,\"y\":8,\"w\":24,\"h\":12,\"i\":\"5\"},\"embeddableConfig\":{},\"panelRefName\":\"panel_5\",\"version\":\"8.13.4\"},{\"type\":\"search\",\"panelIndex\":\"6\",\"gridData\":{\"x\":0,\"y\":20,\"w\":48,\"h\":12,\"i\":\"6\"},\"embeddableConfig\":{},\"panelRefName\":\"panel_6\",\"version\":\"8.13.4\"},{\"type\":\"search\",\"panelIndex\":\"7\",\"gridData\":{\"x\":0,\"y\":32,\"w\":48,\"h\":12,\"i\":\"7\"},\"embeddableConfig\":{},\"panelRefName\":\"panel_7\",\"version\":\"8.13.4\"}]",
    "version": 1,
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"query\":{\"language\":\"kuery\",\"query\":\"\"},\"filter\":[]}"
    }
  },
  "references": [
    {
      "name": "panel_1",
      "type": "visualization",
      "id": "pipeleek-vis-high-verified-count"
    },
    {
      "name": "panel_2",
      "type": "visualization",
      "id": "pipeleek-vis-high-count"
    },
    {
      "name": "panel_3",
      "type": "visualization",
      "id": "pipeleek-vis-intake-timeseries"
    },
    {
      "name": "panel_4",
      "type": "visualization",
      "id": "pipeleek-vis-hits-vs-artifacts-pie"
    },
    {
      "name": "panel_5",
      "type": "visualization",
      "id": "pipeleek-vis-ratings-pie"
    },
    {
      "name": "panel_6",
      "type": "search",
      "id": "pipeleek-search-last100"
    },
    {
      "name": "panel_7",
      "type": "search",
      "id": "pipeleek-search-logs-last100"
    }
  ]
}'
upsert_saved_object "dashboard" "pipeleek-dashboard-hit-monitoring" "$dashboard_payload"

echo "✓ Kibana setup complete!"
echo "✓ Dashboard available: Pipeleek - Hit Monitoring"
