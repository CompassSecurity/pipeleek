#!/bin/bash
# Configure Elasticsearch index template for Pipeleek logs.

set -e

ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://localhost:9200}"
TEMPLATE_NAME="pipeleek-logs-template"
INDEX_PATTERN="pipeleek-logs-*"
MAX_RETRIES=60
RETRY_DELAY=2

echo "Waiting for Elasticsearch at $ELASTICSEARCH_URL..."
for i in $(seq 1 "$MAX_RETRIES"); do
  if curl -fsS "$ELASTICSEARCH_URL" >/dev/null 2>&1; then
    echo "✓ Elasticsearch is reachable"
    break
  fi

  if [ "$i" -eq "$MAX_RETRIES" ]; then
    echo "✗ Elasticsearch did not become reachable after $((MAX_RETRIES * RETRY_DELAY)) seconds"
    exit 1
  fi

  sleep "$RETRY_DELAY"
done

echo "Installing index template $TEMPLATE_NAME for $INDEX_PATTERN..."
curl -fsS -X PUT "$ELASTICSEARCH_URL/_index_template/$TEMPLATE_NAME" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["pipeleek-logs-*"],
    "priority": 500,
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
      },
      "mappings": {
        "dynamic": true,
        "properties": {
          "@timestamp": {"type": "date"},
          "time": {"type": "date"},
          "level": {"type": "keyword"},
          "message": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
          "scan_job": {"type": "keyword"},
          "ingest_pipeline": {"type": "keyword"},
          "source": {"type": "keyword"},
          "confidence": {"type": "keyword"},
          "ruleName": {"type": "keyword"},
          "job": {"type": "keyword"},
          "url": {"type": "keyword"},
          "value": {"type": "text"},
          "event": {
            "properties": {
              "module": {"type": "keyword"},
              "dataset": {"type": "keyword"},
              "kind": {"type": "keyword"},
              "category": {"type": "keyword"},
              "type": {"type": "keyword"},
              "outcome": {"type": "keyword"}
            }
          },
          "scan": {
            "properties": {
              "platform": {"type": "keyword"},
              "source": {"type": "keyword"},
              "level": {"type": "keyword"},
              "confidence": {"type": "keyword"},
              "job_name": {"type": "keyword"},
              "target_url": {"type": "keyword"},
              "asset_type": {"type": "keyword"},
              "message": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
              "is_hit": {"type": "boolean"}
            }
          },
          "secret": {
            "properties": {
              "is_present": {"type": "boolean"},
              "rule_name": {"type": "keyword"}
            }
          }
        }
      }
    }
  }' >/dev/null

echo "✓ Elasticsearch index template installed"
