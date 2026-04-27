#!/bin/bash
# Start ELK stack and automatically setup Kibana data view when ready

set -e

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
KIBANA_HEALTH_ENDPOINT="$KIBANA_URL/api/status"
MAX_RETRIES=120
RETRY_DELAY=2

echo "Starting ELK services..."
DOCKER_API_VERSION=1.43 docker compose up -d elasticsearch logstash kibana

echo "Configuring Elasticsearch index template..."
bash setup-elasticsearch.sh

echo "Waiting for Kibana to be fully ready at $KIBANA_URL..."
for i in $(seq 1 $MAX_RETRIES); do
  if curl -s "$KIBANA_HEALTH_ENDPOINT" 2>/dev/null | grep -q '"level":"available"'; then
    # Extra check: try an actual API call to make sure it's really ready
    if curl -s -X GET "$KIBANA_URL/api/saved_objects" -H "kbn-xsrf: true" >/dev/null 2>&1; then
      echo "✓ Kibana is fully ready!"
      break
    fi
  fi
  if [ $i -eq $MAX_RETRIES ]; then
    echo "✗ Kibana did not become ready after $((MAX_RETRIES * RETRY_DELAY)) seconds"
    exit 1
  fi
  if [ $((i % 10)) -eq 0 ]; then
    echo "  Waiting... ($i/$MAX_RETRIES)"
  fi
  sleep $RETRY_DELAY
done

echo ""
echo "Setting up Kibana data view for Pipeleek logs..."
bash setup-kibana.sh

echo ""
echo "✅ All done! ELK stack is ready."
echo "📊 Open Kibana at $KIBANA_URL and go to Discover to see your logs."
