# Pipeleek Compose Example: Shared Config + ELK

This example runs Pipeleek scan jobs as one-shot containers and forwards all JSON logs into Elasticsearch via Logstash. Kibana is provided for querying and dashboards.

## What this setup provides

- One shared Pipeleek config file mounted read-only in every scan-job container.
- One Elasticsearch instance.
- Elasticsearch heap is tuned to 384MB for better stability in constrained local/dev environments.
- One Kibana instance.
- One Logstash instance that accepts newline-delimited JSON on TCP port 5000 and is tuned to 192MB heap for local/dev environments.
- One service definition per scan job:
  - `scan-gitlab`
  - `scan-github`
  - `scan-bitbucket`
  - `scan-devops`
  - `scan-gitea`
  - `scan-jenkins`

## 1) Prepare shared config

Edit `pipeleek.shared.example.yaml` and fill all token/url placeholders.

The file is mounted into each scanner as:

- Container path: `/config/pipeleek.yaml`
- Access mode: read-only

## 2) Start ELK services

Use the automated startup script that starts ELK and configures Kibana automatically:

```bash
bash start-elk.sh
```

This script:

1. Starts Elasticsearch, Logstash, and Kibana
2. Installs an Elasticsearch index template optimized for Pipeleek scan logs
3. Waits for Kibana to be ready
4. Automatically creates and configures the Kibana data view for pipeleek logs

**Manual alternative** (if you prefer to control services separately):

```bash
docker compose up -d elasticsearch logstash kibana
```

Then manually setup the index template and Kibana data view:

```bash
bash setup-elasticsearch.sh
bash setup-kibana.sh
```

## 3) Run one-shot scan jobs

Run any individual scan job with:

```bash
docker compose --profile gitlab run --rm scan-gitlab
docker compose --profile github run --rm scan-github
docker compose --profile bitbucket run --rm scan-bitbucket
docker compose --profile devops run --rm scan-devops
docker compose --profile gitea run --rm scan-gitea
docker compose --profile jenkins run --rm scan-jenkins
```

Each job:

1. Runs its own scan command using the shared config.
2. Streams each JSON line to Logstash over TCP.
3. Prints periodic progress updates every 30s to the container stderr so you can see it is still running.

## 4) View data in Kibana

Once you've run `bash start-elk.sh`, the Kibana data view is automatically configured. Simply:

1. Open http://localhost:5601
2. Open **Dashboards** and select `Pipeleek - Hit Monitoring`
3. You will see:

- `Pipeleek - High Hits` (count of `scan.confidence: high` hits)
- `Pipeleek - High-Verified Hits` (count of `scan.confidence: high-verified` hits)
- `Pipeleek - Log Intake Over Time` (bar chart over the last 4 hours with fixed 10-minute buckets)
- `Pipeleek - Hits by Asset Type` (pie chart, for example hit logs vs hit artifacts)
- `Pipeleek - Hits by Confidence` (pie chart of confidence ratings)
- `Pipeleek - Last 100 Scan Entries` table (hit-level events only)
- `Pipeleek - Latest 100 Log Entries` table (sorted by newest first, no fixed filter)

4. Use the dashboard filter bar to filter by fields like `scan.platform` and `scan.confidence`

Hit-focused panels use hit events (`level=hit`). If no hits are present in the selected time range, those panels will show no results.

You can also use **Discover** with the same data view for ad-hoc investigation.

For better searchability, logs are also normalized into common fields:

- `scan.platform`
- `scan.level`
- `scan.confidence`
- `scan.job_name`
- `scan.target_url`
- `scan.asset_type`
- `scan.is_hit`
- `secret.rule_name`
- `secret.is_present`
- `event.kind`
- `event.category`
- `event.type`
- `event.outcome`

**If you manually started ELK**, run the setup script:

```bash
bash setup-kibana.sh
```