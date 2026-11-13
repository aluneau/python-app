# Data Analytics Service

A FastAPI-based data analytics service for collecting and processing system metrics.

## Features

- **REST API** with FastAPI
- **System Discovery**: Automatically detects system configuration and metrics
- **Data Collection**: Collects system data using TCP connections
- **Async Processing**: Fully asynchronous for better performance
- **Common Data Sources**: Automatically includes common data sources when none specified
- **Service Ports**: Monitors ~40 common service ports for data collection

## API Endpoints

- `GET /` - API info
- `GET /health` - Health check
- `GET /api/v1/network/info` - Get system configuration
- `GET /api/v1/network/public-ip` - Get external IP information
- `POST /api/v1/scan` - Start data collection
- `GET /api/v1/scan/{scan_id}` - Get collection status
- `GET /api/v1/scan/{scan_id}/results` - Get collection results
- `GET /api/v1/scans` - List all collections
- `GET /api/v1/ports` - List monitored ports

## Running Locally

```bash
pip install -r requirements.txt
python main.py
```

Or with uvicorn directly:
```bash
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

## Kubernetes Deployment

`k8s/daemonset.yaml` runs one collector per node with `hostNetwork: true`, so each
instance sees its node's real interfaces and configuration.

```bash
docker build -t <registry>/data-analytics:latest .
docker push <registry>/data-analytics:latest
# set the image in k8s/daemonset.yaml, then:
kubectl apply -f k8s/daemonset.yaml
curl http://<node-ip>:8080/api/v1/network/info
```

## Usage Examples

```bash
# Get system info
curl http://localhost:8080/api/v1/network/info

# Start data collection
curl -X POST http://localhost:8080/api/v1/scan -H "Content-Type: application/json" -d '{}'

# Check collection status
curl http://localhost:8080/api/v1/scan/{scan_id}

# Get collection results
curl http://localhost:8080/api/v1/scan/{scan_id}/results
```
