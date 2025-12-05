# PySOAR

**Security Orchestration, Automation and Response Platform**

PySOAR is a modern, Python-based SOAR platform designed to help security teams automate incident response, manage alerts, and integrate with threat intelligence sources.

## Features

- **Alert Management**: Ingest, triage, and manage security alerts from multiple sources
- **Incident Response**: Create and track security incidents with full lifecycle management
- **Playbook Automation**: Build and execute automated response playbooks
- **Threat Intelligence**: Integrate with VirusTotal, AbuseIPDB, Shodan, GreyNoise, and more
- **IOC Management**: Track and enrich Indicators of Compromise
- **Asset Inventory**: Maintain an inventory of your assets for context enrichment
- **Audit Logging**: Full audit trail of all actions for compliance
- **RESTful API**: Complete API for integration with other tools
- **Role-Based Access**: Admin, Analyst, and Viewer roles

## Quick Start

### Prerequisites

- Python 3.11+
- Redis (for Celery task queue)
- PostgreSQL (optional, SQLite for development)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/pysoar.git
cd pysoar

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env
# Edit .env with your configuration

# Run database migrations
alembic upgrade head

# Start the application
python -m src.main
```

The API will be available at `http://localhost:8000` with interactive docs at `/api/v1/docs`.

### Docker Setup

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f api

# Stop services
docker-compose down
```

## Configuration

Key environment variables (see `.env.example` for full list):

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | SQLite (dev) |
| `REDIS_URL` | Redis connection string | localhost:6379 |
| `JWT_SECRET_KEY` | Secret key for JWT tokens | Change in production! |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | Optional |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | Optional |
| `SHODAN_API_KEY` | Shodan API key | Optional |

## API Documentation

Once running, access the interactive API documentation:

- **Swagger UI**: http://localhost:8000/api/v1/docs
- **ReDoc**: http://localhost:8000/api/v1/redoc

### Authentication

```bash
# Login to get tokens
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@pysoar.local", "password": "changeme123"}'

# Use the access token for authenticated requests
curl http://localhost:8000/api/v1/alerts \
  -H "Authorization: Bearer <access_token>"
```

## Architecture

```
pysoar/
├── src/
│   ├── api/              # FastAPI routes and endpoints
│   │   └── v1/
│   │       └── endpoints/
│   ├── core/             # Core configuration and utilities
│   ├── integrations/     # Threat intelligence integrations
│   ├── models/           # SQLAlchemy database models
│   ├── playbooks/        # Playbook engine and actions
│   ├── schemas/          # Pydantic request/response schemas
│   ├── services/         # Business logic services
│   └── workers/          # Celery background tasks
├── tests/                # Test suite
├── alembic/              # Database migrations
└── docker-compose.yml    # Docker orchestration
```

## Playbook Actions

Available actions for playbook automation:

| Action | Description |
|--------|-------------|
| `enrich_ip` | Enrich IP address with threat intelligence |
| `enrich_domain` | Enrich domain with threat intelligence |
| `enrich_hash` | Enrich file hash with threat intelligence |
| `send_notification` | Send notification via email/Slack/Teams |
| `update_alert` | Update alert status or fields |
| `create_incident` | Create a new incident |
| `run_script` | Execute a predefined script |
| `conditional` | Branch based on conditions |
| `wait` | Pause execution |

### Example Playbook

```json
{
  "name": "IP Enrichment Playbook",
  "trigger_type": "alert",
  "trigger_conditions": {
    "severity": ["high", "critical"],
    "has_source_ip": true
  },
  "steps": [
    {
      "id": "enrich",
      "name": "Enrich Source IP",
      "action": "enrich_ip",
      "parameters": {},
      "on_success": "check_malicious"
    },
    {
      "id": "check_malicious",
      "name": "Check if Malicious",
      "action": "conditional",
      "parameters": {
        "field": "is_malicious",
        "operator": "equals",
        "value": true
      },
      "on_success": "notify",
      "on_failure": null
    },
    {
      "id": "notify",
      "name": "Send Alert",
      "action": "send_notification",
      "parameters": {
        "channel": "slack",
        "message": "Malicious IP detected: {{source_ip}}"
      }
    }
  ]
}
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/unit/test_auth.py
```

### Code Quality

```bash
# Format code
black src tests

# Sort imports
isort src tests

# Lint
flake8 src tests

# Type checking
mypy src
```

### Running Celery Workers

```bash
# Start worker
celery -A src.workers.celery_app worker --loglevel=info

# Start beat scheduler
celery -A src.workers.celery_app beat --loglevel=info

# Start Flower monitoring
celery -A src.workers.celery_app flower --port=5555
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/)
- Task queue powered by [Celery](https://celeryproject.org/)
- Database ORM by [SQLAlchemy](https://www.sqlalchemy.org/)
