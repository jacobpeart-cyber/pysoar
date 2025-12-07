# PySOAR

**Security Orchestration, Automation and Response Platform**

PySOAR is a modern, full-stack SOAR platform with a Python/FastAPI backend and React/TypeScript frontend. Designed to help security teams automate incident response, manage alerts, and integrate with threat intelligence sources.

## Features

### Core Capabilities
- **Alert Management**: Ingest, triage, and manage security alerts from multiple sources
- **Incident Response**: Create and track security incidents with full lifecycle management
- **Case Management**: Notes, tasks, timeline, and file attachments for incidents
- **Playbook Automation**: Build and execute automated response playbooks
- **IOC Management**: Track and enrich Indicators of Compromise

### Threat Intelligence
- **Multi-source Lookup**: Query VirusTotal, AbuseIPDB, Shodan, GreyNoise, MISP
- **Threat Feed Integration**: Subscribe to and manage threat intelligence feeds
- **IOC Database**: Centralized repository for all threat indicators
- **Automated Enrichment**: Auto-enrich alerts and incidents with threat intel

### Integrations
- **SIEM**: Elasticsearch, Splunk
- **Notifications**: Slack, PagerDuty, Microsoft Teams, Email (SMTP)
- **Threat Intel**: VirusTotal, AbuseIPDB, Shodan, GreyNoise, MISP, Cortex
- **Analysis**: Cortex for observable analysis

### Administration
- **User Management**: RBAC with admin, analyst, and viewer roles
- **Organizations & Teams**: Multi-tenant support with team-based access
- **API Keys**: Generate and manage API keys for programmatic access
- **Audit Logging**: Complete audit trail of all user actions
- **Dark Mode**: Full dark mode support across the UI

### Analytics & Reporting
- **Real-time Dashboard**: Live metrics and KPIs
- **Analytics**: Alert trends, severity distribution, top sources
- **Reports**: Generate and export security reports
- **WebSocket Updates**: Real-time notifications and updates

## Tech Stack

### Backend
- **Framework**: FastAPI (Python 3.11+)
- **Database**: SQLite (development) / PostgreSQL (production)
- **ORM**: SQLAlchemy 2.0 with async support
- **Authentication**: JWT tokens with bcrypt password hashing
- **WebSocket**: Real-time updates and notifications

### Frontend
- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite
- **Styling**: TailwindCSS v4 with dark mode
- **State Management**: React Query (TanStack Query)
- **Routing**: React Router v6
- **Icons**: Lucide React

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- npm or yarn

### Backend Installation

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

# Start the backend server
python -m src.main
```

The API will be available at `http://localhost:8000` with interactive docs at `/docs`.

### Frontend Installation

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start the development server
npm run dev
```

The frontend will be available at `http://localhost:5173`.

### Default Login

- **Email**: admin@pysoar.local
- **Password**: admin123

**Important**: Change the default password after first login!

### Docker Deployment

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Configuration

Key environment variables (see `.env.example` for full list):

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | SQLite (dev) |
| `SECRET_KEY` | Application secret key | Change in production! |
| `JWT_SECRET_KEY` | Secret key for JWT tokens | Change in production! |
| `SMTP_HOST` | SMTP server for emails | Optional |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | Optional |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | Optional |
| `SHODAN_API_KEY` | Shodan API key | Optional |
| `SLACK_WEBHOOK_URL` | Slack webhook for notifications | Optional |

## API Documentation

Once running, access the interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Authentication

```bash
# Login to get tokens
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@pysoar.local", "password": "admin123"}'

# Use the access token for authenticated requests
curl http://localhost:8000/api/v1/alerts \
  -H "Authorization: Bearer <access_token>"
```

### Main Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/health` | Health check |
| `POST /api/v1/auth/login` | User login |
| `GET /api/v1/alerts` | List alerts |
| `GET /api/v1/incidents` | List incidents |
| `GET /api/v1/incidents/{id}/notes` | Get incident notes |
| `GET /api/v1/incidents/{id}/tasks` | Get incident tasks |
| `GET /api/v1/incidents/{id}/timeline` | Get incident timeline |
| `GET /api/v1/iocs` | List IOCs |
| `GET /api/v1/playbooks` | List playbooks |
| `GET /api/v1/assets` | List assets |
| `GET /api/v1/threat-intel/lookup` | Lookup IOC |
| `GET /api/v1/organizations` | List organizations |
| `GET /api/v1/api-keys` | List API keys |
| `GET /api/v1/settings` | Get settings |
| `GET /api/v1/audit` | Audit logs |
| `GET /api/v1/metrics` | System metrics |

## Project Structure

```
pysoar/
├── src/                     # Backend (Python/FastAPI)
│   ├── api/                 # API routes and endpoints
│   │   └── v1/
│   │       └── endpoints/
│   │           ├── alerts.py
│   │           ├── incidents.py
│   │           ├── case_management.py
│   │           ├── organizations.py
│   │           ├── api_keys.py
│   │           └── ...
│   ├── core/                # Core configuration
│   │   ├── config.py
│   │   ├── security.py
│   │   └── database.py
│   ├── integrations/        # External integrations
│   ├── models/              # SQLAlchemy models
│   ├── schemas/             # Pydantic schemas
│   ├── services/            # Business logic
│   └── main.py              # Application entry
├── frontend/                # Frontend (React/TypeScript)
│   ├── src/
│   │   ├── components/      # Reusable components
│   │   ├── contexts/        # React contexts
│   │   ├── hooks/           # Custom hooks
│   │   ├── lib/             # API client
│   │   └── pages/           # Page components
│   │       ├── Dashboard.tsx
│   │       ├── Alerts.tsx
│   │       ├── Incidents.tsx
│   │       ├── ThreatIntel.tsx
│   │       ├── Organizations.tsx
│   │       ├── ApiKeys.tsx
│   │       ├── Analytics.tsx
│   │       └── ...
│   └── package.json
├── tests/                   # Test suite
├── docker-compose.yml       # Docker orchestration
├── Dockerfile               # Backend container
└── requirements.txt         # Python dependencies
```

## Frontend Pages

| Route | Page | Description |
|-------|------|-------------|
| `/` | Dashboard | Overview with metrics and recent activity |
| `/alerts` | Alerts | Alert management and triage |
| `/alerts/:id` | Alert Detail | Single alert view with enrichment |
| `/incidents` | Incidents | Incident list and management |
| `/incidents/:id` | Incident Detail | Case management with notes, tasks, timeline |
| `/iocs` | IOCs | IOC management |
| `/threat-intel` | Threat Intel | IOC lookup and threat feeds |
| `/playbooks` | Playbooks | Playbook management |
| `/assets` | Assets | Asset inventory |
| `/analytics` | Analytics | Metrics and trends |
| `/reports` | Reports | Report generation |
| `/users` | Users | User management (admin) |
| `/organizations` | Organizations | Org/team management (admin) |
| `/api-keys` | API Keys | API key management |
| `/settings` | Settings | System configuration |
| `/audit` | Audit Logs | Audit trail (admin) |
| `/profile` | Profile | User profile |

## Playbook Example

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
      "parameters": {}
    },
    {
      "id": "check",
      "name": "Check if Malicious",
      "action": "conditional",
      "parameters": {
        "field": "is_malicious",
        "operator": "equals",
        "value": true
      },
      "on_success": "notify"
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
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

### Code Quality

```bash
# Format code
black src/
ruff check src/

# Frontend
cd frontend && npm run lint
```

## Security Considerations

- All passwords hashed with bcrypt
- JWT tokens with configurable expiration
- API keys hashed, never stored plain text
- RBAC enforced at API and UI level
- Audit logging for sensitive operations
- Input validation on all endpoints
- CORS configured for production

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/)
- Frontend powered by [React](https://reactjs.org/) and [Vite](https://vitejs.dev/)
- Styled with [TailwindCSS](https://tailwindcss.com/)
- Database ORM by [SQLAlchemy](https://www.sqlalchemy.org/)
