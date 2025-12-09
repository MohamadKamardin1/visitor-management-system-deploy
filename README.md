# Visitor Management System (VMS) - Django Backend

A professional Visitor Management System built with Django REST Framework, featuring OTP verification, SMS notifications, and comprehensive visit tracking.

## Features

- **Visitor Check-in**: Kiosk and QR code support
- **OTP Verification**: Secure phone number verification via SMS (Telerivet)
- **Card Management**: Physical badge/card assignment and tracking with verification
- **Host Dashboard**: Professional dashboard for hosts to manage visitors
- **Secretary Dashboard**: Admin dashboard for managing all visits and cards
- **Host Management**: Host approval/rejection/finish workflow
- **Card Verification**: Card number verification on checkout
- **Audit Logging**: Comprehensive activity tracking
- **Rate Limiting**: Anti-fraud protection for OTP requests
- **Async SMS**: Celery-based SMS sending
- **RESTful API**: Complete REST API with Django REST Framework
- **Configurable Host Display**: Choose how hosts appear on kiosk (name/department/office)

## Tech Stack

- Django 6.0
- Django REST Framework
- PostgreSQL (production) / SQLite (development)
- Redis (caching and Celery broker)
- Celery (async tasks)
- Telerivet (SMS service)
- Bootstrap 5 (Dashboard UI)

## Installation

### Prerequisites

- Python 3.10+
- PostgreSQL (optional, SQLite for development)
- Redis
- Telerivet account (for SMS) - Sign up at https://telerivet.com

### Setup Steps

1. **Clone the repository** (if applicable) or navigate to the project directory

2. **Create and activate virtual environment**:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Set up environment variables**:
```bash
# See ENV_VARIABLES.md for all required variables
# Create .env file with Telerivet credentials and other settings
```

5. **Run migrations**:
```bash
python manage.py makemigrations
python manage.py migrate
```

6. **Create superuser**:
```bash
python manage.py createsuperuser
```

7. **Create initial data** (Hosts, Secretaries, Cards):
   - Use Django admin at `/admin/`
   - Or use the API endpoints

8. **Run Redis** (if not already running):
```bash
redis-server
```

9. **Run Celery worker** (in a separate terminal):
```bash
celery -A vms worker -l info
```

10. **Run Celery beat** (for periodic tasks, in another terminal):
```bash
celery -A vms beat -l info
```

11. **Run development server**:
```bash
python manage.py runserver
```

## Dashboards

### Host Dashboard
- URL: `/api/host/dashboard/`
- Features: View visits, approve/reject/finish visits, statistics
- See [DASHBOARD_FEATURES.md](DASHBOARD_FEATURES.md) for details

### Secretary Dashboard
- URL: `/api/secretary/dashboard/`
- Features: Manage all visits, assign/collect cards, view statistics
- See [DASHBOARD_FEATURES.md](DASHBOARD_FEATURES.md) for details

### Login
- URL: `/api/login/`
- Auto-redirects based on user type

## API Endpoints

### Public Endpoints (No Authentication Required)

- `POST /api/visits/check_in/` - Visitor check-in
- `POST /api/visits/request_otp/` - Request OTP
- `POST /api/visits/verify_otp/` - Verify OTP
- `GET /api/hosts/for_kiosk/` - Get hosts for kiosk selection (with display names)

### Authenticated Endpoints

- `GET /api/hosts/` - List hosts
- `GET /api/secretaries/` - List secretaries
- `GET /api/visitors/` - List visitors
- `GET /api/cards/` - List cards
- `GET /api/visits/` - List visits
- `POST /api/visits/{id}/host_action/` - Host actions (approve/reject/finish)
- `POST /api/visits/{id}/secretary_action/` - Secretary actions (assign/collect card)
- `GET /api/visits/my_visits/` - Get user's visits
- `GET /api/audit-logs/` - View audit logs

## API Usage Examples

### 1. Visitor Check-in

```bash
curl -X POST http://localhost:8000/api/visits/check_in/ \
  -H "Content-Type: application/json" \
  -d '{
    "phone_number": "+1234567890",
    "name": "John Doe",
    "host_id": 1,
    "purpose": "Business meeting",
    "check_in_method": "kiosk"
  }'
```

### 2. Request OTP

```bash
curl -X POST http://localhost:8000/api/visits/request_otp/ \
  -H "Content-Type: application/json" \
  -d '{
    "phone_number": "+1234567890",
    "visit_id": 1
  }'
```

### 3. Verify OTP

```bash
curl -X POST http://localhost:8000/api/visits/verify_otp/ \
  -H "Content-Type: application/json" \
  -d '{
    "phone_number": "+1234567890",
    "code": "123456",
    "visit_id": 1
  }'
```

### 4. Host Approve Visit

```bash
curl -X POST http://localhost:8000/api/visits/1/host_action/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Token YOUR_TOKEN" \
  -d '{
    "action": "approve",
    "instructions": "Please come to office 205"
  }'
```

## Project Structure

```
vms-backend/
├── core/                 # Main application
│   ├── models.py         # Database models
│   ├── serializers.py    # DRF serializers
│   ├── views.py          # API viewsets
│   ├── urls.py           # URL routing
│   ├── utils.py          # Utility functions
│   ├── services.py       # SMS service
│   └── tasks.py          # Celery tasks
├── vms/                  # Project settings
│   ├── settings.py       # Django settings
│   ├── urls.py           # Root URL config
│   └── celery.py         # Celery configuration
├── manage.py
├── requirements.txt
└── README.md
```

## Models

- **Host**: Staff members who receive visitors
- **Secretary**: Staff who manage card assignment
- **Visitor**: People visiting the facility
- **Visit**: Visit records with status tracking
- **Card**: Physical badges/cards
- **OTP**: One-time passwords for verification
- **AuditLog**: System activity logs

## Visit Status Flow

1. `pending_otp` - Waiting for OTP verification
2. `pending_card` - OTP verified, waiting for card assignment
3. `pending_host_approval` - Card assigned, waiting for host approval
4. `approved` - Host approved, visit in progress
5. `rejected` - Host rejected the visit
6. `finished` - Host marked visit as finished
7. `checked_out` - Card collected, visit completed
8. `cancelled` - Visit cancelled

## Environment Variables

See [ENV_VARIABLES.md](ENV_VARIABLES.md) for all available environment variables and Telerivet setup.

## Development

### Running Tests

```bash
python manage.py test
```

### Creating Migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### Accessing Admin Panel

Navigate to `http://localhost:8000/admin/` and login with superuser credentials.

### Accessing Dashboards

- **Host Dashboard**: `http://localhost:8000/api/host/dashboard/`
- **Secretary Dashboard**: `http://localhost:8000/api/secretary/dashboard/`
- **Login**: `http://localhost:8000/api/login/`

## Production Deployment

1. Set `DEBUG=False` in settings
2. Configure proper `ALLOWED_HOSTS`
3. Use PostgreSQL database
4. Set up proper Redis instance
5. Configure Telerivet credentials
6. Set up SSL/TLS certificates
7. Configure proper logging
8. Set up monitoring and backups

## Documentation

- [API_DOCUMENTATION.md](API_DOCUMENTATION.md) - Complete API reference
- [DASHBOARD_FEATURES.md](DASHBOARD_FEATURES.md) - Dashboard features and usage
- [ENV_VARIABLES.md](ENV_VARIABLES.md) - Environment variables configuration
- [SETUP_GUIDE.md](SETUP_GUIDE.md) - Detailed setup instructions

## License

This project is proprietary software.

## Support

For issues and questions, please contact the development team.

