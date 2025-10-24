# Auth Manager Service - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Prerequisites

- Docker and Docker Compose installed
- 5 minutes of your time

### Step 1: Clone and Navigate

```bash
cd auth-manager-svc
```

### Step 2: Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Generate encryption key and update .env
export ENCRYPTION_KEY=$(openssl rand -hex 32)
echo "AUTH_MANAGER_TOKEN_VAULT_ENCRYPTION_KEY=$ENCRYPTION_KEY" >> .env
```

### Step 3: Start Services

```bash
# Start PostgreSQL and Auth Manager
make dev-docker
```

### Step 4: Verify Installation

```bash
# Check health
curl http://localhost:8000/health

# Check readiness
curl http://localhost:8000/health/ready

# View API documentation
open http://localhost:8000/docs
```

## 🎯 Common Commands

### Service Management

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# Restart service
docker-compose restart auth-manager

# View logs
docker-compose logs -f auth-manager

# Check service status
docker-compose ps
```

### Development Mode

```bash
# Start with hot-reload
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Run with Keycloak
docker-compose --profile with-keycloak up -d
```

### Database Operations

```bash
# Run migrations
docker-compose exec auth-manager alembic upgrade head

# Check migration status
docker-compose exec auth-manager alembic current

# Create new migration
docker-compose exec auth-manager alembic revision --autogenerate -m "Description"

# Access database
docker-compose exec postgres psql -U postgres -d auth_manager
```

### Debugging

```bash
# Access container shell
docker-compose exec auth-manager /bin/bash

# View environment variables
docker-compose exec auth-manager env | grep -E "DATABASE|KEYCLOAK"

# Check Python version
docker-compose exec auth-manager python --version

# Test database connection
docker-compose exec auth-manager python -c "from app.db.base import db_manager; print('DB OK')"
```

### Cleanup

```bash
# Stop and remove containers
docker-compose down

# Remove volumes (WARNING: deletes data)
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

## 🔧 Troubleshooting

### Service won't start?

```bash
# Check logs for errors
docker-compose logs auth-manager

# Verify environment variables
docker-compose config

# Ensure database is running
docker-compose ps postgres
```

### Database connection issues?

```bash
# Check database is healthy
docker-compose exec postgres pg_isready -U postgres

# Verify DATABASE_URL in .env
grep DATABASE_URL .env

# Test connection manually
docker-compose exec postgres psql -U postgres -d auth_manager -c "SELECT 1;"
```

### Port already in use?

```bash
# Change port in docker-compose.yml or use:
PORT=8001 docker-compose up -d
```

## 📚 Next Steps

- Read [DEPLOYMENT.md](./DEPLOYMENT.md) for production deployment
- Check [README.md](./README.md) for detailed documentation
- Visit http://localhost:8000/docs for API documentation

## 🆘 Need Help?

1. Check logs: `docker-compose logs auth-manager`
2. Verify health: `curl http://localhost:8000/health`
3. Review [DEPLOYMENT.md](./DEPLOYMENT.md) troubleshooting section
