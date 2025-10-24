#!/bin/bash
set -e

echo "Initializing databases..."

# Create keycloak user and database
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Create keycloak user
    CREATE USER keycloak WITH PASSWORD 'keycloak';
    
    -- Create keycloak database
    CREATE DATABASE keycloak OWNER keycloak;
    
    -- Grant privileges
    GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;
EOSQL

echo "Keycloak database and user created successfully"
