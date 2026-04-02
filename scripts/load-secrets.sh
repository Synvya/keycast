#!/bin/bash
# Load secrets from AWS Secrets Manager into a .env file for Docker Compose.
# Usage: load-secrets.sh <staging|prod>
set -euo pipefail

ENV=${1:?Usage: load-secrets.sh <staging|prod>}
REGION=${AWS_REGION:-us-east-1}

get_secret() {
    aws secretsmanager get-secret-value \
        --secret-id "$1" \
        --query 'SecretString' \
        --output text \
        --region "$REGION"
}

if [ "$ENV" = "staging" ]; then
    DOMAIN=auth.staging.synvya.com
    DYNAMO_PREFIX=synvya-staging
elif [ "$ENV" = "prod" ]; then
    DOMAIN=auth.synvya.com
    DYNAMO_PREFIX=synvya
else
    echo "Error: environment must be 'staging' or 'prod'" >&2
    exit 1
fi

cat > /opt/synvya/.env <<EOF
# IMPORTANT: POSTGRES_PASSWORD must be alphanumeric only (no @, /, #, $ etc.)
# Special characters break URL parsing in DATABASE_URL connection strings.
# If this value is changed after first init, wipe the postgres volume: docker compose down -v
POSTGRES_PASSWORD=$(get_secret synvya/$ENV/keycast/postgres-password)
SERVER_NSEC=$(get_secret synvya/$ENV/keycast/server-nsec)
EP_SERVICE_TOKEN=$(get_secret synvya/$ENV/event-processor/service-token)
AWS_KMS_KEY_ID=alias/keycast-master-key
AWS_REGION=$REGION
BUNKER_RELAYS=wss://relay.damus.io,wss://nos.lol,wss://relay.snort.social
NOSTR_RELAYS=wss://relay.damus.io,wss://nos.lol,wss://relay.snort.social
ALLOWED_ORIGINS=https://$DOMAIN
BASE_URL=https://$DOMAIN
APP_URL=https://$DOMAIN
VITE_DOMAIN=https://$DOMAIN
FROM_EMAIL=noreply@synvya.com
FROM_NAME=Synvya
DYNAMODB_RESERVATION_TABLE=${DYNAMO_PREFIX}-reservation-state
DYNAMODB_CONFIG_TABLE=${DYNAMO_PREFIX}-restaurant-config
VITE_ALLOWED_PUBKEYS=$(get_secret synvya/$ENV/keycast/allowed-pubkeys 2>/dev/null || echo "")
EOF

chmod 600 /opt/synvya/.env
echo "Secrets loaded for $ENV environment -> /opt/synvya/.env"
