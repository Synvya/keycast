#!/bin/bash
# Load secrets from AWS Secrets Manager into a .env file for Docker Compose.
# Usage: load-secrets.sh <staging|production>
set -euo pipefail

ENV=${1:?Usage: load-secrets.sh <staging|production>}
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
    CUSTOMER_TENANT_DOMAIN=b2b-auth.staging.synvya.com
    # Local client development runs against staging
    ALLOW_LOCALHOST_ORIGINS=true
    LOCAL_DEV_ORIGINS=http://account.local.synvya.com:5173
    KMS_KEY_ID=alias/keycast-master-key
    INVITE_BASE_URL=https://account.staging.synvya.com
    PASSWORD_RESET_BASE_URL=https://account.staging.synvya.com
    ADMIN_BASE_URL=https://admin.staging.synvya.com
    BUNKER_RELAYS=wss://relay.staging.synvya.com
    VITE_NDK_EXPLICIT_RELAYS=wss://relay.staging.synvya.com
    VITE_NDK_BUNKER_RELAYS=wss://relay.staging.synvya.com
elif [ "$ENV" = "production" ]; then
    DOMAIN=auth.synvya.com
    # Customer accounts are off while this is empty. Set to b2b-auth.synvya.com to turn them on.
    CUSTOMER_TENANT_DOMAIN=
    ALLOW_LOCALHOST_ORIGINS=false
    LOCAL_DEV_ORIGINS=
    KMS_KEY_ID=alias/synvya-production-keycast-masterkey
    INVITE_BASE_URL=https://account.synvya.com
    PASSWORD_RESET_BASE_URL=https://account.synvya.com
    ADMIN_BASE_URL=https://admin.synvya.com
    BUNKER_RELAYS=wss://relay.synvya.com
    VITE_NDK_EXPLICIT_RELAYS=wss://relay.synvya.com
    VITE_NDK_BUNKER_RELAYS=wss://relay.synvya.com
else
    echo "Error: environment must be 'staging' or 'production'" >&2
    exit 1
fi

EXTRA_ALLOWED_ORIGINS="https://account.synvya.com,https://account.staging.synvya.com,https://server.synvya.com,https://server.staging.synvya.com,https://admin.synvya.com,https://admin.staging.synvya.com"
ALLOWED_PUBKEYS=$(get_secret synvya/$ENV/keycast/allowed-pubkeys 2>/dev/null || echo "")
# localhost: the post-deploy QA tests run on the host against http://localhost:3000
ALLOWED_TENANT_DOMAINS=$DOMAIN,localhost${CUSTOMER_TENANT_DOMAIN:+,$CUSTOMER_TENANT_DOMAIN}

cat > /opt/synvya/.env <<EOF
# IMPORTANT: POSTGRES_PASSWORD must be alphanumeric only (no @, /, #, $ etc.)
# Special characters break URL parsing in DATABASE_URL connection strings.
# If this value is changed after first init, wipe the postgres volume: docker compose down -v
POSTGRES_PASSWORD=$(get_secret synvya/$ENV/keycast/postgres-password)
SERVER_NSEC=$(get_secret synvya/$ENV/keycast/privatekey)
AWS_KMS_KEY_ID=$KMS_KEY_ID
AWS_REGION=$REGION
BUNKER_RELAYS=$BUNKER_RELAYS
VITE_NDK_EXPLICIT_RELAYS=$VITE_NDK_EXPLICIT_RELAYS
VITE_NDK_BUNKER_RELAYS=$VITE_NDK_BUNKER_RELAYS
ALLOWED_ORIGINS=https://$DOMAIN,$EXTRA_ALLOWED_ORIGINS${LOCAL_DEV_ORIGINS:+,$LOCAL_DEV_ORIGINS}
ALLOW_LOCALHOST_ORIGINS=$ALLOW_LOCALHOST_ORIGINS
ALLOWED_TENANT_DOMAINS=$ALLOWED_TENANT_DOMAINS
CUSTOMER_TENANT_DOMAIN=$CUSTOMER_TENANT_DOMAIN
BASE_URL=https://$DOMAIN
APP_URL=https://$DOMAIN
INVITE_BASE_URL=$INVITE_BASE_URL
PASSWORD_RESET_BASE_URL=$PASSWORD_RESET_BASE_URL
ADMIN_BASE_URL=$ADMIN_BASE_URL
VITE_DOMAIN=https://$DOMAIN
FROM_EMAIL=noreply@synvya.com
FROM_NAME=Synvya
ALLOWED_PUBKEYS=$ALLOWED_PUBKEYS
VITE_ALLOWED_PUBKEYS=$ALLOWED_PUBKEYS
EOF

chmod 600 /opt/synvya/.env
echo "Secrets loaded for $ENV environment -> /opt/synvya/.env"
