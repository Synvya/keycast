#!/bin/bash
set -e

# Make scripts executable
chmod +x "$(dirname "$0")/generate_key.sh"
chmod +x "$0"

# Function to print usage
print_usage() {
    echo "Usage: $0 --domain <domain> [--allowed-pubkeys <pubkeys>] [--file <filename>]"
    echo "Example:"
    echo "  $0 --domain keycast.example.com"
    echo "  $0 --domain keycast.example.com --file .env.local"
    exit 1
}

# Parse named arguments
ENV_FILE=".env"
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --domain) DOMAIN="$2"; shift ;;
        --allowed-pubkeys) ALLOWED_PUBKEYS="$2"; shift ;;
        --file) ENV_FILE="$2"; shift ;;
        *) echo "Unknown parameter: $1"; print_usage ;;
    esac
    shift
done

# Check if domain is provided
if [ -z "$DOMAIN" ]; then
    echo "Error: --domain argument is required"
    print_usage
fi

# Strip protocol and trailing slashes from domain
DOMAIN=$(echo "$DOMAIN" | sed -e 's|^[^/]*//||' -e 's|/.*$||')

echo "Using domain: $DOMAIN"
if [ -n "$ALLOWED_PUBKEYS" ]; then
    echo "Using allowed pubkeys: $ALLOWED_PUBKEYS"
else
    echo "No allowed pubkeys specified. Defaulting to allow all pubkeys."
fi

# Check if master.key exists
if [ ! -f "./master.key" ]; then
    echo "Generating master.key..."
    bash "$(dirname "$0")/generate_key.sh"
fi

# Create database directory if it doesn't exist
mkdir -p database

# Create env file from example if it doesn't exist
if [ ! -f "$ENV_FILE" ]; then
    echo "Creating $ENV_FILE file..."
    cp .env.example "$ENV_FILE"

    # Update domain in environment file
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS requires an empty string after -i
        sed -i '' "s/DOMAIN=.*/DOMAIN=$DOMAIN/" "$ENV_FILE"
        # Update allowed pubkeys (escape for sed)
        ESCAPED_PUBKEYS=$(echo "${ALLOWED_PUBKEYS:-}" | sed 's/[\/&]/\\&/g')
        sed -i '' "s/ALLOWED_PUBKEYS=.*/ALLOWED_PUBKEYS=$ESCAPED_PUBKEYS/" "$ENV_FILE"
    else
        # Linux version
        sed -i "s/DOMAIN=.*/DOMAIN=$DOMAIN/" "$ENV_FILE"
        # Update allowed pubkeys (escape for sed)
        ESCAPED_PUBKEYS=$(echo "${ALLOWED_PUBKEYS:-}" | sed 's/[\/&]/\\&/g')
        sed -i "s/ALLOWED_PUBKEYS=.*/ALLOWED_PUBKEYS=$ESCAPED_PUBKEYS/" "$ENV_FILE"
    fi
    echo "Updated DOMAIN in $ENV_FILE to: $DOMAIN"
    echo "Updated ALLOWED_PUBKEYS in $ENV_FILE to: ${ALLOWED_PUBKEYS:-<empty>}"
else
    echo "Note: $ENV_FILE file already exists. Skipping file creation."
    echo "If you need to update the values, edit the $ENV_FILE file manually."
fi

echo "✅ Initialization complete!"
echo "🔑 Generated master key"
echo "📁 Created database directory"
echo "⚙️  Created .env file with:"
echo "   - Domain: $DOMAIN"
echo "   - Allowed pubkeys: ${ALLOWED_PUBKEYS:-<empty>}"
echo ""
echo "Next steps:"
echo "1. Make sure your DNS records are set up for $DOMAIN"
echo "2. Run 'docker-compose build' to build the docker images"
echo "3. Run 'docker-compose up -d' to start the services"

