#!/bin/bash
# deploy.sh - Deploy Nano backend to Google Cloud Run
# Usage: ./deploy.sh [PROJECT_ID] [REGION]

set -e

PROJECT_ID=${1:-"your-gcp-project-id"}
REGION=${2:-"us-central1"}
SERVICE_NAME="nano-api"
IMAGE="gcr.io/$PROJECT_ID/$SERVICE_NAME"

echo "🔨 Building Docker image..."
docker build -t "$IMAGE" .

echo "📤 Pushing to Google Container Registry..."
docker push "$IMAGE"

echo "📝 Loading environment variables from .env..."
if [ -f .env ]; then
  # Read .env, ignore comments/empty lines, and join with commas
  # We use sed to handle potential spaces and ensure proper formatting
  ENV_VARS=$(grep -v '^#' .env | grep -v '^$' | xargs | tr ' ' ',')
else
  echo "⚠️ .env file not found, using default APP_ENV=production"
  ENV_VARS="APP_ENV=production"
fi

echo "🚀 Deploying to Cloud Run..."
gcloud run deploy "$SERVICE_NAME" \
  --image "$IMAGE" \
  --platform managed \
  --region "$REGION" \
  --allow-unauthenticated \
  --port 8080 \
  --memory 512Mi \
  --cpu 1 \
  --min-instances 0 \
  --max-instances 10 \
  --set-env-vars "$ENV_VARS" \
  --project "$PROJECT_ID"

echo "✅ Deployed! Service URL:"
gcloud run services describe "$SERVICE_NAME" \
  --platform managed \
  --region "$REGION" \
  --format 'value(status.url)' \
  --project "$PROJECT_ID"
