# deploy.ps1 - Deploy Nano backend to Google Cloud Run (Windows Version)
# Usage: .\deploy.ps1 [PROJECT_ID] [REGION]

$ErrorActionPreference = "Stop"

$PROJECT_ID = if ($args[0]) { $args[0] } else { "your-gcp-project-id" }
$REGION = if ($args[1]) { $args[1] } else { "us-central1" }
$SERVICE_NAME = "superlock-api"
$SKIP_BUILD = if ($args[2] -eq "skip") { $true } else { $false }
# Modern Artifact Registry path for better reliability
$IMAGE = "${REGION}-docker.pkg.dev/$PROJECT_ID/cloud-run-source/$SERVICE_NAME"

if (-not $SKIP_BUILD) {
    Write-Host "[BUILD] Building and Pushing image via Google Cloud Build..." -ForegroundColor Cyan
    gcloud builds submit --tag $IMAGE --project $PROJECT_ID .
} else {
    Write-Host "[BUILD] Skipping build phase (using existing image)." -ForegroundColor Yellow
}

Write-Host "[CONFIG] Generating env.yaml from .env..." -ForegroundColor Cyan
if (Test-Path .env) {
    # Generate a flat YAML map (no top-level 'env_variables:' key)
    $yamlContent = ""
    Get-Content .env | Where-Object { $_ -match "=" -and $_ -notmatch "^#" } | ForEach-Object {
        $parts = $_ -split "=", 2
        if ($parts.Length -eq 2) {
            $key = $parts[0].Trim()
            $val = $parts[1].Trim()
            # Cloud Run reserved variables: skip PORT
            if ($key -eq "PORT") { return }
            # Remove existing quotes if any, then wrap in double quotes for YAML safety
            $val = $val -replace '^"|"$', ''
            $yamlContent += "${key}: `"${val}`"`n"
        }
    }
    $yamlContent | Set-Content -Path env.yaml -Encoding utf8
} else {
    Write-Host "[WARN] .env file not found, using default APP_ENV=production" -ForegroundColor Yellow
    Set-Content -Path env.yaml -Value "APP_ENV: `"production`"" -Encoding utf8
}

Write-Host "[DEPLOY] Deploying to Cloud Run..." -ForegroundColor Cyan
gcloud run deploy $SERVICE_NAME `
  --image $IMAGE `
  --platform managed `
  --region $REGION `
  --allow-unauthenticated `
  --port 8080 `
  --memory 512Mi `
  --cpu 1 `
  --min-instances 0 `
  --max-instances 10 `
  --env-vars-file env.yaml `
  --project $PROJECT_ID

# Cleanup the temporary yaml file
if (Test-Path env.yaml) { Remove-Item env.yaml }

Write-Host "`n[SUCCESS] Deployed! Service URL:" -ForegroundColor Green
gcloud run services describe $SERVICE_NAME `
  --platform managed `
  --region $REGION `
  --format "value(status.url)" `
  --project $PROJECT_ID
