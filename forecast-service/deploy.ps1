<#
.SYNOPSIS
    Build and deploy the CPE Forecast Service to AWS.

.DESCRIPTION
    Uses AWS SAM CLI to build the Docker container image and deploy to Lambda.
    Run from the forecast-service/ directory.

.PARAMETER Environment
    Deployment environment (dev, staging, prod). Default: dev

.PARAMETER Region
    AWS region. Default: eu-west-2

.EXAMPLE
    .\deploy.ps1
    .\deploy.ps1 -Environment prod -Region eu-west-2
#>

param(
    [ValidateSet("dev", "staging", "prod")]
    [string]$Environment = "dev",

    [string]$Region = "eu-west-2",

    [switch]$Guided
)

$ErrorActionPreference = "Stop"
$StackName = "cpe-forecast-service-$Environment"

Write-Host "`n=== CPE Forecast Service Deployment ===" -ForegroundColor Cyan
Write-Host "Environment: $Environment"
Write-Host "Region:      $Region"
Write-Host "Stack:       $StackName"
Write-Host ""

# Check prerequisites
foreach ($cmd in @("sam", "docker", "aws")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Error "$cmd is not installed or not in PATH"
        exit 1
    }
}

# Verify Docker is running
docker info 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker is not running. Please start Docker Desktop."
    exit 1
}

# Build
Write-Host "`n--- Building container image ---" -ForegroundColor Yellow
sam build --use-container

if ($LASTEXITCODE -ne 0) {
    Write-Error "SAM build failed"
    exit 1
}

# Deploy
Write-Host "`n--- Deploying to AWS ---" -ForegroundColor Yellow

$deployArgs = @(
    "deploy",
    "--stack-name", $StackName,
    "--region", $Region,
    "--capabilities", "CAPABILITY_IAM",
    "--parameter-overrides", "Environment=$Environment",
    "--no-confirm-changeset",
    "--resolve-image-repos"
)

if ($Guided) {
    $deployArgs = @("deploy", "--guided")
}

sam @deployArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "SAM deploy failed"
    exit 1
}

Write-Host "`n=== Deployment complete ===" -ForegroundColor Green
Write-Host "Stack: $StackName"
Write-Host ""

# Show outputs
Write-Host "--- Stack Outputs ---" -ForegroundColor Yellow
aws cloudformation describe-stacks `
    --stack-name $StackName `
    --region $Region `
    --query "Stacks[0].Outputs" `
    --output table
