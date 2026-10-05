$env:DATABASE_URL = "postgresql://neondb_owner:npg_uINH46FfMqTe@ep-rough-mud-b3mcn8s2-pooler.c-4.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
$env:PORT = "8080"

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "Starting VeloShield Unified Server on port 8080..." -ForegroundColor Cyan
Write-Host "Both Frontend & API are served together at http://localhost:8080" -ForegroundColor Green
Write-Host "========================================================`n" -ForegroundColor Cyan

if (-not (Test-Path "backend\target\veloshield.jar")) {
    Write-Host "Building VeloShield package with Maven..." -ForegroundColor Yellow
    Push-Location backend
    mvn clean package -DskipTests
    Pop-Location
}

Start-Process "http://localhost:8080"
java -jar backend\target\veloshield.jar
