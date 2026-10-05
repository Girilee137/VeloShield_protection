@echo off
set "DATABASE_URL=postgresql://neondb_owner:npg_uINH46FfMqTe@ep-rough-mud-b3mcn8s2-pooler.c-4.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
set "PORT=8080"

echo.
echo ========================================================
echo Starting VeloShield Unified Server on port 8080...
echo ========================================================
echo.

if not exist "backend\target\veloshield.jar" (
    echo Building VeloShield package...
    cd backend && call mvn clean package -DskipTests && cd ..
)

start "" http://localhost:8080
java -jar backend\target\veloshield.jar
