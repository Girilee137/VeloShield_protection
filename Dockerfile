# Multi-stage Dockerfile for VeloShield (Single-Service Deployment on Render)
# Stage 1: Build the fat JAR with Maven
FROM maven:3.9.6-eclipse-temurin-21-alpine AS builder
WORKDIR /workspace

# Copy backend pom and source code
COPY backend/pom.xml backend/pom.xml
COPY backend/src backend/src

# Copy frontend assets (packaged directly into JAR's /static resource directory)
COPY frontend frontend

# Build self-contained fat JAR
WORKDIR /workspace/backend
RUN mvn clean package -DskipTests

# Stage 2: Minimal Java 21 runtime container
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Copy shaded fat JAR from build stage
COPY --from=builder /workspace/backend/target/veloshield.jar app.jar

# Copy frontend directory for disk fallback
COPY --from=builder /workspace/frontend frontend

# Default port expected by Render
ENV PORT=8080
EXPOSE 8080

# Run the unified VeloShield application
ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "app.jar"]
