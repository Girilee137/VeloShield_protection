package com.veloshield.servlet;

import com.veloshield.config.DatabaseManager;
import com.veloshield.util.JsonUtil;
import com.veloshield.util.SessionUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;

public class MitigationServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        resp.setContentType("application/json");
        if (!SessionUtil.requireAuth(req, resp)) return;

        int userId = SessionUtil.getUserId(req);
        String pathInfo = req.getPathInfo();

        if (pathInfo == null || pathInfo.equals("/")) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Test ID required")));
            return;
        }

        String[] parts = pathInfo.split("/");
        if (parts.length < 2) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid path")));
            return;
        }

        try {
            int testId = Integer.parseInt(parts[1]);
            generateMitigation(userId, testId, resp);
        } catch (NumberFormatException e) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid test ID")));
        }
    }

    private void generateMitigation(int userId, int testId, HttpServletResponse resp) throws IOException {
        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement ps = conn.prepareStatement(
                "SELECT t.id, tg.url AS target_url, t.status, t.concurrency, t.duration_seconds, " +
                "t.max_requests, t.attempted, t.succeeded, t.failed, t.avg_latency_ms, t.p95_latency_ms, t.errors " +
                "FROM tests t JOIN targets tg ON t.target_id = tg.id " +
                "WHERE t.id = ? AND t.user_id = ?"
            );
            ps.setInt(1, testId);
            ps.setInt(2, userId);
            ResultSet rs = ps.executeQuery();

            if (!rs.next()) {
                resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Test not found")));
                return;
            }

            String status = rs.getString("status");
            if (!"completed".equals(status)) {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Test must be completed before generating mitigation recommendations")));
                return;
            }

            String targetUrl = rs.getString("target_url");
            int attempted = rs.getInt("attempted");
            int succeeded = rs.getInt("succeeded");
            int failed = rs.getInt("failed");
            double avgLatency = rs.getDouble("avg_latency_ms");
            double p95Latency = rs.getDouble("p95_latency_ms");
            String errorsJson = rs.getString("errors");

            // Compute metrics for recommendations
            double failureRate = attempted > 0 ? (double) failed / attempted * 100.0 : 0.0;
            boolean highFailureRate = failureRate > 10.0;
            boolean highLatency = avgLatency > 2000.0;
            boolean veryHighLatency = p95Latency > 5000.0;
            boolean hasErrors = failed > 0;

            // Build summary
            StringBuilder summary = new StringBuilder();
            summary.append(String.format("Assessment Summary for %s:%n%n", targetUrl));
            summary.append(String.format("- Total Requests: %d (Succeeded: %d, Failed: %d)%n", attempted, succeeded, failed));
            summary.append(String.format("- Failure Rate: %.1f%%%n", failureRate));
            summary.append(String.format("- Average Latency: %.1f ms%n", avgLatency));
            summary.append(String.format("- P95 Latency: %.1f ms%n", p95Latency));
            summary.append("\nRecommendations:\n");

            if (highFailureRate) {
                summary.append("- HIGH FAILURE RATE detected. Implement rate limiting to prevent request flooding.\n");
            }
            if (highLatency) {
                summary.append("- HIGH LATENCY detected. Consider enabling caching, CDN, or load balancing.\n");
            }
            if (veryHighLatency) {
                summary.append("- VERY HIGH P95 LATENCY detected. Critical: application may be resource-constrained.\n");
            }
            if (!highFailureRate && !highLatency) {
                summary.append("- Application handled the assessment load adequately. Maintain current defensive configurations.\n");
            }
            summary.append("- Review and apply the Nginx and Cloudflare configurations below for enhanced protection.\n");

            // Generate Nginx config
            String nginxConfig = generateNginxConfig(targetUrl, highFailureRate, highLatency, failureRate, avgLatency);

            // Generate Cloudflare config
            String cloudflareConfig = generateCloudflareConfig(targetUrl, highFailureRate, highLatency, failureRate, avgLatency);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("testId", testId);
            result.put("targetUrl", targetUrl);
            result.put("metrics", Map.of(
                "attempted", attempted,
                "succeeded", succeeded,
                "failed", failed,
                "failureRate", String.format("%.1f%%", failureRate),
                "avgLatencyMs", String.format("%.1f", avgLatency),
                "p95LatencyMs", String.format("%.1f", p95Latency)
            ));
            result.put("summary", summary.toString());
            result.put("nginx", nginxConfig);
            result.put("cloudflare", cloudflareConfig);

            resp.getWriter().write(JsonUtil.toJson(result));

        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Failed to generate mitigation: " + e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private String generateNginxConfig(String targetUrl, boolean highFailureRate, boolean highLatency,
                                        double failureRate, double avgLatency) {
        // Determine rate limit based on observed failure rate
        String rateLimit = highFailureRate ? "10r/s" : "30r/s";
        String burstLimit = highFailureRate ? "20" : "60";
        String cacheConfig = highLatency ? """
                    # Cache static content to reduce latency
                    proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=veloshield_cache:10m max_size=1g
                                     inactive=60m use_temp_path=off;
                    
                    proxy_cache veloshield_cache;
                    proxy_cache_valid 200 302 10m;
                    proxy_cache_valid 404 1m;
                    proxy_cache_use_stale error timeout invalid_header updating
                                          http_500 http_502 http_503 http_504;
                    add_header X-Cache-Status $upstream_cache_status;
                    """ : "    # Caching not critical at current latency levels";

        return """
                # ============================================================
                # VeloShield Nginx Mitigation Configuration
                # Generated for: %s
                # Failure Rate Observed: %.1f%%  |  Avg Latency: %.1f ms
                # ============================================================
                # REVIEW BEFORE DEPLOYMENT — adjust values for your environment
                
                # Rate limiting zone — 10MB shared memory, %s per IP
                limit_req_zone $binary_remote_addr zone=veloshield_limit:10m rate=%s;
                
                # Connection limiting zone
                limit_conn_zone $binary_remote_addr zone=veloshield_conn:10m;
                
                server {
                    listen 80;
                    listen 443 ssl http2;
                    server_name %s;
                
                    # SSL/TLS (update paths)
                    ssl_certificate     /etc/ssl/certs/your_cert.pem;
                    ssl_certificate_key /etc/ssl/private/your_key.pem;
                    ssl_protocols       TLSv1.2 TLSv1.3;
                    ssl_ciphers         HIGH:!aNULL:!MD5;
                    ssl_prefer_server_ciphers on;
                    ssl_session_cache   shared:SSL:10m;
                
                    # Security headers
                    add_header X-Frame-Options SAMEORIGIN always;
                    add_header X-Content-Type-Options nosniff always;
                    add_header X-XSS-Protection "1; mode=block" always;
                    add_header Referrer-Policy strict-origin-when-cross-origin always;
                    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
                    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;
                
                    # Rate limiting — burst=%s with nodelay
                    limit_req zone=veloshield_limit burst=%s nodelay;
                    limit_req_status 429;
                
                    # Connection limiting — max 20 connections per IP
                    limit_conn veloshield_conn 20;
                    limit_conn_status 429;
                
                    # Body size limit
                    client_max_body_size 10m;
                    client_body_timeout 15s;
                    client_header_timeout 15s;
                
                    # Keepalive
                    keepalive_timeout 30s;
                    keepalive_requests 100;
                
                    # Timeout settings
                    send_timeout 15s;
                    proxy_connect_timeout 10s;
                    proxy_send_timeout 15s;
                    proxy_read_timeout 30s;
                
                    # Gzip compression
                    gzip on;
                    gzip_vary on;
                    gzip_min_length 1024;
                    gzip_types text/plain text/css application/json application/javascript text/xml;
                
                %s
                
                    location / {
                        proxy_pass http://your_backend_upstream;
                        proxy_http_version 1.1;
                        proxy_set_header Upgrade $http_upgrade;
                        proxy_set_header Connection 'upgrade';
                        proxy_set_header Host $host;
                        proxy_set_header X-Real-IP $remote_addr;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header X-Forwarded-Proto $scheme;
                        proxy_cache_bypass $http_upgrade;
                
                        # Custom error pages
                        error_page 429 /429.html;
                        error_page 500 502 503 504 /50x.html;
                    }
                
                    # Block common attack patterns
                    location ~* \\.(env|git|sql|bak|log)$ {
                        deny all;
                        return 404;
                    }
                
                    location = /429.html {
                        return 429 'Too many requests. Please slow down.';
                        add_header Content-Type text/plain;
                    }
                
                    location = /50x.html {
                        root /usr/share/nginx/html;
                    }
                }
                """.formatted(targetUrl, failureRate, avgLatency, rateLimit, rateLimit, burstLimit, burstLimit, cacheConfig);
    }

    private String generateCloudflareConfig(String targetUrl, boolean highFailureRate, boolean highLatency,
                                              double failureRate, double avgLatency) {
        String rateAction = highFailureRate ? "BLOCK" : "CHALLENGE";
        String rateThreshold = highFailureRate ? "50" : "100";

        return """
                # ============================================================
                # VeloShield Cloudflare WAF & Rate Limiting Configuration
                # Generated for: %s
                # Failure Rate Observed: %.1f%%  |  Avg Latency: %.1f ms
                # ============================================================
                # Apply these rules in Cloudflare Dashboard:
                # Security → WAF → Rate Limiting Rules & Custom Rules
                # REVIEW BEFORE DEPLOYMENT
                
                # ---- RATE LIMITING RULE ----
                # Rule Name: VeloShield - Rate Limit
                # Expression:
                (http.host eq "your-domain.com")
                
                # Action: %s
                # Threshold: %s requests per 10 seconds (per IP)
                # Period: 10 seconds
                # Mitigation Timeout: 60 seconds
                
                
                # ---- CUSTOM WAF RULE 1: Block Bad Bots ----
                # Rule Name: VeloShield - Block Bad Bots
                # Expression:
                (cf.client.bot) and not (cf.verified_bot_category in {"SEARCH_ENGINE" "MONITORING_ANALYTICS"})
                
                # Action: BLOCK
                
                
                # ---- CUSTOM WAF RULE 2: Challenge Suspicious Traffic ----
                # Rule Name: VeloShield - Challenge Suspicious
                # Expression:
                (http.request.uri.path contains "..") or
                (http.request.uri.path contains "//") or
                (http.user_agent contains "sqlmap") or
                (http.user_agent contains "nikto") or
                (http.user_agent contains "masscan") or
                (http.user_agent contains "python-requests") or
                (http.user_agent contains "curl" and not cf.verified_bot_category in {"MONITORING_ANALYTICS"})
                
                # Action: MANAGED_CHALLENGE
                
                
                # ---- CUSTOM WAF RULE 3: Block Empty User-Agent ----
                # Rule Name: VeloShield - Block Empty UA
                # Expression:
                (not http.user_agent exists) or (http.user_agent eq "")
                
                # Action: BLOCK
                
                
                # ---- FIREWALL SETTINGS (Dashboard: Security → Settings) ----
                Security Level: %s
                Bot Fight Mode: ENABLED
                Browser Integrity Check: ENABLED
                Privacy Pass: ENABLED
                
                
                # ---- PAGE RULES (Dashboard: Rules → Page Rules) ----
                # Cache static assets:
                *%s/static/*
                Cache Level: Cache Everything
                Edge Cache TTL: 1 month
                
                # ---- DDOS PROTECTION (Dashboard: Security → DDoS) ----
                HTTP DDoS Attack Protection: ENABLED
                Sensitivity: %s
                Action Override: MANAGED_CHALLENGE
                
                
                # ---- ADDITIONAL RECOMMENDATIONS ----
                # 1. Enable Cloudflare Proxy (Orange Cloud) for all DNS records
                # 2. Enable "Under Attack Mode" if you detect active attacks
                # 3. Review Cloudflare Analytics to identify attack patterns
                # 4. Configure IP Access Rules to geo-block high-risk regions if applicable
                # 5. Enable Two-Factor Authentication on your Cloudflare account
                """.formatted(
                targetUrl, failureRate, avgLatency,
                rateAction, rateThreshold,
                highFailureRate ? "HIGH" : "MEDIUM",
                targetUrl,
                highFailureRate ? "HIGH" : "MEDIUM"
        );
    }
}
