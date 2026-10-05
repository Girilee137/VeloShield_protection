package com.veloshield.servlet;

import com.veloshield.config.DatabaseManager;
import com.veloshield.model.Finding;
import com.veloshield.service.PostDeploymentScanService;
import com.veloshield.util.JsonUtil;
import com.veloshield.util.SessionUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.sql.*;
import java.time.Instant;
import java.util.*;

public class PostDeploymentServlet extends HttpServlet {

    private final PostDeploymentScanService scanService = new PostDeploymentScanService();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        if (!SessionUtil.requireAuth(req, resp)) return;

        int userId = SessionUtil.getUserId(req);
        String pathInfo = req.getPathInfo();

        if (pathInfo == null || pathInfo.equals("/") || pathInfo.equals("/scans")) {
            handleCreateScan(userId, req, resp);
        } else {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Endpoint not found")));
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        if (!SessionUtil.requireAuth(req, resp)) return;

        int userId = SessionUtil.getUserId(req);
        String pathInfo = req.getPathInfo();

        if (pathInfo == null || pathInfo.equals("/")) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Scan ID required")));
            return;
        }

        String[] parts = pathInfo.split("/");
        if (parts.length >= 2) {
            try {
                int scanId = Integer.parseInt(parts[1].equals("scans") && parts.length > 2 ? parts[2] : parts[1]);
                String sub = parts.length > 2 && !parts[1].equals("scans") ? parts[2] : (parts.length > 3 ? parts[3] : "");

                switch (sub.toLowerCase()) {
                    case "findings" -> handleGetFindings(userId, scanId, resp);
                    case "security" -> handleGetSubSection(userId, scanId, "security", resp);
                    case "performance" -> handleGetSubSection(userId, scanId, "performance", resp);
                    case "api-health" -> handleGetSubSection(userId, scanId, "apiHealth", resp);
                    case "third-party" -> handleGetSubSection(userId, scanId, "thirdParty", resp);
                    case "report" -> handleGetReport(userId, scanId, resp);
                    default -> handleGetScan(userId, scanId, resp);
                }
            } catch (NumberFormatException e) {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid scan ID")));
            }
        }
    }

    private void handleCreateScan(int userId, HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Map<String, Object> body;
        try {
            body = JsonUtil.fromJson(req.getReader().lines().reduce("", String::concat), Map.class);
        } catch (Exception e) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid JSON body")));
            return;
        }

        String targetUrl = (String) body.get("targetUrl");
        if (targetUrl == null || targetUrl.isBlank()) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "targetUrl is required")));
            return;
        }

        // Run Safe Live Scan
        PostDeploymentScanService.PostScanOutput scanResult = scanService.scan(targetUrl.trim());

        // Merge sub-details into metricsJson for persistence
        Map<String, Object> combinedMetrics = new HashMap<>(scanResult.metrics);
        combinedMetrics.put("security", scanResult.securityDetails);
        combinedMetrics.put("performance", scanResult.performanceDetails);
        combinedMetrics.put("apiHealth", scanResult.apiHealthDetails);
        combinedMetrics.put("thirdParty", scanResult.thirdPartyDetails);

        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            conn.setAutoCommit(false);

            PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO assessments (user_id, assessment_type, target_ref, status, scores_json, metrics_json, started_at, finished_at) " +
                    "VALUES (?, 'AFTER_DEPLOYMENT', ?, 'completed', ?, ?, ?, ?) RETURNING id"
            );
            ps.setInt(1, userId);
            ps.setString(2, targetUrl.trim());
            ps.setString(3, JsonUtil.toJson(scanResult.scores));
            ps.setString(4, JsonUtil.toJson(combinedMetrics));
            ps.setTimestamp(5, Timestamp.from(Instant.now()));
            ps.setTimestamp(6, Timestamp.from(Instant.now()));
            ResultSet rs = ps.executeQuery();

            int assessmentId = 0;
            if (rs.next()) {
                assessmentId = rs.getInt(1);
            }

            // Insert findings
            PreparedStatement psf = conn.prepareStatement(
                    "INSERT INTO findings (assessment_id, category, severity, title, description, evidence, affected_file_or_url, recommendation) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            );
            for (Finding f : scanResult.findings) {
                psf.setInt(1, assessmentId);
                psf.setString(2, f.getCategory());
                psf.setString(3, f.getSeverity());
                psf.setString(4, f.getTitle());
                psf.setString(5, f.getDescription());
                psf.setString(6, f.getEvidence());
                psf.setString(7, f.getAffectedFileOrUrl());
                psf.setString(8, f.getRecommendation());
                psf.addBatch();
            }
            psf.executeBatch();
            conn.commit();

            resp.setStatus(HttpServletResponse.SC_CREATED);
            resp.getWriter().write(JsonUtil.toJson(Map.of(
                    "id", assessmentId,
                    "targetUrl", targetUrl,
                    "status", "completed",
                    "scores", scanResult.scores,
                    "metrics", scanResult.metrics,
                    "security", scanResult.securityDetails,
                    "performance", scanResult.performanceDetails,
                    "apiHealth", scanResult.apiHealthDetails,
                    "thirdParty", scanResult.thirdPartyDetails,
                    "findings", scanResult.findings
            )));

        } catch (SQLException e) {
            if (conn != null) {
                try { conn.rollback(); } catch (SQLException ignored) {}
            }
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Database error: " + e.getMessage())));
        } finally {
            if (conn != null) {
                try { conn.setAutoCommit(true); } catch (SQLException ignored) {}
                DatabaseManager.releaseConnection(conn);
            }
        }
    }

    private void handleGetScan(int userId, int scanId, HttpServletResponse resp) throws IOException {
        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement ps = conn.prepareStatement(
                    "SELECT id, target_ref, status, scores_json, metrics_json, started_at " +
                    "FROM assessments WHERE id = ? AND user_id = ? AND assessment_type = 'AFTER_DEPLOYMENT'"
            );
            ps.setInt(1, scanId);
            ps.setInt(2, userId);
            ResultSet rs = ps.executeQuery();

            if (!rs.next()) {
                resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Scan not found")));
                return;
            }

            Map<String, Object> map = new LinkedHashMap<>();
            map.put("id", rs.getInt("id"));
            map.put("targetUrl", rs.getString("target_ref"));
            map.put("status", rs.getString("status"));
            map.put("scores", JsonUtil.fromJson(rs.getString("scores_json"), Map.class));
            map.put("metrics", JsonUtil.fromJson(rs.getString("metrics_json"), Map.class));
            map.put("startedAt", rs.getTimestamp("started_at").toString());

            resp.getWriter().write(JsonUtil.toJson(map));

        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private void handleGetFindings(int userId, int scanId, HttpServletResponse resp) throws IOException {
        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement psCheck = conn.prepareStatement("SELECT id FROM assessments WHERE id = ? AND user_id = ?");
            psCheck.setInt(1, scanId);
            psCheck.setInt(2, userId);
            if (!psCheck.executeQuery().next()) {
                resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Scan not found")));
                return;
            }

            PreparedStatement ps = conn.prepareStatement(
                    "SELECT id, category, severity, title, description, evidence, affected_file_or_url, recommendation, created_at " +
                    "FROM findings WHERE assessment_id = ? ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 WHEN 'INFO' THEN 5 ELSE 6 END"
            );
            ps.setInt(1, scanId);
            ResultSet rs = ps.executeQuery();

            List<Finding> list = new ArrayList<>();
            while (rs.next()) {
                Finding f = new Finding();
                f.setId(rs.getInt("id"));
                f.setAssessmentId(scanId);
                f.setCategory(rs.getString("category"));
                f.setSeverity(rs.getString("severity"));
                f.setTitle(rs.getString("title"));
                f.setDescription(rs.getString("description"));
                f.setEvidence(rs.getString("evidence"));
                f.setAffectedFileOrUrl(rs.getString("affected_file_or_url"));
                f.setRecommendation(rs.getString("recommendation"));
                f.setCreatedAt(rs.getTimestamp("created_at").toString());
                list.add(f);
            }

            resp.getWriter().write(JsonUtil.toJson(list));

        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private void handleGetSubSection(int userId, int scanId, String sectionKey, HttpServletResponse resp) throws IOException {
        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement ps = conn.prepareStatement(
                    "SELECT metrics_json FROM assessments WHERE id = ? AND user_id = ?"
            );
            ps.setInt(1, scanId);
            ps.setInt(2, userId);
            ResultSet rs = ps.executeQuery();
            if (!rs.next()) {
                resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Scan not found")));
                return;
            }

            Map<?, ?> metrics = JsonUtil.fromJson(rs.getString("metrics_json"), Map.class);
            Object sub = metrics.get(sectionKey);
            resp.getWriter().write(JsonUtil.toJson(sub != null ? sub : Map.of()));

        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private void handleGetReport(int userId, int scanId, HttpServletResponse resp) throws IOException {
        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement ps = conn.prepareStatement(
                    "SELECT target_ref, scores_json, metrics_json, started_at FROM assessments WHERE id = ? AND user_id = ?"
            );
            ps.setInt(1, scanId);
            ps.setInt(2, userId);
            ResultSet rs = ps.executeQuery();
            if (!rs.next()) {
                resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Scan not found")));
                return;
            }

            String target = rs.getString("target_ref");
            Map<?, ?> scores = JsonUtil.fromJson(rs.getString("scores_json"), Map.class);

            PreparedStatement psF = conn.prepareStatement(
                    "SELECT category, severity, title, affected_file_or_url, recommendation FROM findings WHERE assessment_id = ?"
            );
            psF.setInt(1, scanId);
            ResultSet rsF = psF.executeQuery();

            StringBuilder csv = new StringBuilder();
            csv.append("VeloShield Post-Deployment Website Health Assessment Report\n");
            csv.append("Target URL,").append(target).append("\n");
            csv.append("Overall Health Score,").append(scores.get("overall")).append("/100\n");
            csv.append("Health Status,").append(scores.get("status")).append("\n");
            csv.append("Security Score,").append(scores.get("security")).append("\n");
            csv.append("Performance Score,").append(scores.get("performance")).append("\n");
            csv.append("Availability Score,").append(scores.get("availability")).append("\n");
            csv.append("API Health Score,").append(scores.get("apiHealth")).append("\n");
            csv.append("Reliability Score,").append(scores.get("reliability")).append("\n\n");

            csv.append("Category,Severity,Title,Affected URL/Resource,Recommendation\n");
            while (rsF.next()) {
                csv.append(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                        rsF.getString("category"),
                        rsF.getString("severity"),
                        rsF.getString("title").replace("\"", "\"\""),
                        rsF.getString("affected_file_or_url").replace("\"", "\"\""),
                        rsF.getString("recommendation").replace("\"", "\"\"")
                ));
            }

            resp.setContentType("text/csv");
            resp.setHeader("Content-Disposition", "attachment; filename=\"veloshield-postdeployment-" + scanId + ".csv\"");
            resp.getWriter().write(csv.toString());

        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }
}
