package com.veloshield.servlet;

import com.fasterxml.jackson.core.type.TypeReference;
import com.veloshield.config.DatabaseManager;
import com.veloshield.model.Finding;
import com.veloshield.service.PreDeploymentScanService;
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

public class PreDeploymentServlet extends HttpServlet {

    private final PreDeploymentScanService scanService = new PreDeploymentScanService();

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
        // Format: /scans/{id} or /scans/{id}/findings or /scans/{id}/report
        if (parts.length >= 2) {
            try {
                int scanId = Integer.parseInt(parts[1].equals("scans") && parts.length > 2 ? parts[2] : parts[1]);
                String sub = parts.length > 2 && !parts[1].equals("scans") ? parts[2] : (parts.length > 3 ? parts[3] : "");

                if ("findings".equalsIgnoreCase(sub)) {
                    handleGetFindings(userId, scanId, resp);
                } else if ("report".equalsIgnoreCase(sub)) {
                    handleGetReport(userId, scanId, resp);
                } else {
                    handleGetScan(userId, scanId, resp);
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

        String projectName = (String) body.getOrDefault("projectName", "Untitled Project");
        List<?> rawFiles = (List<?>) body.get("files");

        if (rawFiles == null || rawFiles.isEmpty()) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "No project files provided for analysis")));
            return;
        }

        List<PreDeploymentScanService.ProjectFile> files = new ArrayList<>();
        for (Object rf : rawFiles) {
            if (rf instanceof Map<?, ?> m) {
                String path = (String) m.get("path");
                String content = (String) m.get("content");
                if (path != null && content != null) {
                    files.add(new PreDeploymentScanService.ProjectFile(path, content));
                }
            }
        }

        // Run Static Analysis
        PreDeploymentScanService.ScanOutput scanResult = scanService.analyze(projectName, files);

        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            conn.setAutoCommit(false);

            PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO assessments (user_id, assessment_type, target_ref, status, scores_json, metrics_json, started_at, finished_at) " +
                    "VALUES (?, 'BEFORE_DEPLOYMENT', ?, 'completed', ?, ?, ?, ?) RETURNING id"
            );
            ps.setInt(1, userId);
            ps.setString(2, projectName);
            ps.setString(3, JsonUtil.toJson(scanResult.scores));
            ps.setString(4, JsonUtil.toJson(scanResult.metrics));
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
                    "projectName", projectName,
                    "status", "completed",
                    "scores", scanResult.scores,
                    "metrics", scanResult.metrics,
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
                    "SELECT id, target_ref, status, scores_json, metrics_json, started_at, finished_at " +
                    "FROM assessments WHERE id = ? AND user_id = ? AND assessment_type = 'BEFORE_DEPLOYMENT'"
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
            map.put("projectName", rs.getString("target_ref"));
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
            // Verify ownership
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

            String project = rs.getString("target_ref");
            Map<?, ?> scores = JsonUtil.fromJson(rs.getString("scores_json"), Map.class);
            Map<?, ?> metrics = JsonUtil.fromJson(rs.getString("metrics_json"), Map.class);

            PreparedStatement psF = conn.prepareStatement(
                    "SELECT category, severity, title, affected_file_or_url, recommendation FROM findings WHERE assessment_id = ?"
            );
            psF.setInt(1, scanId);
            ResultSet rsF = psF.executeQuery();

            StringBuilder csv = new StringBuilder();
            csv.append("VeloShield Pre-Deployment Readiness Assessment Report\n");
            csv.append("Project,").append(project).append("\n");
            csv.append("Overall Readiness Score,").append(scores.get("overall")).append("/100\n");
            csv.append("Status,").append(scores.get("status")).append("\n");
            csv.append("Security Score,").append(scores.get("security")).append("\n");
            csv.append("Configuration Score,").append(scores.get("configuration")).append("\n");
            csv.append("Dependencies Score,").append(scores.get("dependencies")).append("\n");
            csv.append("Project Score,").append(scores.get("project")).append("\n\n");

            csv.append("Category,Severity,Title,File/Location,Recommendation\n");
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
            resp.setHeader("Content-Disposition", "attachment; filename=\"veloshield-predeployment-" + scanId + ".csv\"");
            resp.getWriter().write(csv.toString());

        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }
}
