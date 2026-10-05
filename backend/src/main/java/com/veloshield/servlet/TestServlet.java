package com.veloshield.servlet;

import com.veloshield.config.DatabaseManager;
import com.veloshield.service.LoadTestService;
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

public class TestServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        resp.setContentType("application/json");
        if (!SessionUtil.requireAuth(req, resp)) return;

        int userId = SessionUtil.getUserId(req);
        String pathInfo = req.getPathInfo();

        if (pathInfo == null || pathInfo.equals("/")) {
            // GET /api/tests — list all tests for user
            listTests(userId, resp);
        } else {
            String[] parts = pathInfo.split("/");
            if (parts.length >= 2) {
                try {
                    int testId = Integer.parseInt(parts[1]);
                    if (parts.length == 3 && "report".equals(parts[2])) {
                        // GET /api/tests/{id}/report — CSV export
                        resp.setContentType("text/csv");
                        getReport(userId, testId, resp);
                    } else {
                        // GET /api/tests/{id} — get test details
                        getTest(userId, testId, resp);
                    }
                } catch (NumberFormatException e) {
                    resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    resp.setContentType("application/json");
                    resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid test ID")));
                }
            }
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        resp.setContentType("application/json");
        if (!SessionUtil.requireAuth(req, resp)) return;

        int userId = SessionUtil.getUserId(req);
        startTest(userId, req, resp);
    }

    private void listTests(int userId, HttpServletResponse resp) throws IOException {
        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement ps = conn.prepareStatement(
                "SELECT t.id, t.user_id, t.target_id, tg.url AS target_url, t.status, t.concurrency, " +
                "t.duration_seconds, t.max_requests, t.attempted, t.succeeded, t.failed, " +
                "t.avg_latency_ms, t.p95_latency_ms, t.errors, t.started_at, t.finished_at " +
                "FROM tests t JOIN targets tg ON t.target_id = tg.id " +
                "WHERE t.user_id = ? ORDER BY t.started_at DESC"
            );
            ps.setInt(1, userId);
            ResultSet rs = ps.executeQuery();

            List<Map<String, Object>> tests = new ArrayList<>();
            while (rs.next()) {
                tests.add(buildTestMap(rs));
            }
            resp.getWriter().write(JsonUtil.toJson(tests));
        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Failed to retrieve tests: " + e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private void getTest(int userId, int testId, HttpServletResponse resp) throws IOException {
        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement ps = conn.prepareStatement(
                "SELECT t.id, t.user_id, t.target_id, tg.url AS target_url, t.status, t.concurrency, " +
                "t.duration_seconds, t.max_requests, t.attempted, t.succeeded, t.failed, " +
                "t.avg_latency_ms, t.p95_latency_ms, t.errors, t.started_at, t.finished_at " +
                "FROM tests t JOIN targets tg ON t.target_id = tg.id " +
                "WHERE t.id = ? AND t.user_id = ?"
            );
            ps.setInt(1, testId);
            ps.setInt(2, userId);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                resp.getWriter().write(JsonUtil.toJson(buildTestMap(rs)));
            } else {
                resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Test not found")));
            }
        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Failed to retrieve test: " + e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private void startTest(int userId, HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Map<?, ?> body;
        try {
            body = JsonUtil.fromJson(req.getReader().lines().reduce("", String::concat), Map.class);
        } catch (Exception e) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid JSON body")));
            return;
        }

        Object targetIdObj = body.get("targetId");
        Object concurrencyObj = body.get("concurrency");
        Object durationObj = body.get("durationSeconds");
        Object maxRequestsObj = body.get("maxRequests");

        if (targetIdObj == null || concurrencyObj == null || durationObj == null || maxRequestsObj == null) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "targetId, concurrency, durationSeconds, and maxRequests are required")));
            return;
        }

        int targetId, concurrency, durationSeconds, maxRequests;
        try {
            targetId = ((Number) targetIdObj).intValue();
            concurrency = ((Number) concurrencyObj).intValue();
            durationSeconds = ((Number) durationObj).intValue();
            maxRequests = ((Number) maxRequestsObj).intValue();
        } catch (ClassCastException e) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid numeric values")));
            return;
        }

        // Enforce limits
        if (concurrency < 1 || concurrency > 50) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Concurrency must be between 1 and 50")));
            return;
        }
        if (durationSeconds < 5 || durationSeconds > 120) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Duration must be between 5 and 120 seconds")));
            return;
        }
        if (maxRequests < 10 || maxRequests > 5000) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Max requests must be between 10 and 5000")));
            return;
        }

        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();

            // Check target is verified and owned by user
            PreparedStatement checkPs = conn.prepareStatement(
                "SELECT id, url, verified FROM targets WHERE id = ? AND user_id = ?"
            );
            checkPs.setInt(1, targetId);
            checkPs.setInt(2, userId);
            ResultSet checkRs = checkPs.executeQuery();

            if (!checkRs.next()) {
                resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Target not found")));
                return;
            }



            String targetUrl = checkRs.getString("url");

            // Insert test record
            PreparedStatement insertPs = conn.prepareStatement(
                "INSERT INTO tests (user_id, target_id, status, concurrency, duration_seconds, max_requests, started_at) " +
                "VALUES (?, ?, 'running', ?, ?, ?, ?) RETURNING id"
            );
            insertPs.setInt(1, userId);
            insertPs.setInt(2, targetId);
            insertPs.setInt(3, concurrency);
            insertPs.setInt(4, durationSeconds);
            insertPs.setInt(5, maxRequests);
            insertPs.setTimestamp(6, Timestamp.from(Instant.now()));
            ResultSet rs = insertPs.executeQuery();

            if (rs.next()) {
                int testId = rs.getInt(1);
                DatabaseManager.releaseConnection(conn);
                conn = null;

                // Launch async load test
                LoadTestService.getInstance().runTest(testId, targetUrl, concurrency, durationSeconds, maxRequests);

                resp.setStatus(HttpServletResponse.SC_CREATED);
                resp.getWriter().write(JsonUtil.toJson(Map.of(
                    "testId", testId,
                    "status", "running",
                    "message", "Assessment started successfully"
                )));
            }
        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Failed to start test: " + e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private void getReport(int userId, int testId, HttpServletResponse resp) throws IOException {
        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement ps = conn.prepareStatement(
                "SELECT t.id, tg.url AS target_url, t.status, t.concurrency, t.duration_seconds, " +
                "t.max_requests, t.attempted, t.succeeded, t.failed, t.avg_latency_ms, t.p95_latency_ms, " +
                "t.errors, t.started_at, t.finished_at " +
                "FROM tests t JOIN targets tg ON t.target_id = tg.id " +
                "WHERE t.id = ? AND t.user_id = ?"
            );
            ps.setInt(1, testId);
            ps.setInt(2, userId);
            ResultSet rs = ps.executeQuery();

            if (!rs.next()) {
                resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
                resp.setContentType("application/json");
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Test not found")));
                return;
            }

            StringBuilder csv = new StringBuilder();
            csv.append("Field,Value\n");
            csv.append("Test ID,").append(rs.getInt("id")).append("\n");
            csv.append("Target URL,").append(rs.getString("target_url")).append("\n");
            csv.append("Status,").append(rs.getString("status")).append("\n");
            csv.append("Concurrency,").append(rs.getInt("concurrency")).append("\n");
            csv.append("Duration (s),").append(rs.getInt("duration_seconds")).append("\n");
            csv.append("Max Requests,").append(rs.getInt("max_requests")).append("\n");
            csv.append("Attempted,").append(rs.getInt("attempted")).append("\n");
            csv.append("Succeeded,").append(rs.getInt("succeeded")).append("\n");
            csv.append("Failed,").append(rs.getInt("failed")).append("\n");
            csv.append("Avg Latency (ms),").append(String.format("%.2f", rs.getDouble("avg_latency_ms"))).append("\n");
            csv.append("P95 Latency (ms),").append(String.format("%.2f", rs.getDouble("p95_latency_ms"))).append("\n");
            csv.append("Errors,\"").append(rs.getString("errors").replace("\"", "\"\"")).append("\"\n");

            Timestamp startedAt = rs.getTimestamp("started_at");
            Timestamp finishedAt = rs.getTimestamp("finished_at");
            csv.append("Started At,").append(startedAt != null ? startedAt.toString() : "N/A").append("\n");
            csv.append("Finished At,").append(finishedAt != null ? finishedAt.toString() : "N/A").append("\n");

            resp.setHeader("Content-Disposition", "attachment; filename=\"veloshield-report-" + testId + ".csv\"");
            resp.getWriter().write(csv.toString());

        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.setContentType("application/json");
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Failed to generate report: " + e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private Map<String, Object> buildTestMap(ResultSet rs) throws SQLException {
        Map<String, Object> test = new LinkedHashMap<>();
        test.put("id", rs.getInt("id"));
        test.put("userId", rs.getInt("user_id"));
        test.put("targetId", rs.getInt("target_id"));
        test.put("targetUrl", rs.getString("target_url"));
        test.put("status", rs.getString("status"));
        test.put("concurrency", rs.getInt("concurrency"));
        test.put("durationSeconds", rs.getInt("duration_seconds"));
        test.put("maxRequests", rs.getInt("max_requests"));
        test.put("attempted", rs.getInt("attempted"));
        test.put("succeeded", rs.getInt("succeeded"));
        test.put("failed", rs.getInt("failed"));
        test.put("avgLatencyMs", rs.getDouble("avg_latency_ms"));
        test.put("p95LatencyMs", rs.getDouble("p95_latency_ms"));

        // Parse errors JSON
        String errorsJson = rs.getString("errors");
        try {
            test.put("errors", JsonUtil.getMapper().readValue(
                errorsJson != null ? errorsJson : "{}",
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Integer>>() {}
            ));
        } catch (Exception e) {
            test.put("errors", Map.of());
        }

        Timestamp startedAt = rs.getTimestamp("started_at");
        Timestamp finishedAt = rs.getTimestamp("finished_at");
        test.put("startedAt", startedAt != null ? startedAt.toString() : null);
        test.put("finishedAt", finishedAt != null ? finishedAt.toString() : null);

        return test;
    }
}
