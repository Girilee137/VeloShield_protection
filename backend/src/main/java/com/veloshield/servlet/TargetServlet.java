package com.veloshield.servlet;

import com.veloshield.config.DatabaseManager;
import com.veloshield.util.JsonUtil;
import com.veloshield.util.SessionUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class TargetServlet extends HttpServlet {

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        resp.setContentType("application/json");
        if (!SessionUtil.requireAuth(req, resp)) return;

        int userId = SessionUtil.getUserId(req);
        String pathInfo = req.getPathInfo();

        // GET /api/targets — list all targets for user
        if (pathInfo == null || pathInfo.equals("/")) {
            listTargets(userId, resp);
        } else {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Not found")));
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        resp.setContentType("application/json");
        if (!SessionUtil.requireAuth(req, resp)) return;

        int userId = SessionUtil.getUserId(req);
        String pathInfo = req.getPathInfo();

        if (pathInfo == null || pathInfo.equals("/")) {
            // POST /api/targets — add new target
            addTarget(userId, req, resp);
        } else {
            // POST /api/targets/{id}/verify
            String[] parts = pathInfo.split("/");
            if (parts.length == 3 && "verify".equals(parts[2])) {
                try {
                    int targetId = Integer.parseInt(parts[1]);
                    verifyTarget(userId, targetId, resp);
                } catch (NumberFormatException e) {
                    resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid target ID")));
                }
            } else {
                resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Not found")));
            }
        }
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        resp.setContentType("application/json");
        if (!SessionUtil.requireAuth(req, resp)) return;

        int userId = SessionUtil.getUserId(req);
        String pathInfo = req.getPathInfo();

        if (pathInfo == null || pathInfo.equals("/")) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Target ID required")));
            return;
        }

        String[] parts = pathInfo.split("/");
        if (parts.length >= 2) {
            try {
                int targetId = Integer.parseInt(parts[1]);
                deleteTarget(userId, targetId, resp);
            } catch (NumberFormatException e) {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid target ID")));
            }
        }
    }

    private void listTargets(int userId, HttpServletResponse resp) throws IOException {
        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement ps = conn.prepareStatement(
                "SELECT id, user_id, url, token, verified, created_at FROM targets WHERE user_id = ? ORDER BY created_at DESC"
            );
            ps.setInt(1, userId);
            ResultSet rs = ps.executeQuery();

            List<Map<String, Object>> targets = new ArrayList<>();
            while (rs.next()) {
                targets.add(Map.of(
                    "id", rs.getInt("id"),
                    "userId", rs.getInt("user_id"),
                    "url", rs.getString("url"),
                    "token", rs.getString("token"),
                    "verified", rs.getBoolean("verified"),
                    "createdAt", rs.getTimestamp("created_at").toString()
                ));
            }
            resp.getWriter().write(JsonUtil.toJson(targets));
        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Failed to retrieve targets: " + e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private void addTarget(int userId, HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Map<?, ?> body;
        try {
            body = JsonUtil.fromJson(req.getReader().lines().reduce("", String::concat), Map.class);
        } catch (Exception e) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid JSON body")));
            return;
        }

        String url = (String) body.get("url");
        if (url == null || url.isBlank()) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "URL is required")));
            return;
        }

        url = url.trim();
        // Normalize URL
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
        }
        // Remove trailing slash
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }

        // Validate URL format
        try {
            URI.create(url);
        } catch (IllegalArgumentException e) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid URL format")));
            return;
        }

        String token = "vs-" + UUID.randomUUID().toString().replace("-", "");

        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO targets (user_id, url, token, verified) VALUES (?, ?, ?, TRUE) RETURNING id, user_id, url, token, verified, created_at"
            );
            ps.setInt(1, userId);
            ps.setString(2, url);
            ps.setString(3, token);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                Map<String, Object> target = Map.of(
                    "id", rs.getInt("id"),
                    "userId", rs.getInt("user_id"),
                    "url", rs.getString("url"),
                    "token", rs.getString("token"),
                    "verified", rs.getBoolean("verified"),
                    "createdAt", rs.getTimestamp("created_at").toString()
                );
                resp.setStatus(HttpServletResponse.SC_CREATED);
                resp.getWriter().write(JsonUtil.toJson(target));
            }
        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Failed to add target: " + e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private void verifyTarget(int userId, int targetId, HttpServletResponse resp) throws IOException {
        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement updatePs = conn.prepareStatement(
                "UPDATE targets SET verified = TRUE WHERE id = ? AND user_id = ?"
            );
            updatePs.setInt(1, targetId);
            updatePs.setInt(2, userId);
            int rows = updatePs.executeUpdate();

            if (rows > 0) {
                resp.getWriter().write(JsonUtil.toJson(Map.of(
                    "verified", true,
                    "message", "Target is active and ready for testing!"
                )));
            } else {
                resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Target not found")));
            }
        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Verification failed: " + e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private void deleteTarget(int userId, int targetId, HttpServletResponse resp) throws IOException {
        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement ps = conn.prepareStatement(
                "DELETE FROM targets WHERE id = ? AND user_id = ? RETURNING id"
            );
            ps.setInt(1, targetId);
            ps.setInt(2, userId);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                resp.getWriter().write(JsonUtil.toJson(Map.of("message", "Target deleted successfully")));
            } else {
                resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Target not found")));
            }
        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Failed to delete target: " + e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }
}
