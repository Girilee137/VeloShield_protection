package com.veloshield.servlet;

import com.veloshield.config.DatabaseManager;
import com.veloshield.model.Finding;
import com.veloshield.util.JsonUtil;
import com.veloshield.util.SessionUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.sql.*;
import java.util.*;

public class AssessmentServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        if (!SessionUtil.requireAuth(req, resp)) return;

        int userId = SessionUtil.getUserId(req);
        String pathInfo = req.getPathInfo();

        if (pathInfo != null && pathInfo.equals("/diff")) {
            handleDiff(userId, req, resp);
            return;
        }

        // List assessments
        String typeParam = req.getParameter("type");
        listAssessments(userId, typeParam, resp);
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        if (!SessionUtil.requireAuth(req, resp)) return;

        int userId = SessionUtil.getUserId(req);
        String pathInfo = req.getPathInfo();

        if (pathInfo == null || pathInfo.equals("/")) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Assessment ID required")));
            return;
        }

        try {
            int id = Integer.parseInt(pathInfo.substring(1));
            deleteAssessment(userId, id, resp);
        } catch (NumberFormatException e) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid ID")));
        }
    }

    private void listAssessments(int userId, String typeParam, HttpServletResponse resp) throws IOException {
        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            String sql = "SELECT id, assessment_type, target_ref, status, scores_json, metrics_json, started_at, finished_at " +
                         "FROM assessments WHERE user_id = ? " +
                         (typeParam != null && !typeParam.isBlank() ? "AND assessment_type = ? " : "") +
                         "ORDER BY started_at DESC";

            PreparedStatement ps = conn.prepareStatement(sql);
            ps.setInt(1, userId);
            if (typeParam != null && !typeParam.isBlank()) {
                ps.setString(2, typeParam.trim().toUpperCase());
            }

            ResultSet rs = ps.executeQuery();
            List<Map<String, Object>> list = new ArrayList<>();

            while (rs.next()) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("id", rs.getInt("id"));
                item.put("assessmentType", rs.getString("assessment_type"));
                item.put("targetRef", rs.getString("target_ref"));
                item.put("status", rs.getString("status"));
                item.put("scores", JsonUtil.fromJson(rs.getString("scores_json"), Map.class));
                item.put("metrics", JsonUtil.fromJson(rs.getString("metrics_json"), Map.class));
                item.put("startedAt", rs.getTimestamp("started_at") != null ? rs.getTimestamp("started_at").toString() : null);
                list.add(item);
            }

            resp.getWriter().write(JsonUtil.toJson(list));

        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private void handleDiff(int userId, HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String curParam = req.getParameter("current");
        String prevParam = req.getParameter("previous");

        if (curParam == null || prevParam == null) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Parameters 'current' and 'previous' required")));
            return;
        }

        Connection conn = null;
        try {
            int curId = Integer.parseInt(curParam);
            int prevId = Integer.parseInt(prevParam);

            conn = DatabaseManager.getConnection();

            Map<String, Object> curScores = getScores(conn, userId, curId);
            Map<String, Object> prevScores = getScores(conn, userId, prevId);

            if (curScores == null || prevScores == null) {
                resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "One or both assessments not found")));
                return;
            }

            List<Finding> curFindings = getFindings(conn, curId);
            List<Finding> prevFindings = getFindings(conn, prevId);

            Set<String> prevTitles = new HashSet<>();
            for (Finding f : prevFindings) prevTitles.add(f.getTitle());

            Set<String> curTitles = new HashSet<>();
            for (Finding f : curFindings) curTitles.add(f.getTitle());

            List<Finding> newFindings = new ArrayList<>();
            List<Finding> recurringFindings = new ArrayList<>();
            List<Finding> resolvedFindings = new ArrayList<>();

            for (Finding f : curFindings) {
                if (!prevTitles.contains(f.getTitle())) {
                    newFindings.add(f);
                } else {
                    recurringFindings.add(f);
                }
            }

            for (Finding f : prevFindings) {
                if (!curTitles.contains(f.getTitle())) {
                    resolvedFindings.add(f);
                }
            }

            int curOverall = curScores.get("overall") instanceof Number n ? n.intValue() : 0;
            int prevOverall = prevScores.get("overall") instanceof Number n ? n.intValue() : 0;
            int scoreChange = curOverall - prevOverall;

            Map<String, Object> diff = new LinkedHashMap<>();
            diff.put("currentId", curId);
            diff.put("previousId", prevId);
            diff.put("currentScore", curOverall);
            diff.put("previousScore", prevOverall);
            diff.put("scoreChange", scoreChange);
            diff.put("newFindings", newFindings);
            diff.put("recurringFindings", recurringFindings);
            diff.put("resolvedFindings", resolvedFindings);

            resp.getWriter().write(JsonUtil.toJson(diff));

        } catch (Exception e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private void deleteAssessment(int userId, int id, HttpServletResponse resp) throws IOException {
        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement ps = conn.prepareStatement("DELETE FROM assessments WHERE id = ? AND user_id = ?");
            ps.setInt(1, id);
            ps.setInt(2, userId);
            int rows = ps.executeUpdate();
            if (rows > 0) {
                resp.getWriter().write(JsonUtil.toJson(Map.of("message", "Assessment deleted successfully")));
            } else {
                resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Assessment not found")));
            }
        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private Map<String, Object> getScores(Connection conn, int userId, int id) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT scores_json FROM assessments WHERE id = ? AND user_id = ?");
        ps.setInt(1, id);
        ps.setInt(2, userId);
        ResultSet rs = ps.executeQuery();
        if (rs.next()) {
            return JsonUtil.fromJson(rs.getString("scores_json"), Map.class);
        }
        return null;
    }

    private List<Finding> getFindings(Connection conn, int assessmentId) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT title, category, severity, recommendation, affected_file_or_url FROM findings WHERE assessment_id = ?");
        ps.setInt(1, assessmentId);
        ResultSet rs = ps.executeQuery();
        List<Finding> list = new ArrayList<>();
        while (rs.next()) {
            Finding f = new Finding();
            f.setTitle(rs.getString("title"));
            f.setCategory(rs.getString("category"));
            f.setSeverity(rs.getString("severity"));
            f.setRecommendation(rs.getString("recommendation"));
            f.setAffectedFileOrUrl(rs.getString("affected_file_or_url"));
            list.add(f);
        }
        return list;
    }
}
