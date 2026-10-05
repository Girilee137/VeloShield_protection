package com.veloshield.servlet;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.veloshield.config.DatabaseManager;
import com.veloshield.util.JsonUtil;
import com.veloshield.util.SessionUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.regex.Pattern;

public class AuthServlet extends HttpServlet {

    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        resp.setContentType("application/json");
        String pathInfo = req.getPathInfo();

        if (pathInfo == null) pathInfo = "/";

        switch (pathInfo) {
            case "/register" -> handleRegister(req, resp);
            case "/login"    -> handleLogin(req, resp);
            case "/logout"   -> handleLogout(req, resp);
            default -> {
                resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Endpoint not found")));
            }
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        resp.setContentType("application/json");
        String pathInfo = req.getPathInfo();

        if ("/me".equals(pathInfo)) {
            handleMe(req, resp);
        } else {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Endpoint not found")));
        }
    }

    private void handleRegister(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Map<?, ?> body;
        try {
            body = JsonUtil.fromJson(req.getReader().lines().reduce("", String::concat), Map.class);
        } catch (Exception e) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid JSON body")));
            return;
        }

        String email = (String) body.get("email");
        String password = (String) body.get("password");

        if (email == null || password == null || email.isBlank() || password.isBlank()) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Email and password are required")));
            return;
        }

        email = email.trim().toLowerCase();

        if (!EMAIL_PATTERN.matcher(email).matches()) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid email format")));
            return;
        }

        if (password.length() < 8) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Password must be at least 8 characters")));
            return;
        }

        String hash = BCrypt.withDefaults().hashToString(12, password.toCharArray());

        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO users (email, password_hash) VALUES (?, ?) RETURNING id, email, created_at"
            );
            ps.setString(1, email);
            ps.setString(2, hash);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                int userId = rs.getInt("id");
                String userEmail = rs.getString("email");

                HttpSession session = req.getSession(true);
                session.setAttribute("userId", userId);
                session.setAttribute("email", userEmail);

                resp.setStatus(HttpServletResponse.SC_CREATED);
                resp.getWriter().write(JsonUtil.toJson(Map.of("id", userId, "email", userEmail)));
            }
        } catch (SQLException e) {
            if (e.getMessage() != null && e.getMessage().contains("unique")) {
                resp.setStatus(HttpServletResponse.SC_CONFLICT);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "An account with this email already exists")));
            } else {
                resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Registration failed: " + e.getMessage())));
            }
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private void handleLogin(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Map<?, ?> body;
        try {
            body = JsonUtil.fromJson(req.getReader().lines().reduce("", String::concat), Map.class);
        } catch (Exception e) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid JSON body")));
            return;
        }

        String email = (String) body.get("email");
        String password = (String) body.get("password");

        if (email == null || password == null || email.isBlank() || password.isBlank()) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Email and password are required")));
            return;
        }

        email = email.trim().toLowerCase();

        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement ps = conn.prepareStatement(
                "SELECT id, email, password_hash FROM users WHERE email = ?"
            );
            ps.setString(1, email);
            ResultSet rs = ps.executeQuery();

            if (!rs.next()) {
                resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid email or password")));
                return;
            }

            int userId = rs.getInt("id");
            String storedHash = rs.getString("password_hash");
            String userEmail = rs.getString("email");

            BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), storedHash);
            if (!result.verified) {
                resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Invalid email or password")));
                return;
            }

            HttpSession session = req.getSession(true);
            session.setAttribute("userId", userId);
            session.setAttribute("email", userEmail);

            resp.getWriter().write(JsonUtil.toJson(Map.of("id", userId, "email", userEmail)));
        } catch (SQLException e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write(JsonUtil.toJson(Map.of("error", "Login failed: " + e.getMessage())));
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private void handleLogout(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        HttpSession session = req.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        resp.getWriter().write(JsonUtil.toJson(Map.of("message", "Logged out successfully")));
    }

    private void handleMe(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (!SessionUtil.requireAuth(req, resp)) return;

        HttpSession session = req.getSession(false);
        int userId = (Integer) session.getAttribute("userId");
        String email = (String) session.getAttribute("email");

        resp.getWriter().write(JsonUtil.toJson(Map.of("id", userId, "email", email)));
    }
}
