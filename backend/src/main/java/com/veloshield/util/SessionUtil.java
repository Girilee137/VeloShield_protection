package com.veloshield.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.Map;

public class SessionUtil {

    private SessionUtil() {}

    /**
     * Returns the userId from the current session, or null if not authenticated.
     */
    public static Integer getUserId(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) return null;
        Object userId = session.getAttribute("userId");
        if (userId == null) return null;
        return (Integer) userId;
    }

    /**
     * Checks if the request is authenticated.
     * If not, writes a 401 JSON error response and returns false.
     */
    public static boolean requireAuth(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Integer userId = getUserId(request);
        if (userId == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write(JsonUtil.toJson(Map.of("error", "Unauthorized. Please log in.")));
            return false;
        }
        return true;
    }
}
