package com.veloshield.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public class CorsFilter implements Filter {

    private String allowedOrigin;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String envOrigin = System.getenv("FRONTEND_URL");
        allowedOrigin = (envOrigin != null && !envOrigin.isBlank()) ? envOrigin.trim() : "*";
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpReq = (HttpServletRequest) request;
        HttpServletResponse httpRes = (HttpServletResponse) response;

        String origin = httpReq.getHeader("Origin");

        if (origin != null && !origin.isBlank()) {
            if ("*".equals(allowedOrigin)
                    || allowedOrigin.equals(origin)
                    || origin.startsWith("http://localhost")
                    || origin.startsWith("http://127.0.0.1")
                    || "null".equals(origin)) {
                httpRes.setHeader("Access-Control-Allow-Origin", origin);
                httpRes.setHeader("Vary", "Origin");
            } else {
                httpRes.setHeader("Access-Control-Allow-Origin", allowedOrigin);
            }
        } else if (!"*".equals(allowedOrigin)) {
            httpRes.setHeader("Access-Control-Allow-Origin", allowedOrigin);
        } else {
            httpRes.setHeader("Access-Control-Allow-Origin", "*");
        }

        httpRes.setHeader("Access-Control-Allow-Credentials", "true");
        httpRes.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH");
        httpRes.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Cookie, X-Requested-With");
        httpRes.setHeader("Access-Control-Max-Age", "86400");

        // Handle preflight
        if ("OPTIONS".equalsIgnoreCase(httpReq.getMethod())) {
            httpRes.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {}
}
