package com.veloshield.servlet;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

public class StaticServlet extends HttpServlet {

    private static final Map<String, String> MIME_TYPES = Map.ofEntries(
            Map.entry("html", "text/html; charset=utf-8"),
            Map.entry("htm", "text/html; charset=utf-8"),
            Map.entry("css", "text/css; charset=utf-8"),
            Map.entry("js", "application/javascript; charset=utf-8"),
            Map.entry("json", "application/json; charset=utf-8"),
            Map.entry("png", "image/png"),
            Map.entry("jpg", "image/jpeg"),
            Map.entry("jpeg", "image/jpeg"),
            Map.entry("gif", "image/gif"),
            Map.entry("svg", "image/svg+xml"),
            Map.entry("ico", "image/x-icon"),
            Map.entry("txt", "text/plain; charset=utf-8"),
            Map.entry("woff", "font/woff"),
            Map.entry("woff2", "font/woff2"),
            Map.entry("ttf", "font/ttf")
    );

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String path = req.getRequestURI();

        String contextPath = req.getContextPath();
        if (contextPath != null && !contextPath.isEmpty() && path.startsWith(contextPath)) {
            path = path.substring(contextPath.length());
        }

        if (path == null || path.isEmpty() || path.equals("/")) {
            path = "/index.html";
        } else if (path.equals("/dashboard")) {
            path = "/dashboard.html";
        }

        // Prevent directory traversal
        if (path.contains("..")) {
            resp.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        // 1. Try serving from local disk folders
        File[] candidateDirs = new File[] {
                new File("frontend"),
                new File("../frontend"),
                new File("web_project/frontend")
        };

        File fileOnDisk = null;
        for (File dir : candidateDirs) {
            File f = new File(dir, path.startsWith("/") ? path.substring(1) : path);
            if (f.exists() && f.isFile()) {
                fileOnDisk = f;
                break;
            }
        }

        if (fileOnDisk != null) {
            serveFile(fileOnDisk, resp);
            return;
        }

        // 2. Try serving from classpath resource (/static/...)
        String resourcePath = "/static" + (path.startsWith("/") ? path : "/" + path);
        InputStream is = getClass().getResourceAsStream(resourcePath);
        if (is == null && resourcePath.startsWith("/")) {
            is = getClass().getClassLoader().getResourceAsStream(resourcePath.substring(1));
        }
        if (is != null) {
            try (InputStream stream = is) {
                serveStream(resourcePath, stream, resp);
                return;
            }
        }

        // 404 if not found
        resp.sendError(HttpServletResponse.SC_NOT_FOUND);
    }

    private void serveFile(File file, HttpServletResponse resp) throws IOException {
        setContentType(file.getName(), resp);
        resp.setContentLengthLong(file.length());
        resp.setHeader("Cache-Control", "no-cache");
        try (InputStream in = new FileInputStream(file); OutputStream out = resp.getOutputStream()) {
            in.transferTo(out);
        }
    }

    private void serveStream(String name, InputStream in, HttpServletResponse resp) throws IOException {
        setContentType(name, resp);
        resp.setHeader("Cache-Control", "no-cache");
        try (OutputStream out = resp.getOutputStream()) {
            in.transferTo(out);
        }
    }

    private void setContentType(String filename, HttpServletResponse resp) {
        int dot = filename.lastIndexOf('.');
        if (dot != -1) {
            String ext = filename.substring(dot + 1).toLowerCase();
            String mime = MIME_TYPES.get(ext);
            if (mime != null) {
                resp.setContentType(mime);
                return;
            }
        }
        resp.setContentType("application/octet-stream");
    }
}
