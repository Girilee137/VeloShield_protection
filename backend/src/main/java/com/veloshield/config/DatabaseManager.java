package com.veloshield.config;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedList;
import java.util.Queue;

public class DatabaseManager {

    private static final int POOL_SIZE = 10;
    private static final Queue<Connection> pool = new LinkedList<>();
    private static String jdbcUrl;
    private static String dbUser;
    private static String dbPassword;

    public static synchronized void initialize() {
        String dbUrl = System.getenv("DATABASE_URL");
        if (dbUrl == null || dbUrl.isBlank()) {
            throw new RuntimeException("DATABASE_URL environment variable is not set.");
        }

        try {
            Class.forName("org.postgresql.Driver");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("PostgreSQL JDBC driver not found", e);
        }

        // Handle Neon style strings containing embedded username and passwords
        if (dbUrl.startsWith("postgresql://") || dbUrl.startsWith("postgres://")) {
            try {
                URI uri = new URI(dbUrl);
                
                // Extract credentials from the user info section (username:password)
                String userInfo = uri.getUserInfo();
                if (userInfo != null && userInfo.contains(":")) {
                    String[] parts = userInfo.split(":", 2);
                    dbUser = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
                    dbPassword = URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
                }

                // Construct clean JDBC URL structure
                int port = uri.getPort() == -1 ? 5432 : uri.getPort();
                jdbcUrl = "jdbc:postgresql://" + uri.getHost() + ":" + port + uri.getPath();

                // Append query strings (like sslmode=require & channel_binding)
                if (uri.getQuery() != null) {
                    jdbcUrl += "?" + uri.getQuery();
                } else {
                    jdbcUrl += "?sslmode=require";
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to parse standard database URI string", e);
            }
        } else {
            // Fallback for standard clean jdbc:postgresql:// formats
            jdbcUrl = dbUrl;
            if (!jdbcUrl.contains("sslmode")) {
                jdbcUrl += (jdbcUrl.contains("?") ? "&" : "?") + "sslmode=require";
            }
        }

        // Add tcpKeepAlive=true to prevent premature socket termination on cloud providers
        if (!jdbcUrl.contains("tcpKeepAlive")) {
            jdbcUrl += (jdbcUrl.contains("?") ? "&" : "?") + "tcpKeepAlive=true";
        }

        createTables();
    }

    private static Connection createNewConnection() throws SQLException {
        SQLException lastEx = null;
        for (int attempt = 1; attempt <= 3; attempt++) {
            try {
                Connection conn;
                if (dbUser != null && dbPassword != null) {
                    conn = DriverManager.getConnection(jdbcUrl, dbUser, dbPassword);
                } else {
                    conn = DriverManager.getConnection(jdbcUrl);
                }
                return conn;
            } catch (SQLException e) {
                lastEx = e;
                System.err.println("[DB] Connection attempt " + attempt + " failed: " + e.getMessage());
                if (attempt < 3) {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ignored) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
        }
        throw lastEx;
    }

    private static void createTables() {
        Connection conn = null;
        try {
            conn = getConnection();
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """);

                stmt.execute("""
                    CREATE TABLE IF NOT EXISTS targets (
                        id SERIAL PRIMARY KEY,
                        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        url VARCHAR(500) NOT NULL,
                        token VARCHAR(100) NOT NULL,
                        verified BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """);

                stmt.execute("UPDATE targets SET verified = TRUE");

                stmt.execute("""
                    CREATE TABLE IF NOT EXISTS tests (
                        id SERIAL PRIMARY KEY,
                        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        target_id INT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                        status VARCHAR(50) DEFAULT 'pending',
                        concurrency INT NOT NULL,
                        duration_seconds INT NOT NULL,
                        max_requests INT NOT NULL,
                        attempted INT DEFAULT 0,
                        succeeded INT DEFAULT 0,
                        failed INT DEFAULT 0,
                        avg_latency_ms DOUBLE PRECISION DEFAULT 0,
                        p95_latency_ms DOUBLE PRECISION DEFAULT 0,
                        errors TEXT DEFAULT '{}',
                        started_at TIMESTAMP,
                        finished_at TIMESTAMP
                    )
                """);

                stmt.execute("""
                    CREATE TABLE IF NOT EXISTS assessments (
                        id SERIAL PRIMARY KEY,
                        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        assessment_type VARCHAR(50) NOT NULL,
                        target_ref TEXT NOT NULL,
                        status VARCHAR(50) DEFAULT 'pending',
                        scores_json TEXT DEFAULT '{}',
                        metrics_json TEXT DEFAULT '{}',
                        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        finished_at TIMESTAMP
                    )
                """);

                stmt.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id SERIAL PRIMARY KEY,
                        assessment_id INT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                        category VARCHAR(50) NOT NULL,
                        severity VARCHAR(20) NOT NULL,
                        title VARCHAR(255) NOT NULL,
                        description TEXT,
                        evidence TEXT,
                        affected_file_or_url TEXT,
                        recommendation TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """);

                System.out.println("[DB] Tables verified/created successfully.");
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to create tables: " + e.getMessage(), e);
        } finally {
            releaseConnection(conn);
        }
    }

    public static synchronized Connection getConnection() throws SQLException {
        while (!pool.isEmpty()) {
            Connection conn = pool.poll();
            try {
                if (conn != null && !conn.isClosed() && conn.isValid(2)) {
                    return conn;
                }
            } catch (SQLException ignored) {
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException ignored) {
                }
            }
        }
        return createNewConnection();
    }

    public static synchronized void releaseConnection(Connection conn) {
        if (conn == null) return;
        try {
            if (!conn.isClosed() && conn.isValid(1)) {
                if (pool.size() < POOL_SIZE) {
                    pool.offer(conn);
                    return;
                }
            }
        } catch (SQLException ignored) {
        }
        try {
            conn.close();
        } catch (SQLException ignored) {
        }
    }
}
