package com.veloshield.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.veloshield.config.DatabaseManager;
import com.veloshield.util.JsonUtil;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class LoadTestService {

    private static final LoadTestService INSTANCE = new LoadTestService();

    // Track active tests to prevent running duplicate tests
    private final Set<Integer> activeTests = ConcurrentHashMap.newKeySet();

    private LoadTestService() {}

    public static LoadTestService getInstance() {
        return INSTANCE;
    }

    /**
     * Starts a load test asynchronously. Returns immediately.
     * Updates the DB record as the test progresses.
     */
    public void runTest(int testId, String targetUrl, int concurrency, int durationSeconds, int maxRequests) {
        if (!activeTests.add(testId)) {
            System.out.println("[LoadTest] Test " + testId + " is already running.");
            return;
        }

        Thread testThread = Thread.ofVirtual().name("load-test-" + testId).start(() -> {
            executeTest(testId, targetUrl, concurrency, durationSeconds, maxRequests);
            activeTests.remove(testId);
        });

        // Daemon thread so it doesn't prevent JVM shutdown
        System.out.println("[LoadTest] Started test " + testId + " targeting " + targetUrl);
    }

    private void executeTest(int testId, String targetUrl, int concurrency, int durationSeconds, int maxRequests) {
        // Enforce safety limits
        concurrency = Math.min(concurrency, 50);
        durationSeconds = Math.min(durationSeconds, 120);
        maxRequests = Math.min(maxRequests, 5000);

        AtomicInteger attempted = new AtomicInteger(0);
        AtomicInteger succeeded = new AtomicInteger(0);
        AtomicInteger failed = new AtomicInteger(0);
        List<Long> latencies = Collections.synchronizedList(new ArrayList<>());
        Map<String, AtomicInteger> errorCounts = new ConcurrentHashMap<>();

        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .version(HttpClient.Version.HTTP_1_1)
                .build();

        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        Instant deadline = Instant.now().plusSeconds(durationSeconds);

        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < maxRequests; i++) {
            if (Instant.now().isAfter(deadline)) break;

            final String url = targetUrl;
            Future<?> future = executor.submit(() -> {
                // Check time limit before each request
                if (Instant.now().isAfter(deadline)) return;

                long start = System.currentTimeMillis();
                try {
                    HttpRequest request = HttpRequest.newBuilder()
                            .uri(URI.create(url))
                            .timeout(Duration.ofSeconds(10))
                            .header("User-Agent", "VeloShield-Assessment/1.0 (Authorized Security Assessment)")
                            .GET()
                            .build();

                    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                    long latency = System.currentTimeMillis() - start;
                    latencies.add(latency);
                    attempted.incrementAndGet();

                    int status = response.statusCode();
                    if (status >= 200 && status < 400) {
                        succeeded.incrementAndGet();
                    } else {
                        failed.incrementAndGet();
                        String key = "HTTP_" + status;
                        errorCounts.computeIfAbsent(key, k -> new AtomicInteger(0)).incrementAndGet();
                    }
                } catch (Exception e) {
                    long latency = System.currentTimeMillis() - start;
                    latencies.add(latency);
                    attempted.incrementAndGet();
                    failed.incrementAndGet();

                    String key = classifyError(e);
                    errorCounts.computeIfAbsent(key, k -> new AtomicInteger(0)).incrementAndGet();
                }
            });
            futures.add(future);
        }

        // Signal no more tasks, then wait for running ones to finish
        executor.shutdown();
        long remainingMs = Math.max(0, Duration.between(Instant.now(), deadline).toMillis()) + 5000L;
        try {
            if (!executor.awaitTermination(remainingMs, TimeUnit.MILLISECONDS)) {
                executor.shutdownNow(); // force-stop if still running after deadline
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        // Calculate statistics
        List<Long> sortedLatencies = new ArrayList<>(latencies);
        Collections.sort(sortedLatencies);

        double avgLatency = sortedLatencies.isEmpty() ? 0.0 :
                sortedLatencies.stream().mapToLong(Long::longValue).average().orElse(0.0);

        double p95Latency = 0.0;
        if (!sortedLatencies.isEmpty()) {
            int p95Index = (int) Math.ceil(sortedLatencies.size() * 0.95) - 1;
            p95Index = Math.max(0, Math.min(p95Index, sortedLatencies.size() - 1));
            p95Latency = sortedLatencies.get(p95Index);
        }

        // Serialize error map
        Map<String, Integer> errorsForJson = new LinkedHashMap<>();
        errorCounts.forEach((k, v) -> errorsForJson.put(k, v.get()));
        String errorsJson = JsonUtil.toJson(errorsForJson);

        // Update DB
        Connection conn = null;
        try {
            conn = DatabaseManager.getConnection();
            PreparedStatement ps = conn.prepareStatement(
                "UPDATE tests SET status = 'completed', attempted = ?, succeeded = ?, failed = ?, " +
                "avg_latency_ms = ?, p95_latency_ms = ?, errors = ?, finished_at = ? WHERE id = ?"
            );
            ps.setInt(1, attempted.get());
            ps.setInt(2, succeeded.get());
            ps.setInt(3, failed.get());
            ps.setDouble(4, avgLatency);
            ps.setDouble(5, p95Latency);
            ps.setString(6, errorsJson);
            ps.setTimestamp(7, Timestamp.from(Instant.now()));
            ps.setInt(8, testId);
            ps.executeUpdate();

            System.out.printf("[LoadTest] Test %d completed. Attempted=%d, Succeeded=%d, Failed=%d, AvgLatency=%.1fms, P95=%.1fms%n",
                    testId, attempted.get(), succeeded.get(), failed.get(), avgLatency, p95Latency);

        } catch (Exception e) {
            System.err.println("[LoadTest] Failed to update test " + testId + ": " + e.getMessage());
            // Try to mark as failed
            try {
                if (conn != null) {
                    PreparedStatement ps = conn.prepareStatement(
                        "UPDATE tests SET status = 'failed', finished_at = ? WHERE id = ?"
                    );
                    ps.setTimestamp(1, Timestamp.from(Instant.now()));
                    ps.setInt(2, testId);
                    ps.executeUpdate();
                }
            } catch (Exception ex) {
                System.err.println("[LoadTest] Could not mark test as failed: " + ex.getMessage());
            }
        } finally {
            DatabaseManager.releaseConnection(conn);
        }
    }

    private String classifyError(Exception e) {
        String msg = e.getMessage();
        if (msg == null) msg = e.getClass().getSimpleName();
        if (e instanceof java.net.http.HttpTimeoutException || msg.contains("timed out") || msg.contains("timeout")) {
            return "TIMEOUT";
        }
        if (e instanceof java.net.ConnectException || msg.contains("Connection refused") || msg.contains("connect")) {
            return "CONNECTION_REFUSED";
        }
        if (e instanceof java.net.UnknownHostException || msg.contains("Unknown host")) {
            return "DNS_ERROR";
        }
        if (e instanceof javax.net.ssl.SSLException || msg.contains("SSL") || msg.contains("TLS")) {
            return "SSL_ERROR";
        }
        return "NETWORK_ERROR";
    }
}
