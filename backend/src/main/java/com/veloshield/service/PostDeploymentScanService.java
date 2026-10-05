package com.veloshield.service;

import com.veloshield.model.Finding;
import com.veloshield.security.SsrfValidator;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PostDeploymentScanService {

    private static final int MAX_RESPONSE_BYTES = 2 * 1024 * 1024; // 2MB safety limit
    private static final Duration TIMEOUT = Duration.ofSeconds(8);

    private final HttpClient httpClient;

    public PostDeploymentScanService() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER) // Manually validate redirects for SSRF safety!
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    public static class PostScanOutput {
        public List<Finding> findings = new ArrayList<>();
        public Map<String, Object> scores = new HashMap<>();
        public Map<String, Object> metrics = new HashMap<>();
        public Map<String, Object> securityDetails = new HashMap<>();
        public Map<String, Object> performanceDetails = new HashMap<>();
        public Map<String, Object> apiHealthDetails = new HashMap<>();
        public Map<String, Object> thirdPartyDetails = new HashMap<>();
    }

    public PostScanOutput scan(String targetUrl) {
        PostScanOutput output = new PostScanOutput();
        List<Finding> findings = output.findings;

        // 1. SSRF Check
        SsrfValidator.ValidationResult ssrfResult = SsrfValidator.validateUrl(targetUrl);
        if (!ssrfResult.isValid()) {
            findings.add(new Finding(
                    "SECURITY",
                    "CRITICAL",
                    "Target URL Rejected by SSRF Protection Filter",
                    "WHAT IS WRONG: Target URL was rejected because it points to an unauthorized or restricted address.\n" +
                    "WHY IT MATTERS: Prevents attackers from abusing the assessment engine to scan internal or loopback networks.\n" +
                    "EVIDENCE: " + ssrfResult.getMessage() + "\n" +
                    "HOW TO FIX IT: Provide a valid public domain or routable IP address.",
                    "URL: " + targetUrl + " (" + ssrfResult.getMessage() + ")",
                    targetUrl,
                    "Use a publicly accessible domain name."
            ));
            output.scores = ScoringEngine.calculatePostDeploymentScore(findings, 0, 100.0);
            return output;
        }

        // 2. Safe Main Page Fetch (with SSRF-validated redirect following)
        long startTime = System.currentTimeMillis();
        HttpResponse<String> mainResponse = null;
        String finalUrl = targetUrl;
        int redirectCount = 0;

        try {
            String currentUrl = targetUrl;
            while (redirectCount < 5) {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(currentUrl))
                        .timeout(TIMEOUT)
                        .header("User-Agent", "VeloShield-Scanner/1.0 (Authorized Security & Performance Audit)")
                        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                        .GET()
                        .build();

                long hopStart = System.currentTimeMillis();
                HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                long hopTime = System.currentTimeMillis() - hopStart;

                int code = resp.statusCode();
                if (code >= 300 && code < 400 && resp.headers().firstValue("Location").isPresent()) {
                    redirectCount++;
                    String loc = resp.headers().firstValue("Location").get();
                    URI redirectUri = URI.create(currentUrl).resolve(loc);
                    String nextUrl = redirectUri.toString();

                    // Re-validate redirect target with SSRF
                    SsrfValidator.ValidationResult redirectValidation = SsrfValidator.validateUrl(nextUrl);
                    if (!redirectValidation.isValid()) {
                        findings.add(new Finding(
                                "SECURITY",
                                "HIGH",
                                "Redirect Target Rejected by SSRF Filter",
                                "The target redirected to a restricted host: " + redirectValidation.getMessage(),
                                "Redirect from " + currentUrl + " to " + nextUrl,
                                currentUrl,
                                "Ensure redirect targets are legitimate public endpoints."
                        ));
                        break;
                    }
                    currentUrl = nextUrl;
                    finalUrl = nextUrl;
                } else {
                    mainResponse = resp;
                    finalUrl = currentUrl;
                    break;
                }
            }
        } catch (Exception e) {
            findings.add(new Finding(
                    "RELIABILITY",
                    "HIGH",
                    "Connection Failed to Target Website",
                    "Could not complete HTTP handshake with target website: " + e.getMessage(),
                    "Target: " + targetUrl + " | Exception: " + e.getClass().getSimpleName(),
                    targetUrl,
                    "Verify the target website is online and reachable from the internet."
            ));
            output.scores = ScoringEngine.calculatePostDeploymentScore(findings, 5000, 100.0);
            return output;
        }

        long totalLatency = System.currentTimeMillis() - startTime;
        String htmlBody = mainResponse != null && mainResponse.body() != null ? mainResponse.body() : "";
        HttpHeaders headers = mainResponse != null ? mainResponse.headers() : HttpHeaders.of(Map.of(), (a, b) -> true);
        int statusCode = mainResponse != null ? mainResponse.statusCode() : 0;

        // Truncate if response exceeds safe limit
        if (htmlBody.length() > MAX_RESPONSE_BYTES) {
            htmlBody = htmlBody.substring(0, MAX_RESPONSE_BYTES);
        }

        // 3. Security Headers Analysis
        analyzeSecurityHeaders(headers, finalUrl, findings, output.securityDetails);

        // 4. Cookie Security Analysis
        analyzeCookies(headers, finalUrl, findings, output.securityDetails);

        // 5. HTTPS / TLS & Mixed Content
        analyzeHttps(targetUrl, finalUrl, headers, findings, output.securityDetails);

        // 6. CORS Probing
        analyzeCors(finalUrl, findings, output.securityDetails);

        // 7. Information Exposure Analysis
        analyzeInfoExposure(headers, htmlBody, finalUrl, findings, output.securityDetails);

        // 8. Error / Debug Page Probing
        analyzeErrorPage(finalUrl, findings);

        // 9. Public Resources (robots.txt, security.txt, sitemap.xml)
        analyzePublicResources(finalUrl, findings);

        // 10. Performance Analysis
        analyzePerformance(totalLatency, htmlBody, finalUrl, output.performanceDetails);

        // 11. Safe API Health Probing
        analyzeApiHealth(finalUrl, findings, output.apiHealthDetails);

        // 12. Third-Party & Advertisement Analysis
        analyzeThirdPartyAndAds(htmlBody, finalUrl, findings, output.thirdPartyDetails);

        // 13. Calculate Post-Deployment Health Score
        double failureRate = (statusCode >= 200 && statusCode < 400) ? 0.0 : 100.0;
        output.scores = ScoringEngine.calculatePostDeploymentScore(findings, totalLatency, failureRate);

        output.metrics.put("targetUrl", targetUrl);
        output.metrics.put("finalUrl", finalUrl);
        output.metrics.put("statusCode", statusCode);
        output.metrics.put("totalLatencyMs", totalLatency);
        output.metrics.put("redirectCount", redirectCount);
        output.metrics.put("pageSizeBytes", htmlBody.getBytes().length);

        return output;
    }

    private void analyzeSecurityHeaders(HttpHeaders headers, String url, List<Finding> findings, Map<String, Object> secDetails) {
        Map<String, String> headerMap = new LinkedHashMap<>();

        checkHeader("Strict-Transport-Security", headers, "MEDIUM",
                "Missing HTTP Strict Transport Security (HSTS)",
                "Enforces HTTPS connections and protects users from SSL-stripping man-in-the-middle attacks.",
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header to all HTTPS responses.",
                url, findings, headerMap);

        checkHeader("Content-Security-Policy", headers, "MEDIUM",
                "Missing Content Security Policy (CSP)",
                "Restricts sources of executable scripts, stylesheets, and resources, mitigating Cross-Site Scripting (XSS).",
                "Configure a Content-Security-Policy header defining trusted script-src, style-src, and default-src directives.",
                url, findings, headerMap);

        checkHeader("X-Content-Type-Options", headers, "LOW",
                "Missing X-Content-Type-Options Header",
                "Prevents MIME-type sniffing where browsers execute files with disguised MIME types.",
                "Send 'X-Content-Type-Options: nosniff' header.",
                url, findings, headerMap);

        checkHeader("X-Frame-Options", headers, "MEDIUM",
                "Missing X-Frame-Options (Clickjacking Protection)",
                "Prevents the page from being rendered inside an iframe on malicious third-party origins.",
                "Send 'X-Frame-Options: SAMEORIGIN' or 'X-Frame-Options: DENY'.",
                url, findings, headerMap);

        checkHeader("Referrer-Policy", headers, "LOW",
                "Missing Referrer-Policy Header",
                "Controls how much referrer information (including URLs with sensitive query parameters) is sent in outbound requests.",
                "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
                url, findings, headerMap);

        checkHeader("Permissions-Policy", headers, "LOW",
                "Missing Permissions-Policy Header",
                "Restricts browser features like camera, microphone, and geolocation from being invoked without explicit permission.",
                "Add 'Permissions-Policy: geolocation=(), camera=(), microphone=()'.",
                url, findings, headerMap);

        secDetails.put("securityHeaders", headerMap);
    }

    private void checkHeader(String headerName, HttpHeaders headers, String severity,
                             String title, String why, String howToFix, String url,
                             List<Finding> findings, Map<String, String> headerMap) {
        Optional<String> val = headers.firstValue(headerName);
        if (val.isPresent()) {
            headerMap.put(headerName, val.get());
            findings.add(new Finding(
                    "SECURITY",
                    "PASS",
                    headerName + " Configured",
                    headerName + " is actively configured with value: " + val.get(),
                    headerName + ": " + val.get(),
                    url,
                    "Header is correctly present."
            ));
        } else {
            headerMap.put(headerName, "MISSING");
            findings.add(new Finding(
                    "SECURITY",
                    severity,
                    title,
                    "WHAT IS WRONG: " + headerName + " header was not found in the HTTP response.\n" +
                    "WHY IT MATTERS: " + why + "\n" +
                    "EVIDENCE: Inspected response headers for " + url + ".\n" +
                    "HOW TO FIX IT: " + howToFix,
                    "Header '" + headerName + "' missing",
                    url,
                    howToFix
            ));
        }
    }

    private void analyzeCookies(HttpHeaders headers, String url, List<Finding> findings, Map<String, Object> secDetails) {
        List<String> setCookies = headers.allValues("Set-Cookie");
        List<Map<String, Object>> cookieMetaList = new ArrayList<>();

        if (setCookies.isEmpty()) {
            secDetails.put("cookies", cookieMetaList);
            return;
        }

        for (String sc : setCookies) {
            String[] parts = sc.split(";");
            String name = parts[0].split("=")[0].trim();
            boolean isSecure = sc.toLowerCase().contains("secure");
            boolean isHttpOnly = sc.toLowerCase().contains("httponly");
            boolean hasSameSite = sc.toLowerCase().contains("samesite");

            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("name", name);
            meta.put("secure", isSecure);
            meta.put("httpOnly", isHttpOnly);
            meta.put("sameSite", hasSameSite);
            cookieMetaList.add(meta);

            if (!isHttpOnly) {
                findings.add(new Finding(
                        "COOKIE",
                        "MEDIUM",
                        "Cookie Missing HttpOnly Flag (" + name + ")",
                        "WHAT IS WRONG: Cookie '" + name + "' is accessible to client-side JavaScript.\n" +
                        "WHY IT MATTERS: In case of an XSS vulnerability, attackers can steal this cookie.\n" +
                        "EVIDENCE: Set-Cookie: " + name + "=<masked>; (HttpOnly flag absent)\n" +
                        "HOW TO FIX IT: Add the HttpOnly directive when setting the cookie.",
                        "Cookie '" + name + "' without HttpOnly",
                        url,
                        "Enable HttpOnly attribute on " + name + "."
                ));
            }
            if (!isSecure && url.startsWith("https://")) {
                findings.add(new Finding(
                        "COOKIE",
                        "HIGH",
                        "Cookie Missing Secure Flag on HTTPS (" + name + ")",
                        "WHAT IS WRONG: Cookie '" + name + "' does not enforce transmission over encrypted connections.\n" +
                        "WHY IT MATTERS: The cookie could be transmitted in cleartext over unencrypted HTTP channels.\n" +
                        "EVIDENCE: Set-Cookie: " + name + "=<masked>; (Secure flag absent)\n" +
                        "HOW TO FIX IT: Add the Secure attribute to ensure cookie is only sent via HTTPS.",
                        "Cookie '" + name + "' without Secure",
                        url,
                        "Enable Secure attribute on " + name + "."
                ));
            }
        }

        secDetails.put("cookies", cookieMetaList);
    }

    private void analyzeHttps(String originalUrl, String finalUrl, HttpHeaders headers, List<Finding> findings, Map<String, Object> secDetails) {
        boolean isHttps = finalUrl.toLowerCase().startsWith("https://");
        secDetails.put("isHttps", isHttps);

        if (isHttps) {
            findings.add(new Finding(
                    "HTTPS",
                    "PASS",
                    "HTTPS Encryption Active",
                    "Website communicates over encrypted TLS/HTTPS connection.",
                    "Active protocol: HTTPS (" + finalUrl + ")",
                    finalUrl,
                    "Maintain valid SSL/TLS certificates and renew prior to expiration."
            ));
        } else {
            findings.add(new Finding(
                    "HTTPS",
                    "HIGH",
                    "Website Served Over Insecure HTTP",
                    "WHAT IS WRONG: The website is accessible over unencrypted HTTP.\n" +
                    "WHY IT MATTERS: Traffic, session cookies, and user submissions can be intercepted or modified by network eavesdroppers.\n" +
                    "EVIDENCE: URL is " + finalUrl + ".\n" +
                    "HOW TO FIX IT: Obtain a TLS certificate (e.g., Let's Encrypt) and enforce HTTP to HTTPS automatic redirection.",
                    "Unencrypted HTTP URL: " + finalUrl,
                    finalUrl,
                    "Enforce HTTPS across all pages."
            ));
        }
    }

    private void analyzeCors(String url, List<Finding> findings, Map<String, Object> secDetails) {
        try {
            HttpRequest corsReq = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(TIMEOUT)
                    .header("Origin", "https://untrusted-external-domain.com")
                    .header("User-Agent", "VeloShield-Scanner/1.0")
                    .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                    .build();

            HttpResponse<Void> resp = httpClient.send(corsReq, HttpResponse.BodyHandlers.discarding());
            Optional<String> allowOrigin = resp.headers().firstValue("Access-Control-Allow-Origin");
            Optional<String> allowCreds = resp.headers().firstValue("Access-Control-Allow-Credentials");

            Map<String, String> corsInfo = new HashMap<>();
            corsInfo.put("allowOrigin", allowOrigin.orElse("none"));
            corsInfo.put("allowCredentials", allowCreds.orElse("none"));
            secDetails.put("cors", corsInfo);

            if (allowOrigin.isPresent()) {
                String val = allowOrigin.get();
                if ("*".equals(val) && "true".equalsIgnoreCase(allowCreds.orElse(""))) {
                    findings.add(new Finding(
                            "CORS",
                            "HIGH",
                            "Overly Permissive CORS Configuration with Credentials",
                            "WHAT IS WRONG: Server returned Access-Control-Allow-Origin: * along with Access-Control-Allow-Credentials: true.\n" +
                            "WHY IT MATTERS: Vulnerable to cross-origin data theft if browsers do not strictly block wildcard credentials.\n" +
                            "EVIDENCE: Origin header echoed with credentials allowed.\n" +
                            "HOW TO FIX IT: Explicitly whitelist approved origins instead of wildcard.",
                            "CORS: Origin=* with Credentials=true",
                            url,
                            "Restrict allowed origins to trusted domains."
                    ));
                } else if (val.contains("untrusted-external-domain.com")) {
                    findings.add(new Finding(
                            "CORS",
                            "MEDIUM",
                            "Arbitrary Origin Reflection in CORS Header",
                            "WHAT IS WRONG: Server reflects arbitrary Origin header without whitelist validation.\n" +
                            "WHY IT MATTERS: Any website can make cross-origin authenticated requests to this server.\n" +
                            "EVIDENCE: Sent Origin: https://untrusted-external-domain.com, received Allow-Origin: " + val + ".\n" +
                            "HOW TO FIX IT: Validate requested origin against an explicit server-side whitelist.",
                            "CORS: Reflected untrusted Origin",
                            url,
                            "Validate Origin against an explicit whitelist."
                    ));
                }
            }
        } catch (Exception ignored) {}
    }

    private void analyzeInfoExposure(HttpHeaders headers, String body, String url, List<Finding> findings, Map<String, Object> secDetails) {
        Optional<String> serverHeader = headers.firstValue("Server");
        Optional<String> poweredBy = headers.firstValue("X-Powered-By");

        Map<String, String> techInfo = new HashMap<>();
        serverHeader.ifPresent(s -> techInfo.put("server", s));
        poweredBy.ifPresent(p -> techInfo.put("poweredBy", p));
        secDetails.put("technology", techInfo);

        if (serverHeader.isPresent() && (serverHeader.get().matches(".*\\d+\\.\\d+.*"))) {
            findings.add(new Finding(
                    "INFORMATION_EXPOSURE",
                    "LOW",
                    "Detailed Web Server Version Disclosed",
                    "WHAT IS WRONG: Server header discloses detailed version number (" + serverHeader.get() + ").\n" +
                    "WHY IT MATTERS: Precise version banners help attackers target known CVEs for that specific software release.\n" +
                    "EVIDENCE: Server: " + serverHeader.get() + "\n" +
                    "HOW TO FIX IT: Configure your web server (e.g. server_tokens off in Nginx) to suppress version disclosures.",
                    "Server: " + serverHeader.get(),
                    url,
                    "Suppress version banners in server config."
            ));
        }

        if (poweredBy.isPresent()) {
            findings.add(new Finding(
                    "INFORMATION_EXPOSURE",
                    "LOW",
                    "Technology Fingerprint in X-Powered-By Header",
                    "WHAT IS WRONG: X-Powered-By header is present (" + poweredBy.get() + ").\n" +
                    "WHY IT MATTERS: Identifies application framework or runtime.\n" +
                    "EVIDENCE: X-Powered-By: " + poweredBy.get() + "\n" +
                    "HOW TO FIX IT: Disable X-Powered-By header in application framework.",
                    "X-Powered-By: " + poweredBy.get(),
                    url,
                    "Disable X-Powered-By header."
            ));
        }
    }

    private void analyzeErrorPage(String url, List<Finding> findings) {
        try {
            String probeUrl = url + (url.endsWith("/") ? "" : "/") + "veloshield-safe-probe-404-" + System.currentTimeMillis();
            HttpRequest probe = HttpRequest.newBuilder()
                    .uri(URI.create(probeUrl))
                    .timeout(TIMEOUT)
                    .header("User-Agent", "VeloShield-Scanner/1.0")
                    .GET()
                    .build();

            HttpResponse<String> resp = httpClient.send(probe, HttpResponse.BodyHandlers.ofString());
            String body = resp.body() != null ? resp.body() : "";

            if (body.contains("Exception in thread") || body.contains("Traceback (most recent call last)") ||
                body.contains("DEBUG = True") || body.contains("SQL syntax") || body.contains("fatal error in")) {
                findings.add(new Finding(
                        "INFORMATION_EXPOSURE",
                        "HIGH",
                        "Stack Trace / Debug Information Exposed on 404 Page",
                        "WHAT IS WRONG: Non-existent URL probe exposed technical stack trace or database error details.\n" +
                        "WHY IT MATTERS: Internal paths, stack frames, and error parameters aid attackers in mapping system architecture.\n" +
                        "EVIDENCE: Probe to " + probeUrl + " returned debug keywords in body.\n" +
                        "HOW TO FIX IT: Replace default framework debug pages with generic, custom 404 error pages.",
                        "Probe URL: " + probeUrl + " (Returned stack trace / debug details)",
                        probeUrl,
                        "Enable custom error pages and disable production debug modes."
                ));
            } else {
                findings.add(new Finding(
                        "INFORMATION_EXPOSURE",
                        "PASS",
                        "Error Handling Baseline Verified",
                        "404 error page does not expose raw stack traces or internal exception details.",
                        "Safe probe to 404 page returned clean response.",
                        probeUrl,
                        "Maintain sanitized error responses."
                ));
            }
        } catch (Exception ignored) {}
    }

    private void analyzePublicResources(String url, List<Finding> findings) {
        checkPublicFile(url, "robots.txt", findings);
        checkPublicFile(url, ".well-known/security.txt", findings);
    }

    private void checkPublicFile(String baseUrl, String relativePath, List<Finding> findings) {
        try {
            URI base = URI.create(baseUrl);
            URI target = base.resolve("/" + relativePath);
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(target)
                    .timeout(TIMEOUT)
                    .header("User-Agent", "VeloShield-Scanner/1.0")
                    .GET()
                    .build();

            HttpResponse<Void> resp = httpClient.send(req, HttpResponse.BodyHandlers.discarding());
            if (resp.statusCode() == 200) {
                findings.add(new Finding(
                        "CONFIGURATION",
                        "INFO",
                        "Public File Available (" + relativePath + ")",
                        "Found publicly available " + relativePath + " file.",
                        "Status: 200 OK at " + target,
                        target.toString(),
                        "Review public file contents to ensure internal routes are not inadvertently published."
                ));
            }
        } catch (Exception ignored) {}
    }

    private void analyzePerformance(long latencyMs, String html, String url, Map<String, Object> perfDetails) {
        perfDetails.put("totalResponseTimeMs", latencyMs);
        perfDetails.put("pageSizeBytes", html.getBytes().length);
        perfDetails.put("pageSizeFormatted", String.format("%.1f KB", html.getBytes().length / 1024.0));

        // Count resources in HTML
        int scripts = countMatches(html, "<script");
        int stylesheets = countMatches(html, "rel=[\"']stylesheet[\"']");
        int images = countMatches(html, "<img");
        int iframes = countMatches(html, "<iframe");
        int totalResources = scripts + stylesheets + images + iframes;

        perfDetails.put("scriptsCount", scripts);
        perfDetails.put("stylesheetsCount", stylesheets);
        perfDetails.put("imagesCount", images);
        perfDetails.put("iframesCount", iframes);
        perfDetails.put("totalResources", totalResources);
    }

    private void analyzeApiHealth(String url, List<Finding> findings, Map<String, Object> apiDetails) {
        String[] probePaths = {"/api/health", "/health", "/api/status", "/api/v1", "/api/users"};
        List<Map<String, Object>> endpoints = new ArrayList<>();

        for (String path : probePaths) {
            try {
                URI targetUri = URI.create(url).resolve(path);
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(targetUri)
                        .timeout(Duration.ofSeconds(3))
                        .header("User-Agent", "VeloShield-Scanner/1.0")
                        .GET()
                        .build();

                HttpResponse<Void> resp = httpClient.send(req, HttpResponse.BodyHandlers.discarding());
                int sc = resp.statusCode();

                Map<String, Object> ep = new LinkedHashMap<>();
                ep.put("path", path);
                ep.put("status", sc);

                if (sc == 200) {
                    ep.put("assessment", "PASS — Endpoint Active");
                } else if (sc == 401 || sc == 403) {
                    ep.put("assessment", "PASS — Access Controlled (Authentication Functioning)");
                } else if (sc == 404) {
                    ep.put("assessment", "INFO — Not Found");
                } else {
                    ep.put("assessment", "HTTP " + sc);
                }
                endpoints.add(ep);

                if (sc == 401 || sc == 403) {
                    findings.add(new Finding(
                            "API",
                            "PASS",
                            "Access Control Active on API Route (" + path + ")",
                            "Protected endpoint returned HTTP " + sc + ". This indicates that authorization checks are active and blocking unauthenticated requests.",
                            "Path: " + path + " returned HTTP " + sc,
                            targetUri.toString(),
                            "Protected endpoints returning 401/403 indicate access control is functioning properly."
                    ));
                    break;
                }
            } catch (Exception ignored) {}
        }

        apiDetails.put("probedEndpoints", endpoints);
    }

    private void analyzeThirdPartyAndAds(String html, String pageUrl, List<Finding> findings, Map<String, Object> tpDetails) {
        Set<String> externalDomains = new HashSet<>();
        int analyticsCount = 0;
        int adCount = 0;
        int cdnCount = 0;

        Pattern srcPattern = Pattern.compile("(?i)(?:src|href)=[\"'](https?://[^/\"']+)");
        Matcher m = srcPattern.matcher(html);
        URI pageUri = URI.create(pageUrl);
        String host = pageUri.getHost();

        while (m.find()) {
            String domain = m.group(1);
            if (!domain.contains(host)) {
                externalDomains.add(domain);

                String lower = domain.toLowerCase();
                if (lower.contains("google-analytics") || lower.contains("googletagmanager") || lower.contains("segment") || lower.contains("mixpanel")) {
                    analyticsCount++;
                } else if (lower.contains("doubleclick") || lower.contains("googlesyndication") || lower.contains("adservice") || lower.contains("amazon-adsystem")) {
                    adCount++;
                } else if (lower.contains("cdnjs") || lower.contains("unpkg") || lower.contains("jsdelivr") || lower.contains("googleapis")) {
                    cdnCount++;
                }
            }
        }

        tpDetails.put("externalDomainsCount", externalDomains.size());
        tpDetails.put("externalDomainsList", new ArrayList<>(externalDomains));
        tpDetails.put("analyticsCount", analyticsCount);
        tpDetails.put("adCount", adCount);
        tpDetails.put("cdnCount", cdnCount);

        if (adCount > 0) {
            findings.add(new Finding(
                    "ADVERTISEMENT",
                    "INFO",
                    "Third-Party Advertisement Resources Detected",
                    "Identified " + adCount + " advertisement-related network resource(s). Note: VeloShield strictly analyzes resource footprints and load impact; no advertisements are clicked or manipulated.",
                    "Detected ad networks in page scripts/frames",
                    pageUrl,
                    "Ensure ad scripts do not introduce third-party vulnerabilities or degrade page rendering performance."
            ));
        }

        if (externalDomains.size() > 8) {
            findings.add(new Finding(
                    "THIRD_PARTY",
                    "LOW",
                    "High Third-Party Domain Dependency (" + externalDomains.size() + " domains)",
                    "Page references assets across " + externalDomains.size() + " unique external domains. Multiple DNS lookups and TLS handshakes can increase Page Load Time.",
                    "Referenced domains: " + externalDomains.size(),
                    pageUrl,
                    "Consider bundling critical assets or self-hosting external scripts where appropriate."
            ));
        }
    }

    private int countMatches(String str, String regex) {
        Matcher m = Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(str);
        int count = 0;
        while (m.find()) count++;
        return count;
    }
}
