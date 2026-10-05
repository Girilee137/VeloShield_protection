package com.veloshield.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.veloshield.model.Finding;
import com.veloshield.util.JsonUtil;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PreDeploymentScanService {

    private static final ObjectMapper mapper = JsonUtil.getMapper();

    public static class ProjectFile {
        private String path;
        private String content;

        public ProjectFile() {}
        public ProjectFile(String path, String content) {
            this.path = path;
            this.content = content;
        }

        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        public String getContent() { return content; }
        public void setContent(String content) { this.content = content; }
    }

    public static class ScanOutput {
        public List<Finding> findings = new ArrayList<>();
        public Map<String, Object> scores = new HashMap<>();
        public Map<String, Object> metrics = new HashMap<>();
    }

    // Common secret patterns
    private static final Pattern AWS_KEY_PATTERN = Pattern.compile("(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}");
    private static final Pattern PRIVATE_KEY_PATTERN = Pattern.compile("-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----");
    private static final Pattern GENERIC_SECRET_PATTERN = Pattern.compile("(?i)(api[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|password|passwd|db_pass)\\s*[:=]\\s*['\"]([^'\"]{6,})['\"]");
    private static final Pattern JWT_PATTERN = Pattern.compile("ey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*");
    private static final Pattern DB_CONN_SECRET = Pattern.compile("(?i)(?:postgres|postgresql|mysql|mongodb(?:\\+srv)?):\\/\\/[^:\\s]+:([^@\\s]{4,})@");

    public ScanOutput analyze(String projectName, List<ProjectFile> files) {
        ScanOutput output = new ScanOutput();
        List<Finding> findings = output.findings;

        int filesAnalyzed = files.size();
        int secretsFound = 0;
        int dependenciesScanned = 0;
        int configsChecked = 0;
        int apiRoutesFound = 0;

        for (ProjectFile file : files) {
            String path = file.getPath() != null ? file.getPath() : "unknown";
            String content = file.getContent() != null ? file.getContent() : "";

            // 1. Secret Scanning
            secretsFound += scanSecrets(path, content, findings);

            // 2. Dependency Analysis
            dependenciesScanned += scanDependencies(path, content, findings);

            // 3. Security Configuration
            configsChecked += scanConfigurations(path, content, findings);

            // 4. API Analysis
            apiRoutesFound += scanApis(path, content, findings);

            // 5. Error Handling Analysis
            scanErrorHandling(path, content, findings);

            // 6. Frontend Analysis
            scanFrontend(path, content, findings);

            // 7. Deployment Configuration
            scanDeploymentConfig(path, content, findings);
        }

        // Add PASS findings if categories are clean
        addPassFindingsIfClean(findings);

        // Calculate Scores
        output.scores = ScoringEngine.calculatePreDeploymentScore(findings);

        output.metrics.put("filesAnalyzed", filesAnalyzed);
        output.metrics.put("secretsFound", secretsFound);
        output.metrics.put("dependenciesScanned", dependenciesScanned);
        output.metrics.put("configsChecked", configsChecked);
        output.metrics.put("apiRoutesFound", apiRoutesFound);
        output.metrics.put("projectName", projectName);

        return output;
    }

    private int scanSecrets(String path, String content, List<Finding> findings) {
        int count = 0;

        // AWS Key
        Matcher m1 = AWS_KEY_PATTERN.matcher(content);
        if (m1.find()) {
            count++;
            findings.add(new Finding(
                    "SECURITY",
                    "CRITICAL",
                    "Hardcoded AWS Access Key Detected",
                    "WHAT IS WRONG: An AWS access key identifier was discovered directly hardcoded within project source files.\n" +
                    "WHY IT MATTERS: Exposing cloud credentials allows unauthorized parties to compromise infrastructure, access databases, and provision billable resources.\n" +
                    "EVIDENCE: Matched AWS Access Key pattern in file: " + path + " (Value: " + maskSecret(m1.group(0)) + ").\n" +
                    "HOW TO FIX IT: Revoke this credential immediately in AWS IAM. Extract keys into environment variables or use IAM roles / Secrets Manager.",
                    "File: " + path + " | Pattern: AWS Key ID (Masked: " + maskSecret(m1.group(0)) + ")",
                    path,
                    "Revoke key immediately and migrate to IAM roles or environment variables."
            ));
        }

        // Private Key
        if (PRIVATE_KEY_PATTERN.matcher(content).find()) {
            count++;
            findings.add(new Finding(
                    "SECURITY",
                    "CRITICAL",
                    "Hardcoded Private Key Detected",
                    "WHAT IS WRONG: An unencrypted cryptographic private key block was found in the project repository.\n" +
                    "WHY IT MATTERS: Private keys allow attackers to decrypt traffic, forge cryptographic tokens, or access servers via SSH.\n" +
                    "EVIDENCE: -----BEGIN PRIVATE KEY----- block found in " + path + ".\n" +
                    "HOW TO FIX IT: Remove the private key from git history, rotate the keypair, and load certificates via secure key stores.",
                    "File: " + path + " | Found raw private key header",
                    path,
                    "Remove private key from source control and inject securely at runtime."
            ));
        }

        // Database connection URL with embedded password
        Matcher mDb = DB_CONN_SECRET.matcher(content);
        if (mDb.find()) {
            count++;
            findings.add(new Finding(
                    "SECURITY",
                    "HIGH",
                    "Hardcoded Database Credentials in Connection String",
                    "WHAT IS WRONG: Database credentials (username & password) are embedded in a connection URL within source code.\n" +
                    "WHY IT MATTERS: Anyone with repository access can directly connect to and compromise the application database.\n" +
                    "EVIDENCE: Database URL with password found in " + path + " (Password masked: " + maskSecret(mDb.group(1)) + ").\n" +
                    "HOW TO FIX IT: Supply DATABASE_URL via runtime environment variables (e.g., .env or hosting provider config).",
                    "File: " + path + " | DB Password masked: " + maskSecret(mDb.group(1)),
                    path,
                    "Move database URL and password to environment variables."
            ));
        }

        // Generic API Key / Secret / Password assignment
        Matcher mGen = GENERIC_SECRET_PATTERN.matcher(content);
        while (mGen.find()) {
            String keyName = mGen.group(1);
            String rawVal = mGen.group(2);

            // Avoid flagging dummy examples or environment lookup defaults
            if (isPlaceholder(rawVal)) continue;

            count++;
            findings.add(new Finding(
                    "SECURITY",
                    "HIGH",
                    "Potential Hardcoded Secret Detected (" + keyName + ")",
                    "WHAT IS WRONG: Potential secret or authentication token assigned as a literal string in code.\n" +
                    "WHY IT MATTERS: Hardcoded credentials expose APIs, accounts, or encryption routines to code auditors and threat actors.\n" +
                    "EVIDENCE: Assignment to '" + keyName + "' in " + path + " (Value: " + maskSecret(rawVal) + ").\n" +
                    "HOW TO FIX IT: Replace literal assignment with System.getenv(\"" + keyName.toUpperCase() + "\") or process.env." + keyName.toUpperCase() + ".",
                    "File: " + path + " | Key: " + keyName + " = " + maskSecret(rawVal),
                    path,
                    "Store secret in environment variables or key vault."
            ));
            break; // limit to 1 per file to avoid noise
        }

        return count;
    }

    private int scanDependencies(String path, String content, List<Finding> findings) {
        int count = 0;
        String lower = path.toLowerCase();

        // npm package.json
        if (lower.endsWith("package.json")) {
            try {
                JsonNode root = mapper.readTree(content);
                JsonNode deps = root.path("dependencies");
                JsonNode devDeps = root.path("devDependencies");

                Map<String, String> allDeps = new HashMap<>();
                if (deps.isObject()) deps.fields().forEachRemaining(e -> allDeps.put(e.getKey(), e.getValue().asText()));
                if (devDeps.isObject()) devDeps.fields().forEachRemaining(e -> allDeps.put(e.getKey(), e.getValue().asText()));

                count += allDeps.size();
                for (Map.Entry<String, String> entry : allDeps.entrySet()) {
                    String pkg = entry.getKey();
                    String ver = entry.getValue();

                    checkKnownVulnerabilities(pkg, ver, "npm", path, findings);
                }
            } catch (Exception ignored) {}
        }

        // Maven pom.xml
        if (lower.endsWith("pom.xml")) {
            Pattern depPattern = Pattern.compile("<groupId>([^<]+)</groupId>\\s*<artifactId>([^<]+)</artifactId>(?:\\s*<version>([^<]+)</version>)?");
            Matcher m = depPattern.matcher(content);
            while (m.find()) {
                count++;
                String gid = m.group(1).trim();
                String aid = m.group(2).trim();
                String ver = m.group(3) != null ? m.group(3).trim() : "unspecified";
                checkKnownVulnerabilities(gid + ":" + aid, ver, "Maven", path, findings);
            }
        }

        // Python requirements.txt
        if (lower.endsWith("requirements.txt")) {
            String[] lines = content.split("\\r?\\n");
            for (String line : lines) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                count++;
                String[] parts = line.split("==|>=|<=|~=");
                String name = parts[0].trim();
                String ver = parts.length > 1 ? parts[1].trim() : "any";
                checkKnownVulnerabilities(name, ver, "PyPI", path, findings);
            }
        }

        // Flutter/Dart pubspec.yaml
        if (lower.endsWith("pubspec.yaml")) {
            String[] lines = content.split("\\r?\\n");
            boolean inDeps = false;
            for (String line : lines) {
                if (line.startsWith("dependencies:") || line.startsWith("dev_dependencies:")) {
                    inDeps = true;
                    continue;
                }
                if (inDeps && line.matches("^[a-zA-Z].*")) {
                    inDeps = false;
                }
                if (inDeps && line.startsWith("  ") && line.contains(":")) {
                    count++;
                    String[] parts = line.trim().split(":", 2);
                    String pkg = parts[0].trim();
                    String ver = parts.length > 1 ? parts[1].trim() : "any";
                    checkKnownVulnerabilities(pkg, ver, "Pub", path, findings);
                }
            }
        }

        return count;
    }

    private void checkKnownVulnerabilities(String name, String version, String ecosystem, String file, List<Finding> findings) {
        String lowerName = name.toLowerCase();

        // Curated known vulnerable dependency checks
        if (lowerName.contains("log4j-core") && version.contains("2.14")) {
            findings.add(new Finding(
                    "DEPENDENCY",
                    "CRITICAL",
                    "Critical Log4j Vulnerability (Log4Shell CVE-2021-44228)",
                    "WHAT IS WRONG: Dependency log4j-core version " + version + " is vulnerable to Remote Code Execution via JNDI lookup injection.\n" +
                    "WHY IT MATTERS: Allows unauthenticated attackers to execute arbitrary system commands on the server.\n" +
                    "EVIDENCE: Found " + name + ":" + version + " in " + file + ".\n" +
                    "HOW TO FIX IT: Upgrade log4j-core to 2.17.1 or higher immediately.",
                    "Package: " + name + " | Version: " + version + " | Ecosystem: " + ecosystem,
                    file,
                    "Upgrade log4j-core to version 2.17.1 or later."
            ));
        } else if (lowerName.equals("axios") && (version.contains("0.18.") || version.contains("0.19."))) {
            findings.add(new Finding(
                    "DEPENDENCY",
                    "MEDIUM",
                    "Known SSRF Vulnerability in Axios (" + version + ")",
                    "WHAT IS WRONG: Axios versions < 0.21.1 contain an SSRF vulnerability when handling relative paths on redirects.\n" +
                    "WHY IT MATTERS: Attackers can cause the client to follow unauthorized internal redirect paths.\n" +
                    "EVIDENCE: Found " + name + " version " + version + " in " + file + ".\n" +
                    "HOW TO FIX IT: Upgrade axios to ^1.7.0 or latest.",
                    "Package: " + name + " | Version: " + version + " | Ecosystem: " + ecosystem,
                    file,
                    "Update axios to the latest stable release."
            ));
        } else if (lowerName.equals("lodash") && (version.contains("4.17.15") || version.contains("4.17.11"))) {
            findings.add(new Finding(
                    "DEPENDENCY",
                    "HIGH",
                    "Prototype Pollution in Lodash (" + version + ")",
                    "WHAT IS WRONG: Lodash versions < 4.17.21 are vulnerable to Prototype Pollution via defaultsDeep.\n" +
                    "WHY IT MATTERS: Can lead to Remote Code Execution or denial of service.\n" +
                    "EVIDENCE: Found " + name + " version " + version + " in " + file + ".\n" +
                    "HOW TO FIX IT: Upgrade lodash to 4.17.21 or above.",
                    "Package: " + name + " | Version: " + version + " | Ecosystem: " + ecosystem,
                    file,
                    "Upgrade lodash to 4.17.21 or later."
            ));
        }
    }

    private int scanConfigurations(String path, String content, List<Finding> findings) {
        int checks = 0;

        // Debug mode enabled
        if (content.contains("DEBUG = True") || content.contains("debug: true") || content.contains("\"debug\": true") || content.contains("debug=true")) {
            checks++;
            findings.add(new Finding(
                    "CONFIGURATION",
                    "HIGH",
                    "Debug Mode Enabled in Configuration",
                    "WHAT IS WRONG: Debug mode is explicitly enabled in application configuration.\n" +
                    "WHY IT MATTERS: Debug mode often enables interactive debuggers, verbose error pages with stack traces, and unauthenticated endpoints in production.\n" +
                    "EVIDENCE: Found debug=true / DEBUG=True setting in " + path + ".\n" +
                    "HOW TO FIX IT: Ensure debug mode is toggled off for production environments via environment variables.",
                    "File: " + path + " | Setting: debug=true",
                    path,
                    "Set debug: false or disable debug mode in production."
            ));
        }

        // Wildcard CORS with credentials
        if (content.contains("Access-Control-Allow-Origin") && (content.contains("'*'") || content.contains("\"*\"")) && content.contains("Access-Control-Allow-Credentials")) {
            checks++;
            findings.add(new Finding(
                    "CORS",
                    "HIGH",
                    "Unsafe CORS Wildcard Origin Configuration",
                    "WHAT IS WRONG: Overly permissive CORS header allows '*' origin while handling credentials.\n" +
                    "WHY IT MATTERS: Malicious third-party sites could execute authenticated cross-origin requests on behalf of users.\n" +
                    "EVIDENCE: Found Access-Control-Allow-Origin: '*' configured alongside credentials in " + path + ".\n" +
                    "HOW TO FIX IT: Restrict allowed origins to specific, trusted frontend domains.",
                    "File: " + path + " | Access-Control-Allow-Origin: *",
                    path,
                    "Whitelist specific trusted domains instead of using wildcard '*'."
            ));
        }

        // Insecure cookies (missing Secure or HttpOnly)
        if (content.contains("httpOnly: false") || content.contains("secure: false") || content.contains("cookie.setSecure(false)")) {
            checks++;
            findings.add(new Finding(
                    "COOKIE",
                    "MEDIUM",
                    "Insecure Cookie Flag Configuration",
                    "WHAT IS WRONG: Session or authentication cookies are explicitly configured with Secure: false or HttpOnly: false.\n" +
                    "WHY IT MATTERS: Cookies transmitted without Secure can be intercepted over unencrypted channels, and non-HttpOnly cookies can be stolen via XSS.\n" +
                    "EVIDENCE: Insecure cookie attributes configured in " + path + ".\n" +
                    "HOW TO FIX IT: Enable HttpOnly=true, Secure=true, and SameSite=Lax/Strict on all sensitive cookies.",
                    "File: " + path + " | Insecure cookie attribute detected",
                    path,
                    "Set HttpOnly=true and Secure=true on sensitive cookies."
            ));
        }

        return checks;
    }

    private int scanApis(String path, String content, List<Finding> findings) {
        int count = 0;
        Pattern routePattern = Pattern.compile("(?i)(?:@(?:Get|Post|Put|Delete)Mapping|app\\.(?:get|post|put|delete)|router\\.(?:get|post|put|delete))\\s*\\(\\s*[\"'](/[^\"']+)[\"']");
        Matcher m = routePattern.matcher(content);

        while (m.find()) {
            count++;
            String endpoint = m.group(1);
            if (endpoint.startsWith("/admin") || endpoint.contains("/manage") || endpoint.contains("/internal")) {
                if (!content.contains("requireAuth") && !content.contains("hasRole") && !content.contains("isAuthenticated") && !content.contains("authMiddleware")) {
                    findings.add(new Finding(
                            "AUTHORIZATION",
                            "HIGH",
                            "Potentially Unprotected Administrative Route (" + endpoint + ")",
                            "WHAT IS WRONG: Administrative route '" + endpoint + "' defined without explicit access control or authentication middleware in view.\n" +
                            "WHY IT MATTERS: Unauthenticated users might access administrative controls or sensitive data.\n" +
                            "EVIDENCE: Route: " + endpoint + " in " + path + ".\n" +
                            "HOW TO FIX IT: Ensure authentication and role-based access checks (RBAC) are strictly enforced before processing requests.",
                            "File: " + path + " | Endpoint: " + endpoint,
                            path,
                            "Enforce authentication and role checks on administrative routes."
                    ));
                }
            }
        }
        return count;
    }

    private void scanErrorHandling(String path, String content, List<Finding> findings) {
        // e.printStackTrace() in Java
        if (content.contains("e.printStackTrace()")) {
            findings.add(new Finding(
                    "INFORMATION_EXPOSURE",
                    "LOW",
                    "Raw Stack Trace Logging via printStackTrace()",
                    "WHAT IS WRONG: Direct invocation of e.printStackTrace() prints full system call stacks to standard error.\n" +
                    "WHY IT MATTERS: Stack traces can reveal internal library versions, file paths, and database query structures.\n" +
                    "EVIDENCE: Call to e.printStackTrace() in " + path + ".\n" +
                    "HOW TO FIX IT: Use a structured logging framework (SLF4J, Logback) and avoid printing raw exceptions to user responses.",
                    "File: " + path + " | Call: e.printStackTrace()",
                    path,
                    "Replace printStackTrace() with a structured logger."
            ));
        }

        // Database error string returned directly to HTTP response
        if (content.contains("resp.getWriter().write(\"error: \" + e.getMessage())") || content.contains("res.send(err.message)")) {
            findings.add(new Finding(
                    "INFORMATION_EXPOSURE",
                    "MEDIUM",
                    "Raw Exception Message Exposed in Response",
                    "WHAT IS WRONG: Internal exception message is reflected directly back to the HTTP client.\n" +
                    "WHY IT MATTERS: SQL syntax errors or database table names can leak database internals to potential attackers.\n" +
                    "EVIDENCE: Exception message concatenated into response in " + path + ".\n" +
                    "HOW TO FIX IT: Return generic error messages to clients (e.g., 'An internal error occurred') and log technical details internally.",
                    "File: " + path + " | Direct exception message response",
                    path,
                    "Return sanitized error messages and log raw errors server-side."
            ));
        }
    }

    private void scanFrontend(String path, String content, List<Finding> findings) {
        String lower = path.toLowerCase();
        if (lower.endsWith(".html") || lower.endsWith(".js") || lower.endsWith(".jsx")) {
            // Unencrypted HTTP script tag
            if (content.contains("<script src=\"http://")) {
                findings.add(new Finding(
                        "SECURITY",
                        "MEDIUM",
                        "External Script Loaded Over Insecure HTTP",
                        "WHAT IS WRONG: External JavaScript asset is loaded via unencrypted http:// protocol.\n" +
                        "WHY IT MATTERS: Attackers can execute Man-in-the-Middle (MitM) attacks to tamper with script content and execute malicious code.\n" +
                        "EVIDENCE: Insecure script tag found in " + path + ".\n" +
                        "HOW TO FIX IT: Change script source URL to use https:// exclusively.",
                        "File: " + path + " | <script src=\"http://...\">",
                        path,
                        "Upgrade script reference to https://."
                ));
            }

            // Dangerous innerHTML / eval
            if (content.contains(".innerHTML =") && content.contains("+")) {
                findings.add(new Finding(
                        "SECURITY",
                        "MEDIUM",
                        "Potential DOM Cross-Site Scripting (DOM XSS)",
                        "WHAT IS WRONG: Dynamic string concatenation assigned directly to innerHTML property.\n" +
                        "WHY IT MATTERS: If untrusted input is included without HTML escaping, attackers can execute arbitrary JavaScript in the victim's browser.\n" +
                        "EVIDENCE: Dynamic innerHTML assignment in " + path + ".\n" +
                        "HOW TO FIX IT: Use textContent, DOM manipulation methods, or an HTML sanitization library (DOMPurify).",
                        "File: " + path + " | innerHTML concatenation",
                        path,
                        "Use textContent or sanitize dynamic values before inserting into DOM."
                ));
            }
        }
    }

    private void scanDeploymentConfig(String path, String content, List<Finding> findings) {
        String lower = path.toLowerCase();
        if (lower.endsWith(".env") && !lower.endsWith(".example")) {
            findings.add(new Finding(
                    "CONFIGURATION",
                    "HIGH",
                    "Committed Production Environment File (.env)",
                    "WHAT IS WRONG: Environment file containing potentially active configuration was committed to source.\n" +
                    "WHY IT MATTERS: .env files often contain production secrets, database credentials, and third-party tokens.\n" +
                    "EVIDENCE: Found file: " + path + ".\n" +
                    "HOW TO FIX IT: Add .env to .gitignore and distribute .env.example with placeholders only.",
                    "File: " + path,
                    path,
                    "Add .env to .gitignore and remove it from version control."
            ));
        }
    }

    private void addPassFindingsIfClean(List<Finding> findings) {
        boolean hasCritical = findings.stream().anyMatch(f -> "CRITICAL".equals(f.getSeverity()));
        if (!hasCritical) {
            findings.add(new Finding(
                    "SECURITY",
                    "PASS",
                    "No Critical Hardcoded Cloud Credentials Detected",
                    "Project passed baseline automated secret scanning for root credentials.",
                    "Verified 0 critical credential exposures.",
                    "All scanned files",
                    "Maintain secure key management and environment variable separation."
            ));
        }

        boolean hasConfigIssue = findings.stream().anyMatch(f -> "CONFIGURATION".equals(f.getCategory()) && ("HIGH".equals(f.getSeverity()) || "CRITICAL".equals(f.getSeverity())));
        if (!hasConfigIssue) {
            findings.add(new Finding(
                    "CONFIGURATION",
                    "PASS",
                    "Production Configuration Baseline Verified",
                    "No production debug flags or committed sensitive env files detected.",
                    "Configuration checks completed.",
                    "Configuration files",
                    "Keep production configs isolated from developer environments."
            ));
        }
    }

    private static String maskSecret(String secret) {
        if (secret == null || secret.length() <= 4) return "********";
        int len = secret.length();
        int visible = Math.min(2, len / 4);
        return secret.substring(0, visible) + "*".repeat(len - (visible * 2)) + secret.substring(len - visible);
    }

    private static boolean isPlaceholder(String val) {
        if (val == null) return true;
        String lower = val.toLowerCase().trim();
        return lower.contains("placeholder") || lower.contains("your_") || lower.contains("changeme") ||
                lower.contains("example") || lower.contains("secret_here") || lower.contains("todo") ||
                lower.equals("password") || lower.equals("admin") || lower.equals("test");
    }
}
