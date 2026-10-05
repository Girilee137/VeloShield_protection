package com.veloshield.service;

import com.veloshield.model.Finding;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ScoringEngine {

    /**
     * Calculates the Pre-Deployment Readiness Score (0-100) and component scores.
     */
    public static Map<String, Object> calculatePreDeploymentScore(List<Finding> findings) {
        int criticalCount = 0;
        int highCount = 0;
        int mediumCount = 0;
        int lowCount = 0;
        int infoCount = 0;
        int passCount = 0;

        int securityDeductions = 0;
        int configDeductions = 0;
        int depDeductions = 0;
        int projectDeductions = 0;

        for (Finding f : findings) {
            String sev = f.getSeverity();
            String cat = f.getCategory();

            int points = switch (sev) {
                case "CRITICAL" -> 25;
                case "HIGH" -> 15;
                case "MEDIUM" -> 8;
                case "LOW" -> 3;
                case "INFO" -> 0;
                default -> 0;
            };

            switch (sev) {
                case "CRITICAL" -> criticalCount++;
                case "HIGH" -> highCount++;
                case "MEDIUM" -> mediumCount++;
                case "LOW" -> lowCount++;
                case "INFO" -> infoCount++;
                case "PASS" -> passCount++;
            }

            switch (cat) {
                case "SECURITY", "AUTHENTICATION", "AUTHORIZATION" -> securityDeductions += points;
                case "CONFIGURATION", "CORS", "COOKIE", "HTTPS" -> configDeductions += points;
                case "DEPENDENCY" -> depDeductions += points;
                default -> projectDeductions += points;
            }
        }

        int securityScore = Math.max(0, 100 - securityDeductions);
        int configScore = Math.max(0, 100 - configDeductions);
        int depScore = Math.max(0, 100 - depDeductions);
        int projectScore = Math.max(0, 100 - projectDeductions);

        // Weighted overall score
        int overall = (int) Math.round(
                (securityScore * 0.35) +
                (configScore * 0.25) +
                (depScore * 0.20) +
                (projectScore * 0.20)
        );
        overall = Math.max(0, Math.min(100, overall));

        String status;
        String recommendation;
        if (criticalCount > 0 || highCount >= 3 || overall < 60) {
            status = "NOT READY FOR DEPLOYMENT";
            recommendation = "Critical or high-risk vulnerabilities detected. Block deployment until critical issues are addressed.";
        } else if (highCount > 0 || mediumCount >= 3 || overall < 85) {
            status = "READY WITH CHANGES";
            recommendation = "Review and address the High and Medium findings prior to production deployment.";
        } else {
            status = "READY FOR DEPLOYMENT";
            recommendation = "Project configurations and security posture meet readiness standards.";
        }

        Map<String, Object> result = new HashMap<>();
        result.put("overall", overall);
        result.put("security", securityScore);
        result.put("configuration", configScore);
        result.put("dependencies", depScore);
        result.put("project", projectScore);
        result.put("status", status);
        result.put("recommendation", recommendation);
        result.put("critical", criticalCount);
        result.put("high", highCount);
        result.put("medium", mediumCount);
        result.put("low", lowCount);
        result.put("info", infoCount);
        result.put("pass", passCount);

        return result;
    }

    /**
     * Calculates the Post-Deployment Health Score (0-100) and component scores.
     */
    public static Map<String, Object> calculatePostDeploymentScore(List<Finding> findings, double avgLatencyMs, double failureRate) {
        int criticalCount = 0;
        int highCount = 0;
        int mediumCount = 0;
        int lowCount = 0;
        int infoCount = 0;
        int passCount = 0;

        int secDeductions = 0;
        int apiDeductions = 0;
        int thirdPartyDeductions = 0;

        for (Finding f : findings) {
            String sev = f.getSeverity();
            String cat = f.getCategory();

            int points = switch (sev) {
                case "CRITICAL" -> 25;
                case "HIGH" -> 15;
                case "MEDIUM" -> 8;
                case "LOW" -> 3;
                default -> 0;
            };

            switch (sev) {
                case "CRITICAL" -> criticalCount++;
                case "HIGH" -> highCount++;
                case "MEDIUM" -> mediumCount++;
                case "LOW" -> lowCount++;
                case "INFO" -> infoCount++;
                case "PASS" -> passCount++;
            }

            switch (cat) {
                case "SECURITY", "HTTPS", "COOKIE", "CORS", "INFORMATION_EXPOSURE" -> secDeductions += points;
                case "API" -> apiDeductions += points;
                case "THIRD_PARTY", "ADVERTISEMENT" -> thirdPartyDeductions += points;
                default -> secDeductions += points / 2;
            }
        }

        int securityScore = Math.max(0, 100 - secDeductions);
        int apiHealthScore = Math.max(0, 100 - apiDeductions);

        // Performance Score based on Latency and Third Party Weight
        int perfScore = 100;
        if (avgLatencyMs > 3000) perfScore -= 45;
        else if (avgLatencyMs > 1500) perfScore -= 25;
        else if (avgLatencyMs > 800) perfScore -= 12;
        perfScore = Math.max(0, perfScore - thirdPartyDeductions);

        // Availability and Reliability Scores
        int availabilityScore = (int) Math.max(0, 100 - Math.round(failureRate * 2.5));
        int reliabilityScore = (int) Math.round((availabilityScore * 0.6) + (perfScore * 0.4));

        int overall = (int) Math.round(
                (securityScore * 0.35) +
                (perfScore * 0.25) +
                (availabilityScore * 0.15) +
                (apiHealthScore * 0.15) +
                (reliabilityScore * 0.10)
        );
        overall = Math.max(0, Math.min(100, overall));

        String status;
        if (overall >= 85 && criticalCount == 0 && highCount == 0) {
            status = "HEALTHY";
        } else if (overall >= 65 && criticalCount == 0) {
            status = "DEGRADED";
        } else {
            status = "CRITICAL / AT RISK";
        }

        Map<String, Object> result = new HashMap<>();
        result.put("overall", overall);
        result.put("security", securityScore);
        result.put("performance", perfScore);
        result.put("availability", availabilityScore);
        result.put("apiHealth", apiHealthScore);
        result.put("reliability", reliabilityScore);
        result.put("status", status);
        result.put("critical", criticalCount);
        result.put("high", highCount);
        result.put("medium", mediumCount);
        result.put("low", lowCount);
        result.put("info", infoCount);
        result.put("pass", passCount);

        return result;
    }
}
