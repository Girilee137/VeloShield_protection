package com.veloshield.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public class Assessment {
    private int id;
    private int userId;
    private String assessmentType; // BEFORE_DEPLOYMENT or AFTER_DEPLOYMENT
    private String targetRef;
    private String status = "pending"; // pending, running, completed, failed
    private String scoresJson = "{}";
    private String metricsJson = "{}";
    private String startedAt = Instant.now().toString();
    private String finishedAt;

    private Map<String, Object> scores;
    private Map<String, Object> metrics;
    private List<Finding> findings;

    public Assessment() {}

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public int getUserId() { return userId; }
    public void setUserId(int userId) { this.userId = userId; }

    public String getAssessmentType() { return assessmentType; }
    public void setAssessmentType(String assessmentType) { this.assessmentType = assessmentType; }

    public String getTargetRef() { return targetRef; }
    public void setTargetRef(String targetRef) { this.targetRef = targetRef; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getScoresJson() { return scoresJson; }
    public void setScoresJson(String scoresJson) { this.scoresJson = scoresJson; }

    public String getMetricsJson() { return metricsJson; }
    public void setMetricsJson(String metricsJson) { this.metricsJson = metricsJson; }

    public String getStartedAt() { return startedAt; }
    public void setStartedAt(String startedAt) { this.startedAt = startedAt; }

    public String getFinishedAt() { return finishedAt; }
    public void setFinishedAt(String finishedAt) { this.finishedAt = finishedAt; }

    public Map<String, Object> getScores() { return scores; }
    public void setScores(Map<String, Object> scores) { this.scores = scores; }

    public Map<String, Object> getMetrics() { return metrics; }
    public void setMetrics(Map<String, Object> metrics) { this.metrics = metrics; }

    public List<Finding> getFindings() { return findings; }
    public void setFindings(List<Finding> findings) { this.findings = findings; }
}
