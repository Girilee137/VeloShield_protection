package com.veloshield.model;

import java.time.Instant;

public class Finding {
    private int id;
    private int assessmentId;
    private String category;
    private String severity;
    private String title;
    private String description;
    private String evidence;
    private String affectedFileOrUrl;
    private String recommendation;
    private String status = "open";
    private String createdAt = Instant.now().toString();

    public Finding() {}

    public Finding(String category, String severity, String title, String description,
                   String evidence, String affectedFileOrUrl, String recommendation) {
        this.category = category;
        this.severity = severity;
        this.title = title;
        this.description = description;
        this.evidence = evidence;
        this.affectedFileOrUrl = affectedFileOrUrl;
        this.recommendation = recommendation;
    }

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public int getAssessmentId() { return assessmentId; }
    public void setAssessmentId(int assessmentId) { this.assessmentId = assessmentId; }

    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }

    public String getAffectedFileOrUrl() { return affectedFileOrUrl; }
    public void setAffectedFileOrUrl(String affectedFileOrUrl) { this.affectedFileOrUrl = affectedFileOrUrl; }

    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getCreatedAt() { return createdAt; }
    public void setCreatedAt(String createdAt) { this.createdAt = createdAt; }
}
