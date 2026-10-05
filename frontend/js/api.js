const API = {
  async request(endpoint, options = {}) {
    options.credentials = 'include';
    options.headers = options.headers || {};
    if (!(options.body instanceof FormData) && options.body) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(options.body);
    }
    
    try {
      const response = await fetch(`${API_BASE}${endpoint}`, options);
      if (options.isCsv) {
        return await response.text();
      }
      
      const data = await response.json().catch(() => ({}));
      
      if (!response.ok) {
        throw new Error(data.message || data.error || 'API Request failed');
      }
      
      return data;
    } catch (error) {
      throw error;
    }
  },

  // Auth Endpoints
  async login(email, password) {
    return this.request('/api/auth/login', {
      method: 'POST',
      body: { email, password }
    });
  },

  async register(email, password) {
    return this.request('/api/auth/register', {
      method: 'POST',
      body: { email, password }
    });
  },

  async logout() {
    return this.request('/api/auth/logout', { method: 'POST' });
  },

  async me() {
    return this.request('/api/auth/me');
  },

  // Existing Target & Load Test Endpoints (Preserved)
  async getTargets() {
    return this.request('/api/targets');
  },

  async addTarget(url) {
    return this.request('/api/targets', {
      method: 'POST',
      body: { url }
    });
  },

  async deleteTarget(id) {
    return this.request(`/api/targets/${id}`, { method: 'DELETE' });
  },

  async verifyTarget(id) {
    return this.request(`/api/targets/${id}/verify`, { method: 'POST' });
  },

  async getTests() {
    return this.request('/api/tests');
  },

  async getTest(id) {
    return this.request(`/api/tests/${id}`);
  },

  async startTest(targetId, concurrency, durationSeconds, maxRequests) {
    return this.request('/api/tests', {
      method: 'POST',
      body: {
        targetId: parseInt(targetId),
        concurrency: parseInt(concurrency),
        durationSeconds: parseInt(durationSeconds),
        maxRequests: parseInt(maxRequests)
      }
    });
  },

  async getReport(id) {
    return this.request(`/api/tests/${id}/report`, { isCsv: true });
  },

  async getMitigation(id) {
    return this.request(`/api/mitigation/${id}`);
  },

  // New Workflow A: Before Deployment Endpoints
  async startPreDeploymentScan(projectName, files) {
    return this.request('/api/predeployment/scans', {
      method: 'POST',
      body: { projectName, files }
    });
  },

  async getPreDeploymentScan(id) {
    return this.request(`/api/predeployment/scans/${id}`);
  },

  async getPreDeploymentFindings(id) {
    return this.request(`/api/predeployment/scans/${id}/findings`);
  },

  async getPreDeploymentReport(id) {
    return this.request(`/api/predeployment/scans/${id}/report`, { isCsv: true });
  },

  // New Workflow B: After Deployment Endpoints
  async startPostDeploymentScan(targetUrl) {
    return this.request('/api/postdeployment/scans', {
      method: 'POST',
      body: { targetUrl }
    });
  },

  async getPostDeploymentScan(id) {
    return this.request(`/api/postdeployment/scans/${id}`);
  },

  async getPostDeploymentFindings(id) {
    return this.request(`/api/postdeployment/scans/${id}/findings`);
  },

  async getPostDeploymentSection(id, section) {
    return this.request(`/api/postdeployment/scans/${id}/${section}`);
  },

  async getPostDeploymentReport(id) {
    return this.request(`/api/postdeployment/scans/${id}/report`, { isCsv: true });
  },

  // Historical Assessments & Comparison Diff
  async getAssessments(type = '') {
    const query = type ? `?type=${encodeURIComponent(type)}` : '';
    return this.request(`/api/assessments${query}`);
  },

  async getAssessmentDiff(currentId, previousId) {
    return this.request(`/api/assessments/diff?current=${currentId}&previous=${previousId}`);
  },

  async deleteAssessment(id) {
    return this.request(`/api/assessments/${id}`, { method: 'DELETE' });
  }
};
