// Single-service unified deployment:
// When served by the backend (localhost:8080 or Render), relative paths work seamlessly without CORS.
const API_BASE = (window.location.protocol === 'file:')
  ? 'http://localhost:8080'
  : '';
