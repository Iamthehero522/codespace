// src/lib/api.ts

const API_BASE_URL = import.meta.env.VITE_API_URL ? `${import.meta.env.VITE_API_URL}/api` : 'http://localhost:7001/api';

class ApiClient {
  private getAuthHeaders() {
    const token = localStorage.getItem('token');
    return {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
  }

  private getAuthHeadersForFormData() {
    const token = localStorage.getItem('token');
    return {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
  }

  private async request(endpoint: string, options: RequestInit = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    const headers = this.getAuthHeaders();

    const response = await fetch(url, {
      ...options,
      headers: {
        ...headers,
        ...options.headers,
      },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Network error' }));
      throw new Error(error.error || error.message || `HTTP ${response.status}`);
    }

    return response.json();
  }

  // Auth endpoints
  async login(email: string, password: string, deviceId: string) {
    return this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, deviceId }),
    });
  }

  async register(name: string, email: string, password: string) {
    return this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password }),
    });
  }

  async logout() {
    return this.request('/auth/logout', {
      method: 'POST',
    });
  }

  async getCurrentUser() {
    return this.request('/auth/me');
  }

  // Project endpoints (ZIP uploads)
  async uploadProject(formData: FormData) {
    const url = `${API_BASE_URL}/projects/upload`;
    const headers = this.getAuthHeadersForFormData();

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: formData,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Network error' }));
      throw new Error(error.error || `HTTP ${response.status}`);
    }

    return response.json();
  }

  async getProjects(page = 1, limit = 20, search = '') {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
      ...(search && { search }),
    });
    return this.request(`/projects?${params}`);
  }

  async getProject(id: string) {
    return this.request(`/projects/${id}`);
  }

  async deleteProject(id: string) {
    return this.request(`/projects/${id}`, {
      method: 'DELETE',
    });
  }

  async getProjectFile(projectId: string, filePath: string) {
    return this.request(`/projects/${projectId}/files/${encodeURIComponent(filePath)}`);
  }

  async updateProjectFile(projectId: string, filePath: string, content: string) {
    return this.request(`/projects/${projectId}/files/${encodeURIComponent(filePath)}`, {
      method: 'PUT',
      body: JSON.stringify({ content }),
    });
  }

  // GitHub endpoints
  async getGitHubRepositories(token: string) {
    return this.request(`/github/repositories?token=${encodeURIComponent(token)}`);
  }

  async importGitHubRepository(data: {
    repoUrl: string;
    repoName: string;
    description?: string;
    githubToken: string;
    defaultBranch?: string;
  }) {
    return this.request('/github/import', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getGitHubProjects(page = 1, limit = 20, search = '') {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
      ...(search && { search }),
    });
    return this.request(`/github/projects?${params}`);
  }

  async getGitHubProject(id: string) {
    return this.request(`/github/projects/${id}`);
  }

  async deleteGitHubProject(id: string) {
    return this.request(`/github/projects/${id}`, {
      method: 'DELETE',
    });
  }

  async getGitHubProjectFile(projectId: string, filePath: string) {
    return this.request(`/github/projects/${projectId}/files/${encodeURIComponent(filePath)}`);
  }

  async updateGitHubProjectFile(projectId: string, filePath: string, content: string) {
    return this.request(`/github/projects/${projectId}/files/${encodeURIComponent(filePath)}`, {
      method: 'PUT',
      body: JSON.stringify({ content }),
    });
  }

  async commitGitHubChanges(data: {
    projectId: string;
    commitMessage: string;
    commitDescription?: string;
    changedFiles: Array<{
      filePath: string;
      content: string;
    }>;
  }) {
    return this.request(`/github/projects/${data.projectId}/commit`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // Share token methods
  async generateShareToken(fileId: string, permission: 'read' | 'write', expiresIn?: string) {
    return this.request('/share/generate', {
      method: 'POST',
      body: JSON.stringify({ fileId, permission, expiresIn }),
    });
  }

  async accessShareToken(token: string) {
    return this.request('/share/access', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  // Email sharing functionality
  async sendShareEmail(emailData: {
    recipientEmail: string;
    shareUrl: string;
    fileName: string;
    permission: 'read' | 'write';
    message?: string;
    expiresIn?: string;
  }) {
    return this.request('/codespace/share/send-email', {
      method: 'POST',
      body: JSON.stringify(emailData),
    });
  }

  // Document endpoints (now projects)
  async getDocuments(page = 1, limit = 20, search = '') {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
      ...(search && { search }),
    });
    return this.request(`/documents?${params}`);
  }

  async getDocument(id: string) {
    return this.request(`/documents/${id}`);
  }

  async createDocument(title?: string, content?: string) {
    return this.request('/documents', {
      method: 'POST',
      body: JSON.stringify({ title, content }),
    });
  }

  async updateDocument(id: string, title?: string, content?: string) {
    return this.request(`/documents/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ title, content }),
    });
  }

  async deleteDocument(id: string) {
    return this.request(`/documents/${id}`, {
      method: 'DELETE',
    });
  }

  async shareDocument(id: string, email: string, permission: 'read' | 'write') {
    return this.request(`/documents/${id}/share`, {
      method: 'POST',
      body: JSON.stringify({ email, permission }),
    });
  }

  async getDocumentVersions(id: string) {
    return this.request(`/documents/${id}/versions`);
  }

  // Code execution endpoint
  async runCode(code: string, language: string, input?: string) {
    return this.request('/code/run', {
      method: 'POST',
      body: JSON.stringify({ code, language, input }),
    });
  }

  // User profile endpoints (if needed)
  async getUserProfile() {
    return this.request('/users/profile');
  }

  async updateUserProfile(fullName?: string, avatarUrl?: string) {
    return this.request('/users/profile', {
      method: 'PUT',
      body: JSON.stringify({ fullName, avatarUrl }),
    });
  }

  async changePassword(currentPassword: string, newPassword: string) {
    return this.request('/users/password', {
      method: 'PUT',
      body: JSON.stringify({ currentPassword, newPassword }),
    });
  }

  async searchUsers(query: string) {
    return this.request(`/users/search?q=${encodeURIComponent(query)}`);
  }
}

export const apiClient = new ApiClient();