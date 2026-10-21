import {
  DashboardSummaryDto,
  Project,
  CreateProjectRequest,
  StartScanRequest,
  ScanDto,
  PagedResult,
  FindingSummaryDto,
  FindingDetailDto,
  FindingStatus,
  RemediationDto,
  RemediationVerificationResultDto,
  ProjectDependencyDto,
  VexStatementDto,
  SbomRescanResultDto,
  AuditVerificationResultDto
} from './types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';

class ApiClient {
  private token: string | null = null;

  constructor() {
    if (typeof window !== 'undefined') {
      this.token = localStorage.getItem('pkt_auth_token');
    }
  }

  setToken(token: string) {
    this.token = token;
    if (typeof window !== 'undefined') {
      localStorage.setItem('pkt_auth_token', token);
    }
  }

  getToken(): string | null {
    return this.token;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers = new Headers(options.headers || {});
    headers.set('Content-Type', 'application/json');

    if (this.token) {
      headers.set('Authorization', `Bearer ${this.token}`);
    }

    const url = `${API_BASE}${path}`;
    const res = await fetch(url, {
      ...options,
      headers,
    });

    if (!res.ok) {
      let errorDetail = `HTTP ${res.status} ${res.statusText}`;
      try {
        const errorJson = await res.json();
        errorDetail = errorJson.detail || errorJson.title || JSON.stringify(errorJson);
      } catch {
        // use fallback text
      }
      throw new Error(errorDetail);
    }

    if (res.status === 204) {
      return {} as T;
    }

    return (await res.json()) as T;
  }

  async login(email: string = 'admin@tenant-alpha.local', password: string = 'AdminPassword123!'): Promise<{ token: string; user: any; tenant: any }> {
    const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) {
      throw new Error(`Login failed: ${res.statusText}`);
    }

    const data = await res.json();
    this.setToken(data.token);
    return data;
  }

  // Dashboard
  async getDashboardSummary(): Promise<DashboardSummaryDto> {
    return this.request<DashboardSummaryDto>('/api/v1/dashboard/summary');
  }

  // Projects
  async getProjects(): Promise<Project[]> {
    return this.request<Project[]>('/api/v1/projects');
  }

  async getProject(id: string): Promise<Project> {
    return this.request<Project>(`/api/v1/projects/${id}`);
  }

  async createProject(data: CreateProjectRequest): Promise<Project> {
    return this.request<Project>('/api/v1/projects', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // Scans
  async startScan(projectId: string, data: StartScanRequest): Promise<ScanDto> {
    return this.request<ScanDto>(`/api/v1/projects/${projectId}/scans`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getScan(id: string): Promise<ScanDto> {
    return this.request<ScanDto>(`/api/v1/scans/${id}`);
  }

  async cancelScan(id: string): Promise<{ scanId: string; status: string; cancelledJobsCount: number }> {
    return this.request<{ scanId: string; status: string; cancelledJobsCount: number }>(`/api/v1/scans/${id}/cancel`, {
      method: 'POST',
    });
  }

  subscribeScanEvents(
    scanId: string,
    onProgress: (scan: ScanDto) => void,
    onComplete: (scan: ScanDto) => void,
    onError: (err: string) => void
  ): () => void {
    const controller = new AbortController();
    const url = `${API_BASE}/api/v1/scans/${scanId}/events`;

    const headers: Record<string, string> = {};
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    fetch(url, {
      headers,
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) {
          onError(`Failed to connect to SSE: ${response.statusText}`);
          return;
        }

        const reader = response.body?.getReader();
        if (!reader) {
          onError('Response body stream is not available');
          return;
        }

        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n\n');
          buffer = lines.pop() || '';

          for (const block of lines) {
            const eventMatch = block.match(/event:\s*([^\n]+)/);
            const dataMatch = block.match(/data:\s*([^\n]+)/);

            if (dataMatch) {
              const eventName = eventMatch ? eventMatch[1].trim() : 'scan.progress';
              try {
                const parsed = JSON.parse(dataMatch[1].trim()) as ScanDto;
                if (eventName === 'scan.completed' || eventName === 'scan.finished') {
                  onComplete(parsed);
                } else {
                  onProgress(parsed);
                }
              } catch (e) {
                console.error('Failed to parse SSE data', e);
              }
            }
          }
        }
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          onError(err.message || 'SSE connection error');
        }
      });

    return () => {
      controller.abort();
    };
  }

  // Findings
  async searchFindings(params: {
    projectId?: string;
    severity?: string;
    status?: string;
    category?: string;
    isKev?: boolean;
    keyword?: string;
    cursor?: string;
    limit?: number;
  }): Promise<PagedResult<FindingSummaryDto>> {
    const query = new URLSearchParams();
    if (params.projectId) query.set('ProjectId', params.projectId);
    if (params.severity) query.set('Severity', params.severity);
    if (params.status) query.set('Status', params.status);
    if (params.category) query.set('Category', params.category);
    if (params.isKev !== undefined) query.set('IsKev', String(params.isKev));
    if (params.keyword) query.set('Keyword', params.keyword);
    if (params.cursor) query.set('Cursor', params.cursor);
    if (params.limit) query.set('Limit', String(params.limit));

    return this.request<PagedResult<FindingSummaryDto>>(`/api/v1/findings?${query.toString()}`);
  }

  async getFinding(id: string): Promise<FindingDetailDto> {
    return this.request<FindingDetailDto>(`/api/v1/findings/${id}`);
  }

  async updateFindingStatus(id: string, status: FindingStatus, reason?: string): Promise<any> {
    return this.request(`/api/v1/findings/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, reason }),
    });
  }

  // Remediation
  async generateRemediation(findingId: string): Promise<RemediationDto> {
    return this.request<RemediationDto>(`/api/v1/findings/${findingId}/remediate`, {
      method: 'POST',
    });
  }

  async getRemediation(findingId: string): Promise<RemediationDto> {
    return this.request<RemediationDto>(`/api/v1/findings/${findingId}/remediation`);
  }

  async verifyRemediation(remediationId: string): Promise<RemediationVerificationResultDto> {
    return this.request<RemediationVerificationResultDto>(`/api/v1/remediations/${remediationId}/verify`, {
      method: 'POST',
    });
  }

  async approveRemediation(remediationId: string, reason?: string): Promise<RemediationDto> {
    return this.request<RemediationDto>(`/api/v1/remediations/${remediationId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  }

  async rejectRemediation(remediationId: string, reason: string): Promise<RemediationDto> {
    return this.request<RemediationDto>(`/api/v1/remediations/${remediationId}/reject`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  }

  // SBOM & VEX
  async getProjectDependencies(projectId: string): Promise<ProjectDependencyDto[]> {
    return this.request<ProjectDependencyDto[]>(`/api/v1/sbom/dependencies?projectId=${projectId}`);
  }

  async rescanSbom(projectId: string): Promise<SbomRescanResultDto> {
    return this.request<SbomRescanResultDto>(`/api/v1/sbom/rescan?projectId=${projectId}`, {
      method: 'POST',
    });
  }

  async getVexStatements(projectId: string): Promise<VexStatementDto[]> {
    return this.request<VexStatementDto[]>(`/api/v1/vex?projectId=${projectId}`);
  }

  async registerVexStatement(projectId: string, data: {
    vulnerabilityId: string;
    packagePurl?: string;
    status: string;
    justification?: string;
    impactStatement?: string;
  }): Promise<VexStatementDto> {
    return this.request<VexStatementDto>(`/api/v1/vex?projectId=${projectId}`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // Export
  getExportUrl(projectId: string, format: 'sarif' | 'cyclonedx' | 'meti' | 'csv' | 'json'): string {
    return `${API_BASE}/api/v1/projects/${projectId}/export?format=${format}`;
  }

  async downloadExport(projectId: string, format: 'sarif' | 'cyclonedx' | 'meti' | 'csv' | 'json'): Promise<Blob> {
    const headers: Record<string, string> = {};
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const res = await fetch(this.getExportUrl(projectId, format), { headers });
    if (!res.ok) {
      throw new Error(`Export download failed: ${res.statusText}`);
    }
    return res.blob();
  }

  // Audit
  async verifyAuditHashChain(): Promise<AuditVerificationResultDto> {
    return this.request<AuditVerificationResultDto>('/api/v1/audit-events/verify');
  }
}

export const api = new ApiClient();
