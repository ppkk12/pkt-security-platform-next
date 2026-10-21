export type FindingSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type FindingStatus = 'Open' | 'Triaged' | 'RiskAccepted' | 'FalsePositive' | 'Remediated';
export type FindingCategory = 'SAST' | 'SCA' | 'Secret' | 'IaC' | 'Container';
export type Reachability = 'DirectlyReachable' | 'IndirectlyReachable' | 'Unreachable' | 'Unknown';
export type ScanStatus = 'Queued' | 'Running' | 'Completed' | 'Failed' | 'Cancelled';
export type BusinessCriticality = 'Critical' | 'High' | 'Medium' | 'Low';
export type RemediationVerificationStatus = 'Unverified' | 'Verifying' | 'VerifiedFixed' | 'VerificationFailed' | 'Regressed';
export type RemediationApprovalStatus = 'PendingReview' | 'Approved' | 'Rejected';

export interface Project {
  id: string;
  tenantId: string;
  name: string;
  description: string;
  businessCriticality: BusinessCriticality;
  isInternetFacing: boolean;
  dataSensitivity: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateProjectRequest {
  name: string;
  description: string;
  businessCriticality: BusinessCriticality;
  isInternetFacing: boolean;
  dataSensitivity: string;
}

export interface StartScanRequest {
  scannerTypes?: string[];
  targetDirectory?: string;
  idempotencyKey?: string;
}

export interface ScanJobDto {
  id: string;
  scannerType: string;
  status: ScanStatus;
  leaseToken?: string;
  exitCode?: number;
  errorMessage?: string;
  createdAt: string;
  completedAt?: string;
}

export interface ScanDto {
  id: string;
  projectId: string;
  status: ScanStatus;
  triggerType: string;
  totalFindingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  jobs: ScanJobDto[];
  createdAt: string;
  completedAt?: string;
}

export interface FindingSummaryDto {
  id: string;
  projectId: string;
  title: string;
  severity: FindingSeverity;
  riskScore: number;
  status: FindingStatus;
  category: FindingCategory;
  scannerName: string;
  cweId?: string;
  cveId?: string;
  filePath?: string;
  startLine?: number;
  isKev: boolean;
  epssScore?: number;
  occurrenceCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface FindingEvidenceDto {
  id: string;
  codeSnippetRedacted?: string;
  codeFlowJson?: string;
  rawSarifResultJson?: string;
  createdAt: string;
}

export interface FindingStatusHistoryDto {
  id: string;
  fromStatus: FindingStatus;
  toStatus: FindingStatus;
  changedByUserId?: string;
  reason?: string;
  approvedByUserId?: string;
  createdAt: string;
}

export interface RiskAssessmentDto {
  id: string;
  finalScore: number;
  baseSeverityScore: number;
  threatScore: number;
  reachabilityScore: number;
  assetMultiplier: number;
  formulaVersion: string;
  cvssScore?: number;
  isKev?: boolean;
  epssScore?: number;
  reachability: Reachability;
  missingInputs: string[];
  calculatedAt: string;
}

export interface FindingDetailDto extends FindingSummaryDto {
  description: string;
  confidence: number;
  packagePurl?: string;
  installedVersion?: string;
  fixedVersion?: string;
  endLine?: number;
  enclosingSymbol?: string;
  reachability: Reachability;
  correlationGroupId?: string;
  primaryFingerprint: string;
  secondaryFingerprint: string;
  latestRiskAssessment?: RiskAssessmentDto;
  evidences: FindingEvidenceDto[];
  statusHistory: FindingStatusHistoryDto[];
}

export interface PagedResult<T> {
  items: T[];
  nextCursor?: string;
  hasMore: boolean;
  totalCount: number;
}

export interface TopRiskFindingDto {
  id: string;
  projectId: string;
  projectName: string;
  title: string;
  severity: FindingSeverity;
  riskScore: number;
  scannerName: string;
  ruleId?: string;
  cveId?: string;
  filePath?: string;
  startLine?: number;
  isKev: boolean;
  epssScore?: number;
  reachability: Reachability;
  status: FindingStatus;
  createdAt: string;
}

export interface DashboardSummaryDto {
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  kevCount: number;
  averageRiskScore: number;
  totalProjects: number;
  activeScansCount: number;
  topRiskFindings: TopRiskFindingDto[];
}

export interface RemediationDto {
  id: string;
  findingId: string;
  verifiedFacts: string[];
  aiHypothesisAnalysis: string;
  proposedUnifiedDiff: string;
  sideEffectsWarning: string;
  verificationStatus: RemediationVerificationStatus;
  verificationDetails?: string;
  approvalStatus: RemediationApprovalStatus;
  approvedByUserId?: string;
  approvedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface RemediationVerificationResultDto {
  remediationId: string;
  verificationStatus: RemediationVerificationStatus;
  details: string;
  durationMs: number;
}

export interface ProjectDependencyDto {
  id: string;
  packageName: string;
  version: string;
  packagePurl: string;
  isDirect: boolean;
  depth: number;
}

export interface VexStatementDto {
  id: string;
  projectId: string;
  vulnerabilityId: string;
  packagePurl?: string;
  status: string;
  justification?: string;
  impactStatement?: string;
  createdAt: string;
}

export interface SbomRescanResultDto {
  projectId: string;
  dependenciesCount: number;
  vulnerabilitiesFoundCount: number;
  suppressedByVexCount: number;
  durationMs: number;
}

export interface AuditVerificationResultDto {
  isValid: boolean;
  totalEvents: number;
  brokenEventId?: string;
  brokenReason?: string;
}
