export type CopilotCaseRole = 'read' | 'investigator';

type AuthorizationQueryError = {
  code?: string;
};

type CaseLookupResult = {
  data: { id: string } | null;
  error: AuthorizationQueryError | null;
};

type MembershipLookupResult = {
  data: { role: string } | null;
  error: AuthorizationQueryError | null;
};

export type CaseAuthorizationLookups = {
  findActiveCase: (caseNumber: string) => Promise<CaseLookupResult>;
  findActiveMembership: (caseId: string, userId: string) => Promise<MembershipLookupResult>;
};

export class CaseAuthorizationQueryError extends Error {
  constructor(stage: 'case' | 'membership', code?: string) {
    super('Case authorization could not be verified.');
    this.name = 'CaseAuthorizationQueryError';
    this.stage = stage;
    this.code = code;
  }

  stage: 'case' | 'membership';
  code?: string;
}

export type CaseAuthorizationResult =
  | { authorized: true; caseId: string; role: string }
  | { authorized: false; reason: 'case_unavailable' | 'insufficient_role' };

export async function authorizeCase(
  userId: string,
  caseNumber: string,
  requiredRole: CopilotCaseRole,
  lookups: CaseAuthorizationLookups,
): Promise<CaseAuthorizationResult> {
  const { data: caseRow, error: caseError } = await lookups.findActiveCase(caseNumber);
  if (caseError) throw new CaseAuthorizationQueryError('case', caseError.code);
  if (!caseRow) return { authorized: false, reason: 'case_unavailable' };

  const { data: membership, error: membershipError } = await lookups.findActiveMembership(caseRow.id, userId);
  if (membershipError) throw new CaseAuthorizationQueryError('membership', membershipError.code);
  if (!membership) return { authorized: false, reason: 'case_unavailable' };
  if (requiredRole === 'investigator' && !['admin', 'investigator'].includes(membership.role)) {
    return { authorized: false, reason: 'insufficient_role' };
  }
  return { authorized: true, caseId: caseRow.id, role: membership.role };
}
