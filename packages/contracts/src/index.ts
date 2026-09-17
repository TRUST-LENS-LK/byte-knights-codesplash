import { z } from "zod";

// ============================================================================
// Member 3: Contract versioning and canonical signal taxonomy
// ============================================================================

// Bump this whenever a shape in this file changes in a way that existing
// consumers need to know about, such as a field being renamed, removed, or
// made required. Attach it to persisted records so old data can be told apart
// from new data if the shape ever changes.
export const CONTRACT_VERSION = "1.0.0";

// The canonical signal taxonomy is the fixed list of names a Finding is
// allowed to use in canonicalSignal. Every reason shown to a user must trace
// back to one of these, so the explanation on screen always matches something
// the decision engine actually used. Add new signals here first, then
// reference them from rule or detector code, rather than inventing a new
// string inside a detector.
//
// This list is not enforced as a strict validation constraint yet, see the
// open decision in docs/decisions.md. Other members are still adding
// detectors, and a strict enum would block their work until every signal is
// catalogued here. Treat this as the shared source of truth to add to, not a
// hard runtime check, until the team agrees to tighten it.
export const CANONICAL_SIGNALS = [
  // Deterministic message rules (packages/rules)
  "credential_request",
  "advance_payment",
  "urgency",
  "job_offer",

  // Domain verification (services/api/src/services/domainVerification.mjs)
  "approved_domain",
  "domain_mismatch",
  "domain_unknown",
  "domain_stale",

  // Verified intelligence (Member 5, supabase verified_intelligence table)
  "confirmed_scam_indicator",
  "verified_safe_indicator",
] as const;

export type CanonicalSignal = (typeof CANONICAL_SIGNALS)[number];

export const submissionSchema = z.object({
  type: z.enum(["message", "url", "screenshot"]),
  text: z.string().max(10000).optional(),
  languageHint: z
    .enum(["en", "si", "singlish", "mixed"])
    .optional(),
  retentionConsent: z.boolean().default(false),
});

export const extractedEntitySchema = z.object({
  type: z.enum([
    "url",
    "domain",
    "phone",
    "email",
    "amount",
    "organization",
  ]),
  value: z.string(),
  normalizedValue: z.string().optional(),
  sourceSpan: z.string().optional(),
  confidence: z.number().min(0).max(1).optional(),
});

export const findingSchema = z.object({
  canonicalSignal: z.string(),
  category: z.string(),
  evidence: z.string(),
  source: z.enum([
    "RULE",
    "LLM",
    "DOMAIN_DIRECTORY",
    "SCANNER",
    "APPROVED_REPORT",
  ]),
  strength: z.number().min(0).max(1),
  confidence: z.number().min(0).max(1).optional(),
  limitation: z.string().optional(),
});

export const riskDecisionSchema = z.object({
  riskBand: z.enum(["LOW", "MEDIUM", "HIGH", "UNKNOWN"]),
  recommendation: z.enum([
    "PROCEED_CAUTIOUSLY",
    "VERIFY_INDEPENDENTLY",
    "STOP_AND_AVOID",
    "UNABLE_TO_VERIFY",
  ]),
  findings: z.array(findingSchema),
  limitations: z.array(z.string()),
  safeActions: z.array(z.string()),
  policyVersion: z.string(),
});

export const apiErrorSchema = z.object({
  code: z.string(),
  message: z.string(),
  requestId: z.string().optional(),
});

export type Submission = z.infer<typeof submissionSchema>;
export type ExtractedEntity = z.infer<typeof extractedEntitySchema>;
export type Finding = z.infer<typeof findingSchema>;
export type RiskDecision = z.infer<typeof riskDecisionSchema>;
export type ApiError = z.infer<typeof apiErrorSchema>;

// ============================================================================
// Member 5: User Reporting, Moderation & Verified Intelligence Contracts
// ============================================================================

export const userReportTypeSchema = z.enum([
  "suspicious",
  "false_positive",
  "false_negative",
]);

export const userReportStatusSchema = z.enum([
  "PENDING",
  "REVIEWED",
  "REJECTED",
  "APPROVED",
  "RETIRED",
]);

export const createUserReportSchema = z.object({
  reportType: userReportTypeSchema,
  contentSha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/i, "contentSha256 must be a 64-character hex string"),
  reportedDomain: z.string().max(255).optional().nullable(),
  notes: z.string().max(2000).optional().nullable(),
  submissionId: z.string().uuid().optional().nullable(),
  rawExcerpt: z.string().max(500).optional().nullable(),
});

export const userReportSchema = z.object({
  id: z.string().uuid(),
  reportType: userReportTypeSchema,
  contentSha256: z.string(),
  reportedDomain: z.string().nullable().optional(),
  notes: z.string().nullable().optional(),
  status: userReportStatusSchema,
  createdAt: z.string(),
  reviewedAt: z.string().nullable().optional(),
});

export const moderationActionSchema = z.object({
  reportId: z.string().uuid(),
  action: z.enum(["APPROVE", "REJECT", "RETIRE"]),
  notes: z.string().max(1000).optional().nullable(),
  indicatorType: z.enum(["domain", "content_hash", "phone", "url"]).optional(),
  category: z.string().max(100).optional().nullable(),
});

export const verifiedIntelligenceSchema = z.object({
  id: z.string().uuid(),
  sourceReportId: z.string().uuid().nullable().optional(),
  indicatorType: z.enum(["domain", "content_hash", "phone", "url"]),
  indicatorValue: z.string(),
  defangedValue: z.string(),
  riskLevel: z.enum(["CONFIRMED_SCAM", "VERIFIED_SAFE"]),
  category: z.string().nullable().optional(),
  confidence: z.number().min(0).max(1).default(1.0),
  notes: z.string().nullable().optional(),
  active: z.boolean().default(true),
  createdAt: z.string(),
});

export type UserReportType = z.infer<typeof userReportTypeSchema>;
export type UserReportStatus = z.infer<typeof userReportStatusSchema>;
export type CreateUserReport = z.infer<typeof createUserReportSchema>;
export type UserReport = z.infer<typeof userReportSchema>;
export type ModerationAction = z.infer<typeof moderationActionSchema>;
export type VerifiedIntelligence = z.infer<typeof verifiedIntelligenceSchema>;