import { z } from "zod";

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
  /** The matched substring as it appeared in the raw input text */
  sourceSpan: z.string().optional(),
  /** Zero-based character index where this entity starts in the raw input */
  startIndex: z.number().int().nonnegative().optional(),
  /** Zero-based character index immediately after this entity ends in the raw input */
  endIndex: z.number().int().nonnegative().optional(),
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
