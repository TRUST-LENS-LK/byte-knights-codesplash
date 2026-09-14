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