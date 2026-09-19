import { z } from "zod";
export declare const submissionSchema: z.ZodObject<{
    type: z.ZodEnum<["message", "url", "screenshot"]>;
    text: z.ZodOptional<z.ZodString>;
    languageHint: z.ZodOptional<z.ZodEnum<["en", "si", "singlish", "mixed"]>>;
    retentionConsent: z.ZodDefault<z.ZodBoolean>;
}, "strip", z.ZodTypeAny, {
    type: "message" | "url" | "screenshot";
    retentionConsent: boolean;
    text?: string | undefined;
    languageHint?: "en" | "si" | "singlish" | "mixed" | undefined;
}, {
    type: "message" | "url" | "screenshot";
    text?: string | undefined;
    languageHint?: "en" | "si" | "singlish" | "mixed" | undefined;
    retentionConsent?: boolean | undefined;
}>;
export declare const extractedEntitySchema: z.ZodObject<{
    type: z.ZodEnum<["url", "domain", "phone", "email", "amount", "organization"]>;
    value: z.ZodString;
    normalizedValue: z.ZodOptional<z.ZodString>;
    /** The matched substring as it appeared in the raw input text */
    sourceSpan: z.ZodOptional<z.ZodString>;
    /** Zero-based character index where this entity starts in the raw input */
    startIndex: z.ZodOptional<z.ZodNumber>;
    /** Zero-based character index immediately after this entity ends in the raw input */
    endIndex: z.ZodOptional<z.ZodNumber>;
    confidence: z.ZodOptional<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    type: "url" | "domain" | "phone" | "email" | "amount" | "organization";
    value: string;
    normalizedValue?: string | undefined;
    sourceSpan?: string | undefined;
    startIndex?: number | undefined;
    endIndex?: number | undefined;
    confidence?: number | undefined;
}, {
    type: "url" | "domain" | "phone" | "email" | "amount" | "organization";
    value: string;
    normalizedValue?: string | undefined;
    sourceSpan?: string | undefined;
    startIndex?: number | undefined;
    endIndex?: number | undefined;
    confidence?: number | undefined;
}>;
export declare const findingSchema: z.ZodObject<{
    canonicalSignal: z.ZodString;
    category: z.ZodString;
    evidence: z.ZodString;
    source: z.ZodEnum<["RULE", "LLM", "DOMAIN_DIRECTORY", "SCANNER", "APPROVED_REPORT"]>;
    strength: z.ZodNumber;
    confidence: z.ZodOptional<z.ZodNumber>;
    limitation: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    canonicalSignal: string;
    category: string;
    evidence: string;
    source: "RULE" | "LLM" | "DOMAIN_DIRECTORY" | "SCANNER" | "APPROVED_REPORT";
    strength: number;
    confidence?: number | undefined;
    limitation?: string | undefined;
}, {
    canonicalSignal: string;
    category: string;
    evidence: string;
    source: "RULE" | "LLM" | "DOMAIN_DIRECTORY" | "SCANNER" | "APPROVED_REPORT";
    strength: number;
    confidence?: number | undefined;
    limitation?: string | undefined;
}>;
export declare const riskDecisionSchema: z.ZodObject<{
    riskBand: z.ZodEnum<["LOW", "MEDIUM", "HIGH", "UNKNOWN"]>;
    recommendation: z.ZodEnum<["PROCEED_CAUTIOUSLY", "VERIFY_INDEPENDENTLY", "STOP_AND_AVOID", "UNABLE_TO_VERIFY"]>;
    findings: z.ZodArray<z.ZodObject<{
        canonicalSignal: z.ZodString;
        category: z.ZodString;
        evidence: z.ZodString;
        source: z.ZodEnum<["RULE", "LLM", "DOMAIN_DIRECTORY", "SCANNER", "APPROVED_REPORT"]>;
        strength: z.ZodNumber;
        confidence: z.ZodOptional<z.ZodNumber>;
        limitation: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        canonicalSignal: string;
        category: string;
        evidence: string;
        source: "RULE" | "LLM" | "DOMAIN_DIRECTORY" | "SCANNER" | "APPROVED_REPORT";
        strength: number;
        confidence?: number | undefined;
        limitation?: string | undefined;
    }, {
        canonicalSignal: string;
        category: string;
        evidence: string;
        source: "RULE" | "LLM" | "DOMAIN_DIRECTORY" | "SCANNER" | "APPROVED_REPORT";
        strength: number;
        confidence?: number | undefined;
        limitation?: string | undefined;
    }>, "many">;
    limitations: z.ZodArray<z.ZodString, "many">;
    safeActions: z.ZodArray<z.ZodString, "many">;
    policyVersion: z.ZodString;
}, "strip", z.ZodTypeAny, {
    riskBand: "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";
    recommendation: "PROCEED_CAUTIOUSLY" | "VERIFY_INDEPENDENTLY" | "STOP_AND_AVOID" | "UNABLE_TO_VERIFY";
    findings: {
        canonicalSignal: string;
        category: string;
        evidence: string;
        source: "RULE" | "LLM" | "DOMAIN_DIRECTORY" | "SCANNER" | "APPROVED_REPORT";
        strength: number;
        confidence?: number | undefined;
        limitation?: string | undefined;
    }[];
    limitations: string[];
    safeActions: string[];
    policyVersion: string;
}, {
    riskBand: "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";
    recommendation: "PROCEED_CAUTIOUSLY" | "VERIFY_INDEPENDENTLY" | "STOP_AND_AVOID" | "UNABLE_TO_VERIFY";
    findings: {
        canonicalSignal: string;
        category: string;
        evidence: string;
        source: "RULE" | "LLM" | "DOMAIN_DIRECTORY" | "SCANNER" | "APPROVED_REPORT";
        strength: number;
        confidence?: number | undefined;
        limitation?: string | undefined;
    }[];
    limitations: string[];
    safeActions: string[];
    policyVersion: string;
}>;
export declare const apiErrorSchema: z.ZodObject<{
    code: z.ZodString;
    message: z.ZodString;
    requestId: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    code: string;
    message: string;
    requestId?: string | undefined;
}, {
    code: string;
    message: string;
    requestId?: string | undefined;
}>;
export type Submission = z.infer<typeof submissionSchema>;
export type ExtractedEntity = z.infer<typeof extractedEntitySchema>;
export type Finding = z.infer<typeof findingSchema>;
export type RiskDecision = z.infer<typeof riskDecisionSchema>;
export type ApiError = z.infer<typeof apiErrorSchema>;
export declare const userReportTypeSchema: z.ZodEnum<["suspicious", "false_positive", "false_negative"]>;
export declare const userReportStatusSchema: z.ZodEnum<["PENDING", "REVIEWED", "REJECTED", "APPROVED", "RETIRED"]>;
export declare const createUserReportSchema: z.ZodObject<{
    reportType: z.ZodEnum<["suspicious", "false_positive", "false_negative"]>;
    contentSha256: z.ZodString;
    reportedDomain: z.ZodNullable<z.ZodOptional<z.ZodString>>;
    notes: z.ZodNullable<z.ZodOptional<z.ZodString>>;
    submissionId: z.ZodNullable<z.ZodOptional<z.ZodString>>;
    rawExcerpt: z.ZodNullable<z.ZodOptional<z.ZodString>>;
}, "strip", z.ZodTypeAny, {
    reportType: "suspicious" | "false_positive" | "false_negative";
    contentSha256: string;
    reportedDomain?: string | null | undefined;
    notes?: string | null | undefined;
    submissionId?: string | null | undefined;
    rawExcerpt?: string | null | undefined;
}, {
    reportType: "suspicious" | "false_positive" | "false_negative";
    contentSha256: string;
    reportedDomain?: string | null | undefined;
    notes?: string | null | undefined;
    submissionId?: string | null | undefined;
    rawExcerpt?: string | null | undefined;
}>;
export declare const userReportSchema: z.ZodObject<{
    id: z.ZodString;
    reportType: z.ZodEnum<["suspicious", "false_positive", "false_negative"]>;
    contentSha256: z.ZodString;
    reportedDomain: z.ZodOptional<z.ZodNullable<z.ZodString>>;
    notes: z.ZodOptional<z.ZodNullable<z.ZodString>>;
    status: z.ZodEnum<["PENDING", "REVIEWED", "REJECTED", "APPROVED", "RETIRED"]>;
    createdAt: z.ZodString;
    reviewedAt: z.ZodOptional<z.ZodNullable<z.ZodString>>;
}, "strip", z.ZodTypeAny, {
    status: "PENDING" | "REVIEWED" | "REJECTED" | "APPROVED" | "RETIRED";
    reportType: "suspicious" | "false_positive" | "false_negative";
    contentSha256: string;
    id: string;
    createdAt: string;
    reportedDomain?: string | null | undefined;
    notes?: string | null | undefined;
    reviewedAt?: string | null | undefined;
}, {
    status: "PENDING" | "REVIEWED" | "REJECTED" | "APPROVED" | "RETIRED";
    reportType: "suspicious" | "false_positive" | "false_negative";
    contentSha256: string;
    id: string;
    createdAt: string;
    reportedDomain?: string | null | undefined;
    notes?: string | null | undefined;
    reviewedAt?: string | null | undefined;
}>;
export declare const moderationActionSchema: z.ZodObject<{
    reportId: z.ZodString;
    action: z.ZodEnum<["APPROVE", "REJECT", "RETIRE"]>;
    notes: z.ZodNullable<z.ZodOptional<z.ZodString>>;
    indicatorType: z.ZodOptional<z.ZodEnum<["domain", "content_hash", "phone", "url"]>>;
    category: z.ZodNullable<z.ZodOptional<z.ZodString>>;
}, "strip", z.ZodTypeAny, {
    reportId: string;
    action: "APPROVE" | "REJECT" | "RETIRE";
    category?: string | null | undefined;
    notes?: string | null | undefined;
    indicatorType?: "url" | "domain" | "phone" | "content_hash" | undefined;
}, {
    reportId: string;
    action: "APPROVE" | "REJECT" | "RETIRE";
    category?: string | null | undefined;
    notes?: string | null | undefined;
    indicatorType?: "url" | "domain" | "phone" | "content_hash" | undefined;
}>;
export declare const verifiedIntelligenceSchema: z.ZodObject<{
    id: z.ZodString;
    sourceReportId: z.ZodOptional<z.ZodNullable<z.ZodString>>;
    indicatorType: z.ZodEnum<["domain", "content_hash", "phone", "url"]>;
    indicatorValue: z.ZodString;
    defangedValue: z.ZodString;
    riskLevel: z.ZodEnum<["CONFIRMED_SCAM", "VERIFIED_SAFE"]>;
    category: z.ZodOptional<z.ZodNullable<z.ZodString>>;
    confidence: z.ZodDefault<z.ZodNumber>;
    notes: z.ZodOptional<z.ZodNullable<z.ZodString>>;
    active: z.ZodDefault<z.ZodBoolean>;
    createdAt: z.ZodString;
}, "strip", z.ZodTypeAny, {
    confidence: number;
    id: string;
    createdAt: string;
    indicatorType: "url" | "domain" | "phone" | "content_hash";
    indicatorValue: string;
    defangedValue: string;
    riskLevel: "CONFIRMED_SCAM" | "VERIFIED_SAFE";
    active: boolean;
    category?: string | null | undefined;
    notes?: string | null | undefined;
    sourceReportId?: string | null | undefined;
}, {
    id: string;
    createdAt: string;
    indicatorType: "url" | "domain" | "phone" | "content_hash";
    indicatorValue: string;
    defangedValue: string;
    riskLevel: "CONFIRMED_SCAM" | "VERIFIED_SAFE";
    confidence?: number | undefined;
    category?: string | null | undefined;
    notes?: string | null | undefined;
    sourceReportId?: string | null | undefined;
    active?: boolean | undefined;
}>;
export type UserReportType = z.infer<typeof userReportTypeSchema>;
export type UserReportStatus = z.infer<typeof userReportStatusSchema>;
export type CreateUserReport = z.infer<typeof createUserReportSchema>;
export type UserReport = z.infer<typeof userReportSchema>;
export type ModerationAction = z.infer<typeof moderationActionSchema>;
export type VerifiedIntelligence = z.infer<typeof verifiedIntelligenceSchema>;
//# sourceMappingURL=index.d.ts.map