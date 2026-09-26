export function getOpenApiSpec() {
  return {
    openapi: '3.0.3',
    info: {
      title: 'TrustLens LK API',
      version: '1.0.0',
      description: 'Sri Lanka Scam Decision Support and Community Intelligence Platform API.',
      contact: {
        name: 'Byte Knights',
      },
    },
    servers: [
      {
        url: 'http://localhost:8787',
        description: 'Local development server',
      },
    ],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Supabase Auth JWT Bearer token (from moderator login)',
        },
      },
      schemas: {
        Submission: {
          type: 'object',
          properties: {
            type: { type: 'string', enum: ['message', 'url', 'screenshot'], default: 'message', description: 'Submission content type' },
            text: { type: 'string', maxLength: 10000, example: 'Congratulations! You won Rs. 50,000. Send OTP to claim.' },
            url: { type: 'string', format: 'uri', maxLength: 2048, example: 'https://scam-lottery-lk.xyz/claim' },
            imageRef: { type: 'string', maxLength: 512 },
            languageHint: { type: 'string', enum: ['en', 'si', 'singlish', 'mixed'], default: 'en' },
            retentionConsent: { type: 'boolean', default: false, description: 'Explicit user consent for privacy-preserved research data retention' },
          },
        },
        ExtractedEntity: {
          type: 'object',
          required: ['type', 'value'],
          properties: {
            type: { type: 'string', enum: ['url', 'domain', 'phone', 'email', 'amount', 'organization'] },
            value: { type: 'string', example: 'https://scam.lk' },
            normalizedValue: { type: 'string', nullable: true, example: 'scam.lk' },
            sourceSpan: { type: 'string', nullable: true, example: 'https://scam.lk' },
            startIndex: { type: 'integer', nullable: true, example: 12 },
            endIndex: { type: 'integer', nullable: true, example: 27 },
            confidence: { type: 'number', minimum: 0, maximum: 1, example: 0.99 },
          },
        },
        Finding: {
          type: 'object',
          required: ['canonicalSignal', 'category', 'evidence', 'source', 'strength'],
          properties: {
            canonicalSignal: { type: 'string', example: 'credential_request' },
            category: { type: 'string', example: 'Sensitive information theft' },
            evidence: { type: 'string', example: 'OTP or one-time verification code requested' },
            source: { type: 'string', enum: ['RULE', 'LLM', 'DOMAIN_DIRECTORY', 'SCANNER', 'APPROVED_REPORT'] },
            strength: { type: 'number', minimum: 0, maximum: 1, example: 0.99 },
            confidence: { type: 'number', minimum: 0, maximum: 1, example: 0.99 },
            limitation: { type: 'string', example: 'Keyword rule; cross-verify through official channels.' },
            detectorVersion: { type: 'string', example: 'rules-v2' },
          },
        },
        RiskDecision: {
          type: 'object',
          required: ['riskBand', 'recommendation', 'findings', 'limitations', 'safeActions', 'policyVersion'],
          properties: {
            riskBand: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'UNKNOWN'] },
            recommendation: { type: 'string', enum: ['PROCEED_CAUTIOUSLY', 'VERIFY_INDEPENDENTLY', 'STOP_AND_AVOID', 'UNABLE_TO_VERIFY'] },
            findings: { type: 'array', items: { $ref: '#/components/schemas/Finding' } },
            counterEvidence: { type: 'array', items: { $ref: '#/components/schemas/Finding' } },
            overridesApplied: { type: 'array', items: { type: 'string' } },
            missingChecks: { type: 'array', items: { type: 'string', enum: ['RULE', 'LLM', 'DOMAIN_DIRECTORY', 'SCANNER', 'APPROVED_REPORT'] } },
            limitations: { type: 'array', items: { type: 'string' } },
            safeActions: { type: 'array', items: { type: 'string' } },
            policyVersion: { type: 'string', example: 'rules-v2' },
          },
        },
        AiValidationResult: {
          type: 'object',
          properties: {
            verdict: { type: 'string', enum: ['AGREE', 'DISAGREE', 'UNCERTAIN'], example: 'DISAGREE' },
            confidence: { type: 'number', minimum: 0, maximum: 1, example: 0.85 },
            reasoning: { type: 'string', example: 'The message is an internal IT notification about a system upgrade.' },
            originalRiskBand: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'UNKNOWN'], example: 'HIGH' },
            adjustedRiskBand: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'UNKNOWN'], example: 'MEDIUM' },
            appliedAction: { type: 'string', enum: ['DOWNGRADED', 'HARD_BLOCKED', 'RETAINED'], example: 'DOWNGRADED' },
            evaluatedAt: { type: 'string', format: 'date-time' },
          },
        },
        AnalyzeResponse: {
          type: 'object',
          required: ['inputType', 'decision', 'entities', 'requestId'],
          properties: {
            inputType: { type: 'string', enum: ['message', 'url', 'screenshot'] },
            submissionId: { type: 'string', format: 'uuid', nullable: true },
            decision: { $ref: '#/components/schemas/RiskDecision' },
            entities: { type: 'array', items: { $ref: '#/components/schemas/ExtractedEntity' } },
            requestId: { type: 'string', format: 'uuid' },
            aiValidation: { $ref: '#/components/schemas/AiValidationResult', nullable: true },
          },
        },
        ScannerPreviewRequest: {
          type: 'object',
          required: ['url'],
          properties: {
            url: { type: 'string', format: 'uri', example: 'https://login.example.com/verify' },
          },
        },
        ScannerPreviewResponse: {
          type: 'object',
          required: ['safeToFetch', 'hostname', 'url', 'requestId'],
          properties: {
            safeToFetch: { type: 'boolean', example: true },
            hostname: { type: 'string', example: 'login.example.com' },
            url: { type: 'string', format: 'uri', example: 'https://login.example.com/verify' },
            requestId: { type: 'string', format: 'uuid' },
          },
        },
        UserReportInput: {
          type: 'object',
          required: ['reportType', 'contentSha256'],
          properties: {
            reportType: { type: 'string', enum: ['suspicious', 'false_positive', 'false_negative'] },
            contentSha256: { type: 'string', pattern: '^[a-f0-9]{64}$', example: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f61234' },
            reportedDomain: { type: 'string', maxLength: 255, nullable: true, example: 'scam-lottery-lk.xyz' },
            notes: { type: 'string', maxLength: 2000, nullable: true, example: 'WhatsApp message demanding fee upfront.' },
          },
        },
        UserReport: {
          type: 'object',
          required: ['id', 'reportType', 'contentSha256', 'status', 'createdAt'],
          properties: {
            id: { type: 'string', format: 'uuid' },
            reportType: { type: 'string', enum: ['suspicious', 'false_positive', 'false_negative'] },
            contentSha256: { type: 'string' },
            reportedDomain: { type: 'string', nullable: true },
            notes: { type: 'string', nullable: true },
            status: { type: 'string', enum: ['PENDING', 'REVIEWED', 'REJECTED', 'APPROVED', 'RETIRED'] },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
        ModerationActionInput: {
          type: 'object',
          required: ['reportId', 'action'],
          properties: {
            reportId: { type: 'string', format: 'uuid' },
            action: { type: 'string', enum: ['APPROVE', 'REJECT', 'RETIRE'] },
            notes: { type: 'string', maxLength: 1000, nullable: true, example: 'Confirmed phishing website.' },
            indicatorType: { type: 'string', enum: ['domain', 'content_hash', 'phone', 'url'], nullable: true },
            category: { type: 'string', maxLength: 100, nullable: true, example: 'Phishing' },
          },
        },
        ModerationQueueResponse: {
          type: 'object',
          required: ['reports', 'count', 'total', 'page', 'limit', 'totalPages', 'status', 'requestId'],
          properties: {
            reports: { type: 'array', items: { $ref: '#/components/schemas/UserReport' } },
            count: { type: 'integer', example: 1 },
            total: { type: 'integer', example: 1 },
            page: { type: 'integer', example: 1 },
            limit: { type: 'integer', example: 20 },
            totalPages: { type: 'integer', example: 1 },
            status: { type: 'string', example: 'PENDING' },
            requestId: { type: 'string', format: 'uuid' },
          },
        },
        ModerationStatsResponse: {
          type: 'object',
          required: ['totalReports', 'pendingCount', 'approvedCount', 'rejectedCount', 'reportsVelocity24h', 'threatCategories', 'requestId'],
          properties: {
            totalReports: { type: 'integer', example: 42 },
            pendingCount: { type: 'integer', example: 5 },
            approvedCount: { type: 'integer', example: 35 },
            rejectedCount: { type: 'integer', example: 2 },
            reportsVelocity24h: { type: 'integer', example: 8 },
            threatCategories: { type: 'object', additionalProperties: { type: 'integer' } },
            requestId: { type: 'string', format: 'uuid' },
          },
        },
        ApiError: {
          type: 'object',
          required: ['code', 'message'],
          properties: {
            code: { type: 'string', example: 'INVALID_SUBMISSION' },
            message: { type: 'string', example: 'text or url is required.' },
            requestId: { type: 'string', format: 'uuid' },
          },
        },
        OfficialDomainRecord: {
          type: 'object',
          required: ['name', 'officialDomain', 'status', 'active'],
          properties: {
            id: { type: 'integer', nullable: true, example: 3 },
            name: { type: 'string', example: 'Bank of Ceylon' },
            officialDomain: { type: 'string', example: 'boc.lk' },
            category: { type: 'string', nullable: true, example: 'Banking' },
            sourceUrl: { type: 'string', format: 'uri', nullable: true, example: 'https://www.boc.lk' },
            reviewer: { type: 'string', nullable: true, example: 'Isuru Adikaram' },
            verifiedAt: { type: 'string', format: 'date-time', nullable: true },
            nextReviewDate: { type: 'string', format: 'date', nullable: true, example: '2026-12-18' },
            status: { type: 'string', enum: ['ACTIVE', 'STALE', 'RETIRED'] },
            active: { type: 'boolean' },
          },
        },
        DomainDirectoryListResponse: {
          type: 'object',
          required: ['entries', 'count', 'requestId'],
          properties: {
            entries: { type: 'array', items: { $ref: '#/components/schemas/OfficialDomainRecord' } },
            count: { type: 'integer', example: 13 },
            requestId: { type: 'string', format: 'uuid' },
          },
        },
        DomainDirectoryLookupResponse: {
          type: 'object',
          required: ['outcome', 'matchedRecord', 'submittedDomain', 'requestId'],
          properties: {
            outcome: { type: 'string', enum: ['MATCHED', 'STALE', 'UNKNOWN'], description: 'MISMATCH is only produced by /api/analyze, which also compares a claimed organization; a plain domain lookup cannot detect impersonation on its own.' },
            matchedRecord: { allOf: [{ $ref: '#/components/schemas/OfficialDomainRecord' }], nullable: true },
            submittedDomain: { type: 'string', example: 'online.boc.lk' },
            requestId: { type: 'string', format: 'uuid' },
          },
        },
      },
    },

    paths: {
      '/health': {
        get: {
          summary: 'Service Health Check',
          description: 'Returns API health status, service identifier, and unique request trace ID.',
          responses: {
            200: {
              description: 'Service is healthy',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    required: ['status', 'service', 'requestId'],
                    properties: {
                      status: { type: 'string', example: 'ok' },
                      service: { type: 'string', example: 'trustlens-api' },
                      requestId: { type: 'string', format: 'uuid' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/api/analyze': {
        post: {
          summary: 'Analyze text message or URL for scam indicators',
          description: 'Runs deterministic rule engine, remote URL scanner, and entity extraction to produce risk decisions.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Submission' },
              },
            },
          },
          responses: {
            200: {
              description: 'Analysis decision and extracted entities',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AnalyzeResponse' },
                },
              },
            },
            400: {
              description: 'Invalid submission payload',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
            413: {
              description: 'Payload exceeds maximum size limit (100KB)',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
            429: {
              description: 'Rate limit exceeded',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
          },
        },
      },
      '/api/scanner/preview': {
        post: {
          summary: 'Inspect URL for SSRF safety and security signals',
          description: 'Validates URL target against private IPv4/IPv6 ranges and evaluates structural URL scam signals without performing HTTP fetch.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ScannerPreviewRequest' },
              },
            },
          },
          responses: {
            200: {
              description: 'URL is safe for scanning',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/ScannerPreviewResponse' },
                },
              },
            },
            400: {
              description: 'URL is unsafe or malformed',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
          },
        },
      },
      '/api/reports': {
        post: {
          summary: 'Submit a community scam report',
          description: 'Allows citizens to report suspicious content, false positives, or false negatives with a privacy-preserving SHA-256 hash.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UserReportInput' },
              },
            },
          },
          responses: {
            201: {
              description: 'Report successfully recorded with PENDING status',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    required: ['report', 'reportId', 'status', 'requestId'],
                    properties: {
                      report: { $ref: '#/components/schemas/UserReport' },
                      reportId: { type: 'string', format: 'uuid' },
                      status: { type: 'string', example: 'PENDING' },
                      requestId: { type: 'string', format: 'uuid' },
                    },
                  },
                },
              },
            },
            400: {
              description: 'Invalid report payload',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
            503: {
              description: 'Reporting storage unavailable',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
          },
        },
      },
      '/api/domain-directory': {
        get: {
          summary: 'List official domain directory entries',
          description: 'Returns reviewed organizations from the official domain directory. Requires no auth: matches the RLS policy that already lets anon/authenticated callers read active organizations directly from Supabase.',
          parameters: [
            {
              name: 'category',
              in: 'query',
              required: false,
              schema: { type: 'string', example: 'Banking' },
              description: 'Filter entries to one category',
            },
            {
              name: 'includeStale',
              in: 'query',
              required: false,
              schema: { type: 'string', enum: ['true', 'false'], default: 'false' },
              description: 'Include entries past their review date (excluded by default, since they cannot contribute positive evidence)',
            },
          ],
          responses: {
            200: {
              description: 'Directory entries',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/DomainDirectoryListResponse' } } },
            },
            502: {
              description: 'Directory fetch failed',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
          },
        },
      },
      '/api/domain-directory/lookup': {
        get: {
          summary: 'Look up one domain against the official directory',
          description: 'Checks whether a submitted domain matches a reviewed organization. UNKNOWN means not verified, never fraudulent; STALE means a match exists but its review date has passed.',
          parameters: [
            {
              name: 'domain',
              in: 'query',
              required: true,
              schema: { type: 'string', example: 'online.boc.lk' },
              description: 'The domain to check, an exact match or a subdomain of a directory entry both match',
            },
          ],
          responses: {
            200: {
              description: 'Lookup result',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/DomainDirectoryLookupResponse' } } },
            },
            400: {
              description: 'Missing domain query parameter',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
            502: {
              description: 'Directory lookup failed',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
          },
        },
      },
      '/api/moderation/stats': {
        get: {
          summary: 'Fetch aggregated moderation dashboard statistics',
          description: 'Returns metrics on report volumes, pending queue size, 24h velocity, and threat category distribution.',
          security: [{ BearerAuth: [] }],
          responses: {
            200: {
              description: 'Aggregated moderation statistics and metrics overview',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/ModerationStatsResponse' },
                },
              },
            },
            401: {
              description: 'Unauthorized - moderator credentials required',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
          },
        },
      },
      '/api/moderation/queue': {
        get: {
          summary: 'Fetch paginated reports for moderation',
          description: 'Returns reports filtered by status (PENDING, APPROVED, REJECTED, ALL) with offset pagination support.',
          security: [{ BearerAuth: [] }],
          parameters: [
            {
              name: 'status',
              in: 'query',
              required: false,
              schema: { type: 'string', enum: ['PENDING', 'APPROVED', 'REJECTED', 'ALL'], default: 'PENDING' },
              description: 'Filter by report resolution status',
            },
            {
              name: 'page',
              in: 'query',
              required: false,
              schema: { type: 'integer', default: 1, minimum: 1 },
              description: 'Page number for pagination',
            },
            {
              name: 'limit',
              in: 'query',
              required: false,
              schema: { type: 'integer', default: 20, minimum: 1, maximum: 100 },
              description: 'Number of items per page',
            },
          ],
          responses: {
            200: {
              description: 'Paginated list of reports matching the status filter',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/ModerationQueueResponse' },
                },
              },
            },
            401: {
              description: 'Unauthorized - moderator credentials required',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
          },
        },
      },
      '/api/moderation/review': {
        post: {
          summary: 'Review and approve/reject a pending report',
          description: 'Updates report status and automatically creates sanitized community intelligence if approved.',
          security: [{ BearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ModerationActionInput' },
              },
            },
          },
          responses: {
            200: {
              description: 'Report updated and verified intelligence created if approved',
            },
            401: {
              description: 'Unauthorized - moderator credentials required',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
            404: {
              description: 'Report not found',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
          },
        },
      },
      '/api/moderation/login': {
        post: {
          summary: 'Moderator Authentication Login',
          description: 'Authenticates a moderator via Supabase Auth and returns a JWT access token.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['email', 'password'],
                  properties: {
                    email: { type: 'string', example: 'moderator@trustlens.lk' },
                    password: { type: 'string', example: 'MyPassword123!' },
                  },
                },
              },
            },
          },
          responses: {
            200: {
              description: 'Successful login returning JWT access token and user info',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    required: ['accessToken', 'user', 'requestId'],
                    properties: {
                      accessToken: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
                      user: { type: 'object' },
                      requestId: { type: 'string', format: 'uuid' },
                    },
                  },
                },
              },
            },
            401: {
              description: 'Invalid credentials or non-moderator account',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
          },
        },
      },
      '/api/moderation/seed-demo': {
        post: {
          summary: 'Seed Realistic Demo Threat Reports (Protected)',
          description: 'Populates 3 realistic Sri Lankan scam reports into the moderation queue for demonstration and testing.',
          security: [{ BearerAuth: [] }],
          responses: {
            200: {
              description: 'Reports successfully seeded',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    required: ['seeded', 'count', 'requestId'],
                    properties: {
                      seeded: { type: 'array', items: { $ref: '#/components/schemas/UserReport' } },
                      count: { type: 'integer', example: 3 },
                      requestId: { type: 'string', format: 'uuid' },
                    },
                  },
                },
              },
            },
            401: {
              description: 'Unauthorized - moderator credentials required',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
            },
          },
        },
      },
    },
  }
}

export function getSwaggerHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TrustLens LK API Documentation</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  <style>
    body { margin: 0; background: #0f172a; color: #f8fafc; font-family: system-ui, -apple-system, sans-serif; }
    .topbar { display: none !important; }
    .swagger-ui { font-family: inherit; }
    .swagger-ui .info { margin: 30px 0; background: #1e293b; padding: 24px; border-radius: 12px; border: 1px solid #334155; }
    .swagger-ui .info .title { color: #38bdf8; font-weight: 700; }
    .swagger-ui .info p, .swagger-ui .info li { color: #94a3b8; }
    .swagger-ui .scheme-container { background: #1e293b; border-radius: 8px; border: 1px solid #334155; box-shadow: none; margin: 0 0 20px 0; padding: 15px; }
    .swagger-ui .opblock { border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.3); border: 1px solid #334155; background: #1e293b; }
    .swagger-ui .opblock .opblock-summary-method { border-radius: 6px; font-weight: 700; }
    .swagger-ui .opblock-summary-path { color: #f1f5f9 !important; font-weight: 600; }
    .swagger-ui .opblock-description-wrapper p { color: #cbd5e1; }
    .swagger-ui table thead tr th { color: #f8fafc; border-bottom: 1px solid #334155; }
    .swagger-ui table tbody tr td { color: #cbd5e1; border-bottom: 1px solid #1e293b; }
    .swagger-ui .parameter__name { color: #38bdf8; font-weight: 600; }
    .swagger-ui .parameter__type { color: #94a3b8; }
    .swagger-ui section.models { border: 1px solid #334155; border-radius: 12px; background: #1e293b; }
    .swagger-ui section.models h4 { color: #38bdf8; border-bottom: 1px solid #334155; }
    .swagger-ui .model-title { color: #f8fafc; }
    .swagger-ui .model { color: #cbd5e1; }
    .swagger-ui .btn { border-radius: 6px; font-weight: 600; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js" crossorigin></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis],
      });
    };
  </script>
</body>
</html>`
}
