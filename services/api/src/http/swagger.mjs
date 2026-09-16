export function getOpenApiSpec() {
  return {
    openapi: '3.0.3',
    info: {
      title: 'TrustLens LK API',
      version: '0.1.0',
      description: 'Sri Lanka Scam Decision Support and Community Intelligence Platform API.',
    },
    servers: [
      {
        url: 'http://localhost:8787',
        description: 'Local development server',
      },
    ],
    components: {
      securitySchemes: {
        ModeratorSecretKey: {
          type: 'apiKey',
          in: 'header',
          name: 'x-moderator-key',
          description: 'Passcode for developer/moderator quick access',
        },
        BearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Supabase Auth JWT Bearer token',
        },
      },
    },
    paths: {
      '/health': {
        get: {
          summary: 'Service Health Check',
          responses: {
            200: {
              description: 'Service is healthy',
              content: {
                'application/json': {
                  example: { status: 'ok', service: 'trustlens-api', requestId: '123e4567-e89b-12d3-a456-426614174000' },
                },
              },
            },
          },
        },
      },
      '/api/analyze': {
        post: {
          summary: 'Analyze text message or URL for scam indicators',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['text'],
                  properties: {
                    type: { type: 'string', enum: ['message', 'url', 'screenshot'], default: 'message' },
                    text: { type: 'string', example: 'Congratulations! You won Rs. 50,000. Send OTP to claim.' },
                    languageHint: { type: 'string', enum: ['en', 'si', 'singlish', 'mixed'], default: 'en' },
                    retentionConsent: { type: 'boolean', default: false },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: 'Analysis decision and extracted entities' },
            400: { description: 'Invalid submission' },
          },
        },
      },
      '/api/reports': {
        post: {
          summary: 'Submit a community scam report',
          description: 'Allows citizens to report suspicious content, false positives, or false negatives with a SHA-256 hash.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['reportType', 'contentSha256'],
                  properties: {
                    reportType: { type: 'string', enum: ['suspicious', 'false_positive', 'false_negative'] },
                    contentSha256: { type: 'string', example: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f61234' },
                    reportedDomain: { type: 'string', example: 'scam-lottery-lk.xyz' },
                    notes: { type: 'string', example: 'WhatsApp message demanding fee upfront.' },
                  },
                },
              },
            },
          },
          responses: {
            201: { description: 'Report successfully recorded with PENDING status' },
            400: { description: 'Invalid report payload' },
          },
        },
      },
      '/api/moderation/queue': {
        get: {
          summary: 'Fetch pending reports for moderation',
          security: [{ ModeratorSecretKey: [] }, { BearerAuth: [] }],
          parameters: [
            {
              name: 'status',
              in: 'query',
              required: false,
              schema: { type: 'string', enum: ['PENDING', 'APPROVED', 'REJECTED', 'ALL'], default: 'PENDING' },
            },
          ],
          responses: {
            200: { description: 'List of reports matching the status filter' },
            401: { description: 'Unauthorized - moderator credentials required' },
          },
        },
      },
      '/api/moderation/review': {
        post: {
          summary: 'Review and approve/reject a pending report',
          security: [{ ModeratorSecretKey: [] }, { BearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['reportId', 'action'],
                  properties: {
                    reportId: { type: 'string', format: 'uuid' },
                    action: { type: 'string', enum: ['APPROVE', 'REJECT', 'RETIRE'] },
                    notes: { type: 'string', example: 'Confirmed scam mimicking bank.' },
                    indicatorType: { type: 'string', enum: ['domain', 'content_hash', 'phone', 'url'] },
                    category: { type: 'string', example: 'Phishing' },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: 'Report updated and verified intelligence created if approved' },
            401: { description: 'Unauthorized' },
            404: { description: 'Report not found' },
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
    body { margin: 0; background: #fafbfc; }
    .topbar { display: none !important; }
    .swagger-ui .info { margin: 25px 0; }
    .swagger-ui .info .title { color: #087f8c; font-family: system-ui, sans-serif; }
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
