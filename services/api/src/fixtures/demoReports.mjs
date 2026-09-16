import { createHash, randomUUID } from 'node:crypto'

function hash(text) {
  return createHash('sha256').update(text.trim()).digest('hex')
}

export const DEMO_REPORTS = [
  {
    id: randomUUID(),
    report_type: 'suspicious',
    reported_domain: 'ceb-billpay-portal.xyz',
    raw_excerpt: 'CEB Alert: Electricity bill of Rs. 4,850 overdue. Disconnection scheduled today. Pay now at https://ceb-billpay-portal.xyz/pay',
    content_sha256: hash('CEB Alert: Electricity bill of Rs. 4,850 overdue. Disconnection scheduled today. Pay now at https://ceb-billpay-portal.xyz/pay'),
    notes: 'Received via SMS from header CEB-ALERT. Legitimate CEB uses ceb.lk. Phishing scam targeting households.',
    status: 'PENDING',
    created_at: new Date(Date.now() - 1000 * 60 * 12).toISOString(), // 12 mins ago
    updated_at: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
  },
  {
    id: randomUUID(),
    report_type: 'suspicious',
    reported_domain: 'combank-secure-update.online',
    raw_excerpt: 'Commercial Bank: Account access restricted due to unverified KYC. Verify immediately at https://combank-secure-update.online/auth',
    content_sha256: hash('Commercial Bank: Account access restricted due to unverified KYC. Verify immediately at https://combank-secure-update.online/auth'),
    notes: 'SMS asking for online banking credentials and OTP. Sent from international virtual number +44 7911...',
    status: 'PENDING',
    created_at: new Date(Date.now() - 1000 * 60 * 45).toISOString(), // 45 mins ago
    updated_at: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
  },
  {
    id: randomUUID(),
    report_type: 'false_positive',
    reported_domain: 'mohe.gov.lk',
    raw_excerpt: 'Ministry of Higher Education: University intake scholarship registration is now open on the official portal http://mohe.gov.lk',
    content_sha256: hash('Ministry of Higher Education: University intake scholarship registration is now open on the official portal http://mohe.gov.lk'),
    notes: 'Citizen flagged this because it was an HTTP link, but this is the official ministry portal.',
    status: 'PENDING',
    created_at: new Date(Date.now() - 1000 * 60 * 180).toISOString(), // 3 hours ago
    updated_at: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
  },
]
