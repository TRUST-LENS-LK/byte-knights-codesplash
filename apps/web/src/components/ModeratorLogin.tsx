import React, { useState } from 'react'
import {
  Mail,
  Lock,
  Eye,
  EyeOff,
  ArrowLeft,
  AlertCircle,
  Sparkles,
} from 'lucide-react'
import { type ModeratorUser, loginModerator } from '../services/moderatorService'
import './ModeratorDashboard.css'

export interface ModeratorLoginProps {
  onSuccess: (token: string, user: ModeratorUser) => void
  onBackToScanner: () => void
}

export const ModeratorLogin: React.FC<ModeratorLoginProps> = ({
  onSuccess,
  onBackToScanner,
}) => {
  const [loginEmail, setLoginEmail] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [loginLoading, setLoginLoading] = useState(false)
  const [loginError, setLoginError] = useState<string | null>(null)
  const [showPassword, setShowPassword] = useState(false)

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoginLoading(true)
    setLoginError(null)

    const res = await loginModerator(loginEmail.trim(), loginPassword)
    setLoginLoading(false)

    if (res.success && res.token && res.user) {
      onSuccess(res.token, res.user)
    } else {
      setLoginError(res.error || 'Invalid credentials or missing moderator privileges.')
    }
  }

  return (
    <div className="neo-login-viewport">
      <div className="neo-login-container">
        <div className="neo-login-card">
          {/* Top Bar: Circular Back Button only */}
          <div className="neo-login-top-bar" style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '8px' }}>
            <button
              type="button"
              className="neo-login-close-btn"
              onClick={onBackToScanner}
              title="Return to Citizen Scanner"
              aria-label="Return to Citizen Scanner"
            >
              <ArrowLeft size={16} aria-hidden="true" />
            </button>
          </div>

          {/* Header & Brand: Bigger Logo + Prominent TrustLensLK */}
          <div className="neo-login-header" style={{ textAlign: 'center', marginBottom: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '12px' }}>
              <img
                src="/TrustLens_Icon.png"
                alt="TrustLens LK"
                style={{
                  width: '92px',
                  height: 'auto',
                  maxHeight: '74px',
                  objectFit: 'contain',
                  filter: 'drop-shadow(0 6px 16px rgba(7, 94, 206, 0.18))',
                }}
              />
            </div>
            <div style={{ fontSize: '28px', fontWeight: '800', letterSpacing: '-0.03em', color: '#0F172A', lineHeight: '1.2', marginBottom: '6px' }}>
              TrustLens<span style={{ color: '#0066FF' }}>LK</span>
            </div>
            <h1 className="neo-login-title" style={{ fontSize: '15px', fontWeight: '600', color: '#64748B', margin: '0' }}>
              Sign In to Moderator Deck
            </h1>
          </div>

          {/* Error Message */}
          {loginError && (
            <div className="neo-login-error" role="alert">
              <AlertCircle size={16} aria-hidden="true" />
              <span>{loginError}</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleLogin} className="neo-login-form">
            <div className="neo-form-field">
              <label className="neo-input-label">Email</label>
              <div className="neo-input-box">
                <Mail size={16} className="neo-input-icon" aria-hidden="true" />
                <input
                  type="email"
                  required
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  placeholder="eg: abc@xyz.lk"
                  autoFocus
                  className="neo-dark-input"
                />
              </div>
            </div>

            <div className="neo-form-field">
              <label className="neo-input-label">Password</label>
              <div className="neo-input-box">
                <Lock size={16} className="neo-input-icon" aria-hidden="true" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  placeholder="Enter password"
                  className="neo-dark-input"
                />
                <button
                  type="button"
                  className="neo-password-toggle"
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={() => setShowPassword((prev) => !prev)}
                  title={showPassword ? 'Hide password' : 'Show password'}
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* Primary Action Button: Solid Blue */}
            <button
              type="submit"
              className="neo-login-btn-primary"
              disabled={loginLoading || !loginPassword}
            >
              {loginLoading ? (
                <>
                  <span className="neo-login-spinner" />
                  <span>Verifying RBAC Session...</span>
                </>
              ) : (
                'Sign In'
              )}
            </button>

            {/* Quick Demo Credentials Helper for Judges/Reviewers */}
            <div className="neo-login-demo-helper">
              <button
                type="button"
                className="neo-btn-demo-creds"
                onClick={() => {
                  setLoginEmail('moderator2@trustlens.lk')
                  setLoginPassword('ModPass2026!')
                  setLoginError(null)
                }}
                title="Auto-fill verified credentials for hackathon demonstration"
              >
                <Sparkles size={13} aria-hidden="true" />
                <span>Auto-fill Demo Credentials</span>
              </button>
            </div>

            {/* Divider */}
            <div className="neo-login-divider">
              <span>OR RETURN TO PUBLIC SCANNER</span>
            </div>

            {/* Secondary Action: Back to Public Scanner */}
            <button
              type="button"
              className="neo-login-btn-secondary"
              onClick={onBackToScanner}
            >
              <ArrowLeft size={15} aria-hidden="true" />
              <span>Return to Public Scanner</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
