import { useState, useRef, type DragEvent, type ChangeEvent } from 'react'
import { Upload, FileImage, RefreshCw, CheckCircle2, AlertCircle, Sparkles, X } from 'lucide-react'
import { performOcr, type OcrProgress, type OcrResult } from '../services/ocrService'
import './ScreenshotOcrUploader.css'

export interface ScreenshotOcrUploaderProps {
  onTextConfirmed: (correctedText: string, confidence: number) => void
  onCancel?: () => void
}

export function ScreenshotOcrUploader({ onTextConfirmed, onCancel }: ScreenshotOcrUploaderProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [imagePreview, setImagePreview] = useState<string | null>(null)
  const [isProcessing, setIsProcessing] = useState(false)
  const [progress, setProgress] = useState<OcrProgress | null>(null)
  const [ocrResult, setOcrResult] = useState<OcrResult | null>(null)
  const [editableText, setEditableText] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isDragOver, setIsDragOver] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileSelect = (file: File) => {
    if (!file.type.startsWith('image/')) {
      setError('Please select a valid screenshot image file (.png, .jpg, .webp).')
      return
    }

    if (file.size > 10 * 1024 * 1024) {
      setError('Screenshot file size exceeds 10MB limit.')
      return
    }

    setError(null)
    setSelectedFile(file)
    setOcrResult(null)
    setEditableText('')

    const reader = new FileReader()
    reader.onload = (e) => setImagePreview(e.target?.result as string)
    reader.readAsDataURL(file)

    // Automatically trigger OCR processing
    void processImage(file)
  }

  const processImage = async (file: File) => {
    setIsProcessing(true)
    setError(null)
    setProgress({ status: 'starting', progress: 0.05, message: 'Starting OCR engine...' })

    try {
      const result = await performOcr(file, {
        onProgress: (upd) => setProgress(upd),
      })

      setOcrResult(result)
      setEditableText(result.text)

      if (!result.text.trim()) {
        setError('No text could be recognized in this image. You can type or paste the text manually below.')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'OCR processing failed.')
    } finally {
      setIsProcessing(false)
    }
  }

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragOver(false)
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0])
    }
  }

  const handleInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFileSelect(e.target.files[0])
    }
  }

  const handleReset = () => {
    setSelectedFile(null)
    setImagePreview(null)
    setOcrResult(null)
    setEditableText('')
    setError(null)
    setProgress(null)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const handleConfirmText = () => {
    if (!editableText.trim()) return
    onTextConfirmed(editableText.trim(), ocrResult?.confidence || 100)
  }

  // Determine badge styling based on confidence
  const conf = ocrResult?.confidence || 0
  const confBadgeClass = conf >= 75 ? 'conf-high' : conf >= 50 ? 'conf-med' : 'conf-low'

  return (
    <div className="ocr-uploader-card">
      <div className="ocr-header">
        <div className="ocr-title">
          <Sparkles size={18} className="ocr-icon-sparkle" />
          <span>Screenshot OCR & Text Extractor</span>
        </div>
        {onCancel && (
          <button type="button" className="ocr-btn-close" onClick={onCancel} title="Close OCR panel">
            <X size={16} />
          </button>
        )}
      </div>

      {!selectedFile ? (
        <div
          className={`ocr-dropzone ${isDragOver ? 'drag-over' : ''}`}
          onDragOver={(e) => {
            e.preventDefault()
            setIsDragOver(true)
          }}
          onDragLeave={() => setIsDragOver(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            type="ref"
            ref={fileInputRef}
            aria-label="Upload screenshot image"
            type="file"
            accept="image/png,image/jpeg,image/webp,image/gif"
            onChange={handleInputChange}
            style={{ display: 'none' }}
          />
          <Upload size={32} className="ocr-drop-icon" />
          <p className="ocr-drop-text">
            <strong>Upload screenshot</strong> or drag and drop image here
          </p>
          <span className="ocr-drop-hint">Supports PNG, JPG, WEBP (English & Sinhala OCR)</span>
        </div>
      ) : (
        <div className="ocr-active-container">
          <div className="ocr-preview-row">
            {imagePreview && (
              <div className="ocr-preview-box">
                <img src={imagePreview} alt="Screenshot preview" className="ocr-thumbnail" />
                <span className="ocr-file-name">{selectedFile.name}</span>
              </div>
            )}

            <button type="button" className="btn-secondary btn-sm" onClick={handleReset} disabled={isProcessing}>
              <RefreshCw size={14} /> Reset Image
            </button>
          </div>

          {isProcessing && (
            <div className="ocr-progress-box">
              <div className="ocr-progress-bar-bg">
                <div
                  className="ocr-progress-bar-fill"
                  style={{ width: `${Math.round((progress?.progress || 0) * 100)}%` }}
                />
              </div>
              <p className="ocr-progress-msg">{progress?.message || 'Recognizing text...'}</p>
            </div>
          )}

          {error && (
            <div className="ocr-error-banner">
              <AlertCircle size={16} />
              <span>{error}</span>
            </div>
          )}

          {ocrResult && !isProcessing && (
            <div className="ocr-result-box">
              <div className="ocr-result-meta">
                <span className={`ocr-conf-badge ${confBadgeClass}`}>
                  <CheckCircle2 size={13} />
                  OCR Confidence: {conf}%
                </span>
                <span className="ocr-lang-badge">Languages: English + Sinhala</span>
              </div>

              <div className="ocr-editable-group">
                <label htmlFor="ocr-editable-text" className="ocr-label">
                  Recognized Text (Review and correct any OCR typos before analyzing):
                </label>
                <textarea
                  id="ocr-editable-text"
                  className="ocr-textarea"
                  rows={4}
                  value={editableText}
                  onChange={(e) => setEditableText(e.target.value)}
                  placeholder="Recognized text will appear here..."
                />
              </div>

              <div className="ocr-action-row">
                <button
                  type="button"
                  className="btn-primary ocr-btn-confirm"
                  onClick={handleConfirmText}
                  disabled={!editableText.trim()}
                >
                  <FileImage size={16} />
                  Analyze Corrected Text
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
