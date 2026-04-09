import { startTransition, useCallback, useEffect, useState } from 'react'
import './App.css'

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'
const TOKEN_KEY = 'medtara-token'
const USER_KEY = 'medtara-user'

const demoAccounts = [
  { role: 'Admin', email: 'admin@securehealth.local', password: 'Admin@123' },
  { role: 'Doctor', email: 'doctor@securehealth.local', password: 'Doctor@123' },
  { role: 'Patient', email: 'patient@securehealth.local', password: 'Patient@123' },
]

const guestSections = [
  { id: 'hero', label: 'Overview' },
  { id: 'access', label: 'Access' },
  { id: 'capabilities', label: 'Capabilities' },
]

const signedInSections = [
  { id: 'hero', label: 'Overview' },
  { id: 'workspace', label: 'Workspace' },
  { id: 'records', label: 'Records' },
  { id: 'security', label: 'Security' },
]

const emptyRegisterForm = {
  name: '',
  email: '',
  password: '',
  role: 'patient',
}

const emptyThreatPreviewForm = {
  eventType: 'Manual Threat Check',
  input: '',
}

function readStoredJson(key, fallback) {
  try {
    const value = localStorage.getItem(key)
    return value ? JSON.parse(value) : fallback
  } catch {
    return fallback
  }
}

function scrollToSection(id) {
  document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

function formatDate(value) {
  if (!value) {
    return 'No timestamp'
  }

  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'Invalid date' : date.toLocaleString()
}

async function request(path, options = {}, token) {
  const headers = new Headers(options.headers ?? {})

  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }

  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  })

  const contentType = response.headers.get('content-type') ?? ''
  const payload = contentType.includes('application/json')
    ? await response.json()
    : await response.text()

  if (!response.ok) {
    const message =
      typeof payload === 'object' && payload !== null
        ? payload.message || payload.error || 'Request failed'
        : 'Request failed'
    throw new Error(message)
  }

  return payload
}

function App() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) ?? '')
  const [user, setUser] = useState(() => readStoredJson(USER_KEY, null))
  const [mode, setMode] = useState('login')
  const [loginForm, setLoginForm] = useState({
    email: demoAccounts[0].email,
    password: demoAccounts[0].password,
  })
  const [registerForm, setRegisterForm] = useState(emptyRegisterForm)
  const [files, setFiles] = useState([])
  const [directory, setDirectory] = useState([])
  const [securityLogs, setSecurityLogs] = useState([])
  const [assessments, setAssessments] = useState([])
  const [status, setStatus] = useState('Sign in to start using MedTara.')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [uploadFiles, setUploadFiles] = useState([])
  const [uploadForm, setUploadForm] = useState({ patientId: '', doctorId: '' })
  const [assignmentDrafts, setAssignmentDrafts] = useState({})
  const [threatPreviewForm, setThreatPreviewForm] = useState(emptyThreatPreviewForm)
  const [threatPreview, setThreatPreview] = useState(null)

  const loadDashboardData = useCallback(async () => {
    if (!token || !user) {
      return
    }

    setRefreshing(true)
    setError('')

    try {
      const requests = [request('/api/file', {}, token)]

      if (user?.role === 'doctor' || user?.role === 'admin') {
        requests.push(request('/api/user/directory', {}, token))
      }

      if (user?.role === 'admin') {
        requests.push(request('/api/security/logs', {}, token))
        requests.push(request('/api/security/assessments', {}, token))
      }

      const [filesResult, directoryResult = [], logsResult = [], assessmentsResult = []] =
        await Promise.all(requests)

      startTransition(() => {
        setFiles(Array.isArray(filesResult) ? filesResult : [])
        setDirectory(Array.isArray(directoryResult) ? directoryResult : [])
        setSecurityLogs(Array.isArray(logsResult) ? logsResult : [])
        setAssessments(Array.isArray(assessmentsResult) ? assessmentsResult : [])
        setStatus(`Loaded latest ${user.role} dashboard data.`)
      })
    } catch (loadError) {
      setError(loadError.message)
    } finally {
      setRefreshing(false)
    }
  }, [token, user])

  useEffect(() => {
    loadDashboardData()
  }, [loadDashboardData])

  function persistSession(nextToken, nextUser) {
    localStorage.setItem(TOKEN_KEY, nextToken)
    localStorage.setItem(USER_KEY, JSON.stringify(nextUser))
    setToken(nextToken)
    setUser(nextUser)
  }

  function clearSession(message) {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
    setToken('')
    setUser(null)
    setFiles([])
    setDirectory([])
    setSecurityLogs([])
    setAssessments([])
    setThreatPreview(null)
    setAssignmentDrafts({})
    setStatus(message)
  }

  async function handleLogin(event) {
    event.preventDefault()
    setLoading(true)
    setError('')

    try {
      const result = await request('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify(loginForm),
      })

      persistSession(result.token, result.user)
      setStatus(`Signed in as ${result.user.role}.`)
      scrollToSection('workspace')
    } catch (loginError) {
      setError(loginError.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleRegister(event) {
    event.preventDefault()
    setLoading(true)
    setError('')

    try {
      const result = await request('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify(registerForm),
      })

      setMode('login')
      setRegisterForm(emptyRegisterForm)
      setLoginForm({
        email: result.user.email,
        password: '',
      })
      setStatus(`Account created for ${result.user.email}. You can sign in now.`)
      scrollToSection('access')
    } catch (registerError) {
      setError(registerError.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleUpload(event) {
    event.preventDefault()
    if (!uploadFiles.length) {
      setError('Choose at least one file before uploading.')
      return
    }

    const formData = new FormData()
    for (const file of uploadFiles) {
      formData.append('file', file)
    }

    if (uploadForm.patientId) {
      formData.append('patientId', uploadForm.patientId)
    }
    if (uploadForm.doctorId) {
      formData.append('doctorId', uploadForm.doctorId)
    }

    setLoading(true)
    setError('')

    try {
      await request('/api/file/upload', { method: 'POST', body: formData }, token)
      setUploadFiles([])
      setUploadForm({ patientId: '', doctorId: '' })
      setStatus('Files uploaded successfully.')
      await loadDashboardData()
    } catch (uploadError) {
      setError(uploadError.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleDownload(file) {
    setError('')

    try {
      const response = await fetch(`${API_BASE}/api/file/download/${file._id}`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      })

      if (!response.ok) {
        const payload = await response.json().catch(() => ({}))
        throw new Error(payload.message || 'Download failed')
      }

      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = file.originalName || file.filename
      anchor.click()
      URL.revokeObjectURL(url)
      setStatus(`Downloaded ${file.originalName || file.filename}.`)
    } catch (downloadError) {
      setError(downloadError.message)
    }
  }

  async function handleAssignmentSave(fileId) {
    const draft = assignmentDrafts[fileId]
    if (!draft) {
      return
    }

    setLoading(true)
    setError('')

    try {
      await request(
        `/api/file/${fileId}/assignment`,
        {
          method: 'PATCH',
          body: JSON.stringify({
            patientId: draft.patientId || null,
            doctorId: draft.doctorId || null,
          }),
        },
        token,
      )
      setStatus('File assignment updated.')
      await loadDashboardData()
    } catch (assignmentError) {
      setError(assignmentError.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleAnalyzeLog(logId) {
    setLoading(true)
    setError('')

    try {
      await request(`/api/security/logs/${logId}/analyze`, { method: 'POST' }, token)
      setStatus('Security log analyzed.')
      await loadDashboardData()
    } catch (analysisError) {
      setError(analysisError.message)
    } finally {
      setLoading(false)
    }
  }

  async function handlePreviewThreat(event) {
    event.preventDefault()
    setLoading(true)
    setError('')

    try {
      const preview = await request(
        '/api/security/preview',
        {
          method: 'POST',
          body: JSON.stringify({
            eventType: threatPreviewForm.eventType,
            input: threatPreviewForm.input,
          }),
        },
        token,
      )

      setThreatPreview(preview)
      setStatus('Threat preview generated.')
    } catch (previewError) {
      setError(previewError.message)
    } finally {
      setLoading(false)
    }
  }

  const patients = directory.filter((entry) => entry.role === 'patient')
  const doctors = directory.filter((entry) => entry.role === 'doctor')
  const navSections = user
    ? signedInSections.filter((section) => section.id !== 'security' || user.role === 'admin')
    : guestSections

  return (
    <div className="page-shell">
      <div className="ambient ambient-left" />
      <div className="ambient ambient-right" />

      <header className="topbar">
        <div className="brand-lockup">
          <div className="brand-mark">MT</div>
          <div>
            <p className="eyebrow">Secure Healthcare Data Platform</p>
            <h1 className="brand-title">MedTara Control Center</h1>
          </div>
        </div>

        <nav className="topnav" aria-label="Section navigation">
          {navSections.map((section) => (
            <button
              key={section.id}
              className="nav-link"
              type="button"
              onClick={() => scrollToSection(section.id)}
            >
              {section.label}
            </button>
          ))}
        </nav>

        <div className="topbar-actions">
          {user ? (
            <>
              <span className="role-chip">{user.role}</span>
              <button className="ghost-button" type="button" onClick={loadDashboardData}>
                Refresh
              </button>
              <button
                className="secondary-button"
                type="button"
                onClick={() => clearSession('You have been signed out.')}
              >
                Sign out
              </button>
            </>
          ) : (
            <button className="primary-button" type="button" onClick={() => scrollToSection('access')}>
              Open access portal
            </button>
          )}
        </div>
      </header>

      <div className="app-shell">
      <section className="hero-panel" id="hero">
        <div className="hero-copy">
          <p className="eyebrow accent-eyebrow">Single-page healthcare security workspace</p>
          <h2>Protected records, role-aware access, and TARA visibility in one flow.</h2>
          <p className="hero-text">
            MedTara brings login, file encryption, patient-doctor assignment, audit visibility,
            and threat analysis into one continuous interface connected to your local API.
          </p>

          <div className="hero-actions">
            <button
              className="primary-button"
              type="button"
              onClick={() => scrollToSection(user ? 'workspace' : 'access')}
            >
              {user ? 'Jump to workspace' : 'Start with access'}
            </button>
            <button className="ghost-button" type="button" onClick={() => scrollToSection('capabilities')}>
              Explore capabilities
            </button>
          </div>

          <div className="hero-pills">
            <span className="trust-pill">Encrypted uploads</span>
            <span className="trust-pill">Role-based access</span>
            <span className="trust-pill">Threat-aware operations</span>
          </div>
        </div>

        <div className="hero-side">
          <div className="status-card">
            <span className="status-label">Backend</span>
            <strong>{API_BASE}</strong>
            <p>{status}</p>
          </div>

          <div className="demo-card">
            <span className="status-label">Demo access</span>
            {demoAccounts.map((account) => (
              <button
                key={account.role}
                className="ghost-button"
                type="button"
                onClick={() => {
                  setMode('login')
                  setLoginForm({ email: account.email, password: account.password })
                  setStatus(`${account.role} demo credentials loaded.`)
                }}
              >
                {account.role}: {account.email}
              </button>
            ))}
          </div>
        </div>
      </section>

      {error ? <div className="banner error">{error}</div> : null}
      {refreshing ? <div className="banner info">Refreshing live dashboard data...</div> : null}

      {!token || !user ? (
        <section className="auth-layout" id="access">
          <div className="panel auth-panel">
            <div className="tab-row">
              <button
                type="button"
                className={mode === 'login' ? 'tab active' : 'tab'}
                onClick={() => setMode('login')}
              >
                Sign in
              </button>
              <button
                type="button"
                className={mode === 'register' ? 'tab active' : 'tab'}
                onClick={() => setMode('register')}
              >
                Register
              </button>
            </div>

            {mode === 'login' ? (
              <form className="form-grid" onSubmit={handleLogin}>
                <label>
                  Email
                  <input
                    type="email"
                    value={loginForm.email}
                    onChange={(event) =>
                      setLoginForm((current) => ({ ...current, email: event.target.value }))
                    }
                  />
                </label>
                <label>
                  Password
                  <input
                    type="password"
                    value={loginForm.password}
                    onChange={(event) =>
                      setLoginForm((current) => ({ ...current, password: event.target.value }))
                    }
                  />
                </label>
                <button className="primary-button" type="submit" disabled={loading}>
                  {loading ? 'Signing in...' : 'Sign in'}
                </button>
              </form>
            ) : (
              <form className="form-grid" onSubmit={handleRegister}>
                <label>
                  Full name
                  <input
                    value={registerForm.name}
                    onChange={(event) =>
                      setRegisterForm((current) => ({ ...current, name: event.target.value }))
                    }
                  />
                </label>
                <label>
                  Email
                  <input
                    type="email"
                    value={registerForm.email}
                    onChange={(event) =>
                      setRegisterForm((current) => ({ ...current, email: event.target.value }))
                    }
                  />
                </label>
                <label>
                  Password
                  <input
                    type="password"
                    value={registerForm.password}
                    onChange={(event) =>
                      setRegisterForm((current) => ({ ...current, password: event.target.value }))
                    }
                  />
                </label>
                <label>
                  Role
                  <select
                    value={registerForm.role}
                    onChange={(event) =>
                      setRegisterForm((current) => ({ ...current, role: event.target.value }))
                    }
                  >
                    <option value="patient">Patient</option>
                    <option value="doctor">Doctor</option>
                  </select>
                </label>
                <button className="primary-button" type="submit" disabled={loading}>
                  {loading ? 'Creating account...' : 'Create account'}
                </button>
              </form>
            )}
          </div>

          <div className="panel feature-panel" id="capabilities">
            <p className="eyebrow">Capabilities</p>
            <h2>One page, multiple secure workflows</h2>
            <ul className="feature-list">
              <li>Authenticate users with the existing JWT backend</li>
              <li>Show role-aware file access for patients, doctors, and admins</li>
              <li>Upload encrypted healthcare documents from doctor and admin accounts</li>
              <li>Review suspicious logs and TARA assessments as an admin</li>
            </ul>
          </div>
        </section>
      ) : (
        <>
          <section className="toolbar" id="workspace">
            <div>
              <p className="eyebrow">Signed in</p>
              <h2>
                {user.name} <span className="role-chip">{user.role}</span>
              </h2>
            </div>
            <div className="toolbar-actions">
              <button className="ghost-button" type="button" onClick={() => scrollToSection('records')}>
                View records
              </button>
            </div>
          </section>

          <section className="stats-grid">
            <article className="panel stat-card">
              <span className="status-label">Files visible</span>
              <strong>{files.length}</strong>
            </article>
            <article className="panel stat-card">
              <span className="status-label">Directory entries</span>
              <strong>{directory.length}</strong>
            </article>
            <article className="panel stat-card">
              <span className="status-label">Security logs</span>
              <strong>{securityLogs.length}</strong>
            </article>
            <article className="panel stat-card">
              <span className="status-label">Threat assessments</span>
              <strong>{assessments.length}</strong>
            </article>
          </section>

          {(user.role === 'doctor' || user.role === 'admin') && (
            <section className="panel">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">Secure File Handling</p>
                  <h2>Upload healthcare records</h2>
                </div>
              </div>

              <form className="form-grid upload-grid" onSubmit={handleUpload}>
                <label className="file-picker">
                  Select up to 5 files
                  <input
                    type="file"
                    multiple
                    accept=".pdf,.jpg,.jpeg,.png"
                    onChange={(event) => setUploadFiles(Array.from(event.target.files ?? []))}
                  />
                </label>

                <label>
                  Patient assignment
                  <select
                    value={uploadForm.patientId}
                    onChange={(event) =>
                      setUploadForm((current) => ({ ...current, patientId: event.target.value }))
                    }
                  >
                    <option value="">Choose patient</option>
                    {patients.map((patient) => (
                      <option key={patient._id} value={patient._id}>
                        {patient.name} ({patient.email})
                      </option>
                    ))}
                  </select>
                </label>

                {user.role === 'admin' ? (
                  <label>
                    Doctor assignment
                    <select
                      value={uploadForm.doctorId}
                      onChange={(event) =>
                        setUploadForm((current) => ({ ...current, doctorId: event.target.value }))
                      }
                    >
                      <option value="">Choose doctor</option>
                      {doctors.map((doctor) => (
                        <option key={doctor._id} value={doctor._id}>
                          {doctor.name} ({doctor.email})
                        </option>
                      ))}
                    </select>
                  </label>
                ) : null}

                <button className="primary-button" type="submit" disabled={loading}>
                  {loading ? 'Uploading...' : 'Upload files'}
                </button>
              </form>

              {uploadFiles.length ? (
                <p className="subtle-text">
                  Ready: {uploadFiles.map((file) => file.name).join(', ')}
                </p>
              ) : null}
            </section>
          )}

          {(user.role === 'doctor' || user.role === 'admin') && (
            <section className="panel">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">User Directory</p>
                  <h2>Patients and clinicians</h2>
                </div>
              </div>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Email</th>
                      <th>Role</th>
                    </tr>
                  </thead>
                  <tbody>
                    {directory.map((entry) => (
                      <tr key={entry._id}>
                        <td>{entry.name}</td>
                        <td>{entry.email}</td>
                        <td>{entry.role}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          <section className="panel" id="records">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Records</p>
                <h2>Accessible healthcare files</h2>
              </div>
            </div>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>File</th>
                    <th>Patient</th>
                    <th>Doctor</th>
                    <th>Uploaded by</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {files.map((file) => {
                    const draft = assignmentDrafts[file._id] ?? {
                      patientId: file.patient?._id ?? '',
                      doctorId: file.doctor?._id ?? '',
                    }

                    return (
                      <tr key={file._id}>
                        <td>
                          <strong>{file.originalName || file.filename}</strong>
                          <p className="cell-meta">{file.mimeType || 'unknown type'}</p>
                        </td>
                        <td>{file.patient?.name ?? 'Unassigned'}</td>
                        <td>{file.doctor?.name ?? 'Unassigned'}</td>
                        <td>{file.uploadedBy?.name ?? 'Unknown'}</td>
                        <td>
                          <div className="action-stack">
                            <button
                              className="secondary-button"
                              type="button"
                              onClick={() => handleDownload(file)}
                            >
                              Download
                            </button>

                            {user.role === 'admin' ? (
                              <div className="assignment-row">
                                <select
                                  value={draft.patientId}
                                  onChange={(event) =>
                                    setAssignmentDrafts((current) => ({
                                      ...current,
                                      [file._id]: {
                                        ...draft,
                                        patientId: event.target.value,
                                      },
                                    }))
                                  }
                                >
                                  <option value="">No patient</option>
                                  {patients.map((patient) => (
                                    <option key={patient._id} value={patient._id}>
                                      {patient.name}
                                    </option>
                                  ))}
                                </select>
                                <select
                                  value={draft.doctorId}
                                  onChange={(event) =>
                                    setAssignmentDrafts((current) => ({
                                      ...current,
                                      [file._id]: {
                                        ...draft,
                                        doctorId: event.target.value,
                                      },
                                    }))
                                  }
                                >
                                  <option value="">No doctor</option>
                                  {doctors.map((doctor) => (
                                    <option key={doctor._id} value={doctor._id}>
                                      {doctor.name}
                                    </option>
                                  ))}
                                </select>
                                <button
                                  className="ghost-button"
                                  type="button"
                                  onClick={() => handleAssignmentSave(file._id)}
                                >
                                  Save
                                </button>
                              </div>
                            ) : null}
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </section>
          {user.role === 'admin' ? (
            <section className="admin-grid" id="security">
              <div className="panel">
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">Security Monitoring</p>
                    <h2>Event logs</h2>
                  </div>
                </div>
                <div className="log-list">
                  {securityLogs.map((log) => (
                    <article className="log-card" key={log._id}>
                      <div className="log-header">
                        <strong>{log.action}</strong>
                        <button
                          className="ghost-button"
                          type="button"
                          onClick={() => handleAnalyzeLog(log._id)}
                        >
                          Analyze
                        </button>
                      </div>
                      <p>{log.user?.email ?? 'Unknown user'}</p>
                      <p className="cell-meta">
                        {log.ip ?? 'No IP'} • {formatDate(log.createdAt)}
                      </p>
                    </article>
                  ))}
                </div>
              </div>

              <div className="panel">
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">TARA</p>
                    <h2>Manual threat preview</h2>
                  </div>
                </div>

                <form className="form-grid" onSubmit={handlePreviewThreat}>
                  <label>
                    Event type
                    <input
                      value={threatPreviewForm.eventType}
                      onChange={(event) =>
                        setThreatPreviewForm((current) => ({
                          ...current,
                          eventType: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <label>
                    Suspicious input
                    <textarea
                      rows="6"
                      value={threatPreviewForm.input}
                      onChange={(event) =>
                        setThreatPreviewForm((current) => ({
                          ...current,
                          input: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <button className="primary-button" type="submit" disabled={loading}>
                    {loading ? 'Previewing...' : 'Preview threat'}
                  </button>
                </form>

                {threatPreview ? (
                  <div className="preview-card">
                    <p className="eyebrow">{threatPreview.severity} severity</p>
                    <h3>{threatPreview.attackType}</h3>
                    <p>{threatPreview.summary}</p>
                    <p className="subtle-text">Risk score: {threatPreview.riskScore}</p>
                  </div>
                ) : null}
              </div>

              <div className="panel admin-span">
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">Assessments</p>
                    <h2>Latest threat findings</h2>
                  </div>
                </div>
                <div className="assessment-grid">
                  {assessments.map((assessment) => (
                    <article className="assessment-card" key={assessment._id}>
                      <div className="assessment-top">
                        <span className={`severity-pill severity-${assessment.severity}`}>
                          {assessment.severity}
                        </span>
                        <strong>{assessment.attackType}</strong>
                      </div>
                      <p>{assessment.summary}</p>
                      <p className="cell-meta">Event: {assessment.eventType}</p>
                      <p className="cell-meta">Risk score: {assessment.riskScore}</p>
                    </article>
                  ))}
                </div>
              </div>
            </section>
          ) : null}
        </>
      )}
      </div>
    </div>
  )
}

export default App
