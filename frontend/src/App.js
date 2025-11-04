import React, { useState } from 'react';
import './App.css';

const API_BASE = "http://localhost:8000/api";

function App() {
  const [currentPage, setCurrentPage] = useState('login');
  const [user, setUser] = useState(null);
  const [scans, setScans] = useState([]);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [domainInput, setDomainInput] = useState('');
  const [scanType, setScanType] = useState('basic');
  const [selectedScan, setSelectedScan] = useState(null);

  const handleLogin = (e) => {
    e.preventDefault();
    if (email && password) {
      fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      })
        .then(res => res.json())
        .then(data => {
          if (data.user) {
            setUser(data.user);
            localStorage.setItem('token', data.token);
            setCurrentPage('dashboard');
            setEmail('');
            setPassword('');
          } else {
            alert('Login failed: ' + (data.detail || 'Unknown error'));
          }
        })
        .catch(err => alert('Error: ' + err.message));
    }
  };

  const handleRegister = (e) => {
    e.preventDefault();
    if (email && password && firstName && lastName) {
      fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, first_name: firstName, last_name: lastName })
      })
        .then(res => res.json())
        .then(data => {
          if (data.user) {
            setUser(data.user);
            localStorage.setItem('token', data.token);
            setCurrentPage('dashboard');
            setEmail('');
            setPassword('');
            setFirstName('');
            setLastName('');
          } else {
            alert('Registration failed: ' + (data.detail || 'Unknown error'));
          }
        })
        .catch(err => alert('Error: ' + err.message));
    }
  };

  const handleInitiateScan = (e) => {
    e.preventDefault();
    if (domainInput && user.scans_remaining > 0) {
      const token = localStorage.getItem('token');
      
      fetch(`${API_BASE}/scans/initiate`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ domain: domainInput, scan_type: scanType })
      })
        .then(res => res.json())
        .then(data => {
          const newScan = {
            id: scans.length + 1,
            domain: data.domain,
            type: scanType,
            status: data.status,
            startTime: new Date().toLocaleTimeString(),
            progress: data.progress,
            results: data.results
          };
          
          setScans([newScan, ...scans]);
          setUser({ ...user, scans_remaining: user.scans_remaining - 1 });
          setDomainInput('');
        })
        .catch(err => alert('Scan failed: ' + err.message));
    }
  };

  const handleLogout = () => {
    setUser(null);
    setCurrentPage('login');
    setScans([]);
    localStorage.removeItem('token');
  };

  return (
    <div className="app">
      {currentPage === 'login' && !user && (
        <div className="auth-container">
          <div className="auth-box">
            <div className="logo"><span className="vuln">Vuln</span><span className="hub">Hub</span></div>
            <p className="tagline">Automated Security Scanning</p>
            <form onSubmit={handleLogin}>
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              <button type="submit" className="btn-primary">Login</button>
            </form>
            <p className="toggle-auth">
              Don't have an account? <a onClick={() => setCurrentPage('register')}>Register</a>
            </p>
          </div>
        </div>
      )}

      {currentPage === 'register' && !user && (
        <div className="auth-container">
          <div className="auth-box">
            <div className="logo"><span className="vuln">Vuln</span><span className="hub">Hub</span></div>
            <p className="tagline">Create Your Account</p>
            <form onSubmit={handleRegister}>
              <input
                type="text"
                placeholder="First Name"
                value={firstName}
                onChange={(e) => setFirstName(e.target.value)}
                required
              />
              <input
                type="text"
                placeholder="Last Name"
                value={lastName}
                onChange={(e) => setLastName(e.target.value)}
                required
              />
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              <button type="submit" className="btn-primary">Register</button>
            </form>
            <p className="toggle-auth">
              Already have an account? <a onClick={() => setCurrentPage('login')}>Login</a>
            </p>
          </div>
        </div>
      )}

      {user && (
        <div className="dashboard">
          <header className="navbar">
            <div className="navbar-content">
              <div className="logo-nav"><span className="vuln">Vuln</span><span className="hub">Hub</span></div>
              <div className="user-menu">
                <span>{user.email}</span>
                <span className="tier-badge">{user.tier}</span>
                <button onClick={handleLogout} className="btn-logout">Logout</button>
              </div>
            </div>
          </header>

          <div className="dashboard-container">
            <div className="scan-section">
              <h2>Initiate Scan</h2>
              <form onSubmit={handleInitiateScan} className="scan-form">
                <div className="form-group">
                  <label>Domain or IP</label>
                  <input
                    type="text"
                    placeholder="example.com or 192.168.1.1"
                    value={domainInput}
                    onChange={(e) => setDomainInput(e.target.value)}
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Scan Type</label>
                  <select value={scanType} onChange={(e) => setScanType(e.target.value)}>
                    <option value="basic">Basic Scan</option>
                    <option value="full">Full Depth Scan</option>
                  </select>
                </div>
                <div className="scan-info">
                  <p>Scans Remaining: <strong>{user.scans_remaining}</strong></p>
                </div>
                <button type="submit" className="btn-primary" disabled={user.scans_remaining === 0}>
                  Start Scan
                </button>
              </form>
            </div>

            <div className="results-section">
              <h2>Recent Scans</h2>
              {scans.length === 0 ? (
                <p className="empty-state">No scans yet. Start by initiating a scan above.</p>
              ) : (
                <div className="scans-list">
                  {scans.map(scan => (
                    <div key={scan.id} className="scan-item">
                      <div className="scan-header">
                        <div>
                          <h3>{scan.domain}</h3>
                          <p>Type: {scan.type} | Started: {scan.startTime}</p>
                        </div>
                        <div className={`status-badge ${scan.status}`}>
                          {scan.status === 'in_progress' ? `⟳ ${Math.round(scan.progress || 0)}%` : '✓ Complete'}
                        </div>
                      </div>
                      {scan.status === 'in_progress' && (
                        <div className="progress-bar">
                          <div className="progress-fill" style={{ width: `${scan.progress || 0}%` }}></div>
                        </div>
                      )}
                      {scan.status === 'completed' && (
                        <button 
                          className="btn-view-report"
                          onClick={() => setSelectedScan(scan)}
                        >
                          View Report ({scan.results.length} findings)
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {selectedScan && (
            <div className="modal-overlay" onClick={() => setSelectedScan(null)}>
              <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <button className="close-btn" onClick={() => setSelectedScan(null)}>×</button>
                <h2>Scan Report - {selectedScan.domain}</h2>
                <div className="vulnerabilities-list">
                  {selectedScan.results.map((vuln, idx) => (
                    <div key={idx} className={`vuln-item severity-${vuln.severity.toLowerCase()}`}>
                      <div className="vuln-header">
                        <span className="severity-badge">{vuln.severity}</span>
                        <h4>{vuln.title}</h4>
                      </div>
                      {vuln.cve_id && <p className="cve-id"><strong>CVE ID:</strong> <a href={vuln.reference} target="_blank" rel="noopener noreferrer">{vuln.cve_id}</a></p>}
                      {vuln.cvss_score && <p className="cvss-score"><strong>CVSS Score:</strong> {vuln.cvss_score}/10</p>}
                      <p className="remediation"><strong>Remediation:</strong> {vuln.remediation}</p>
                      <p className="disclaimer">⚠️ All recommendations are advisory only. Test before implementing.</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
