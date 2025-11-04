-- VulnHub Database Schema (Fixed Order)

-- Users Table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    tier VARCHAR(50) DEFAULT 'free', -- free, premium_1, premium_2, premium_3
    subscription_status VARCHAR(50) DEFAULT 'active', -- active, inactive, cancelled
    subscription_start_date TIMESTAMP,
    subscription_end_date TIMESTAMP,
    scans_remaining INT DEFAULT 1, -- For free/premium_1 tier limits
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan Targets Table (domains/IPs to scan)
CREATE TABLE scan_targets (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    domain_or_ip VARCHAR(255) NOT NULL,
    target_type VARCHAR(50), -- 'domain' or 'ip'
    is_public_facing BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Vulnerabilities Database (CVE library) - CREATE THIS BEFORE scan_results
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) UNIQUE, -- e.g., CVE-2024-1234
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity_level VARCHAR(50), -- Critical, High, Medium, Low, Info
    check_type VARCHAR(100), -- 'ssl_cert', 'outdated_plugin', 'misconfiguration', etc.
    remediation_steps TEXT, -- Detailed fix instructions
    affected_software VARCHAR(255), -- e.g., 'WordPress 5.0-5.8'
    cvss_score FLOAT, -- CVSS severity score
    external_reference_url VARCHAR(255), -- Link to NVD or other source
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scans Table (scan history/records)
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    target_id INT NOT NULL,
    scan_type VARCHAR(50), -- 'basic' or 'full_depth'
    status VARCHAR(50) DEFAULT 'pending', -- pending, in_progress, completed, failed
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    is_scheduled BOOLEAN DEFAULT FALSE,
    schedule_frequency VARCHAR(50), -- 'daily', 'weekly', 'monthly' (for premium_2+)
    next_scheduled_run TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (target_id) REFERENCES scan_targets(id) ON DELETE CASCADE
);

-- Vulnerabilities Found Table (results from scans)
CREATE TABLE scan_results (
    id SERIAL PRIMARY KEY,
    scan_id INT NOT NULL,
    vulnerability_id INT NOT NULL,
    severity_level VARCHAR(50), -- Critical, High, Medium, Low, Info
    detected_value VARCHAR(255), -- What was actually found (e.g., SSL version)
    status VARCHAR(50) DEFAULT 'open', -- open, resolved, accepted_risk
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

-- Scan Report Table (generated reports for users)
CREATE TABLE scan_reports (
    id SERIAL PRIMARY KEY,
    scan_id INT NOT NULL,
    report_content TEXT, -- JSON or formatted report
    report_type VARCHAR(50), -- 'basic' or 'full_depth'
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Billing/Subscription Table
CREATE TABLE subscriptions (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    tier VARCHAR(50) NOT NULL, -- free, premium_1, premium_2, premium_3
    price_per_month DECIMAL(10, 2),
    max_scans_per_month INT, -- NULL for unlimited
    features TEXT, -- JSON list of features
    payment_status VARCHAR(50) DEFAULT 'pending', -- pending, paid, failed
    renewal_date TIMESTAMP,
    cancel_date TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Audit Log Table (for tracking user actions)
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    action VARCHAR(255), -- e.g., 'scan_initiated', 'report_downloaded'
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_scan_targets_user_id ON scan_targets(user_id);
CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scan_results_scan_id ON scan_results(scan_id);
CREATE INDEX idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
