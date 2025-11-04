import requests
import json
from datetime import datetime
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://vulnhub:@localhost/vulnhub_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Common web vulnerabilities to add
COMMON_CVES = [
    {
        'cve_id': 'CVE-2023-44487',
        'title': 'HTTP/2 Rapid Reset Attack',
        'description': 'HTTP/2 allows Denial of Service via a rapid sequence of RST_STREAM frames',
        'severity': 'High',
        'check_type': 'ssl_tls',
        'remediation': 'Update to latest patched version of HTTP/2 implementation. Ensure rate limiting on RST_STREAM frames.',
        'affected_software': 'OpenSSL, Nginx, Apache',
        'cvss_score': 7.5,
        'external_reference': 'https://nvd.nist.gov/vuln/detail/CVE-2023-44487'
    },
    {
        'cve_id': 'CVE-2021-44228',
        'title': 'Apache Log4j Remote Code Execution',
        'description': 'Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints',
        'severity': 'Critical',
        'check_type': 'framework_vulnerability',
        'remediation': 'Upgrade Log4j to version 2.17.1 or later. Disable JNDI lookups by setting log4j.formatMsgNoLookups to true.',
        'affected_software': 'Apache Log4j 2.0-beta9 through 2.15.0',
        'cvss_score': 10.0,
        'external_reference': 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'
    },
    {
        'cve_id': 'CVE-2022-3786',
        'title': 'OpenSSL X.509 Email Address Buffer Overflow',
        'description': 'A buffer overflow was found in the processing of X.509 email addresses',
        'severity': 'High',
        'check_type': 'ssl_cert',
        'remediation': 'Update OpenSSL to version 3.0.7 or 1.1.1s or later.',
        'affected_software': 'OpenSSL 3.0.0 through 3.0.6, 1.1.1 through 1.1.1r',
        'cvss_score': 7.5,
        'external_reference': 'https://nvd.nist.gov/vuln/detail/CVE-2022-3786'
    },
    {
        'cve_id': 'CVE-2023-21830',
        'title': 'Oracle WebLogic Authentication Bypass',
        'description': 'Vulnerability in Oracle WebLogic Server allows unauthenticated attacker to cause denial of service',
        'severity': 'High',
        'check_type': 'misconfiguration',
        'remediation': 'Apply Oracle WebLogic Server security patches. Enable authentication on all admin consoles.',
        'affected_software': 'Oracle WebLogic Server 14.1.1, 12.2.1.3-4, 12.1.4.0',
        'cvss_score': 7.5,
        'external_reference': 'https://nvd.nist.gov/vuln/detail/CVE-2023-21830'
    },
    {
        'cve_id': 'CVE-2022-41080',
        'title': 'Microsoft Exchange Server Remote Code Execution',
        'description': 'Microsoft Exchange Server contains a remote code execution vulnerability in the processing of email messages',
        'severity': 'Critical',
        'check_type': 'misconfiguration',
        'remediation': 'Update Microsoft Exchange Server to latest patch. Apply KB5016191 or later.',
        'affected_software': 'Exchange Server 2013, 2016, 2019, 2022',
        'cvss_score': 8.8,
        'external_reference': 'https://nvd.nist.gov/vuln/detail/CVE-2022-41080'
    },
    {
        'cve_id': 'CVE-2023-34362',
        'title': 'MOVEit Transfer Remote Code Execution',
        'description': 'Progress MOVEit Transfer contains an SQL injection vulnerability that allows remote code execution',
        'severity': 'Critical',
        'check_type': 'sql_injection',
        'remediation': 'Update MOVEit Transfer to version 2023.0.0 or later. Apply security patches immediately.',
        'affected_software': 'Progress MOVEit Transfer versions before 2023.0.0',
        'cvss_score': 9.8,
        'external_reference': 'https://nvd.nist.gov/vuln/detail/CVE-2023-34362'
    },
    {
        'cve_id': 'CVE-2022-0585',
        'title': 'WordPress Plugin Vulnerability - SQL Injection',
        'description': 'Multiple WordPress plugins contain SQL injection vulnerabilities',
        'severity': 'High',
        'check_type': 'outdated_plugin',
        'remediation': 'Update all WordPress plugins to latest versions. Remove unused plugins.',
        'affected_software': 'WordPress plugins (various)',
        'cvss_score': 7.5,
        'external_reference': 'https://nvd.nist.gov/vuln/detail/CVE-2022-0585'
    },
    {
        'cve_id': 'CVE-2023-20198',
        'title': 'Cisco IOS XE Software Command Injection',
        'description': 'Cisco IOS XE Software contains a command injection vulnerability',
        'severity': 'Critical',
        'check_type': 'misconfiguration',
        'remediation': 'Update Cisco IOS XE to patched version. Disable telnet, use SSH only.',
        'affected_software': 'Cisco IOS XE Software',
        'cvss_score': 9.8,
        'external_reference': 'https://nvd.nist.gov/vuln/detail/CVE-2023-20198'
    },
    {
        'cve_id': 'CVE-2022-46163',
        'title': 'Fortinet FortiOS Authentication Bypass',
        'description': 'Fortinet FortiOS contains an authentication bypass vulnerability',
        'severity': 'High',
        'check_type': 'misconfiguration',
        'remediation': 'Update FortiOS to latest patched version. Enable MFA on all admin accounts.',
        'affected_software': 'Fortinet FortiOS 7.0.0 through 7.0.10, 7.2.0 through 7.2.3',
        'cvss_score': 7.2,
        'external_reference': 'https://nvd.nist.gov/vuln/detail/CVE-2022-46163'
    },
    {
        'cve_id': 'CVE-2023-25690',
        'title': 'Apache HTTP Server Request Splitting',
        'description': 'Apache HTTP Server contains a request splitting vulnerability',
        'severity': 'Medium',
        'check_type': 'misconfiguration',
        'remediation': 'Update Apache HTTP Server to version 2.4.56 or later.',
        'affected_software': 'Apache HTTP Server 2.4.0 through 2.4.55',
        'cvss_score': 6.1,
        'external_reference': 'https://nvd.nist.gov/vuln/detail/CVE-2023-25690'
    }
]

def populate_cves():
    db = SessionLocal()
    try:
        for cve in COMMON_CVES:
            # Check if CVE already exists
            result = db.execute(
                text("SELECT id FROM vulnerabilities WHERE cve_id = :cve_id"),
                {"cve_id": cve['cve_id']}
            ).first()
            
            if not result:
                # Insert new CVE
                db.execute(
                    text("""
                        INSERT INTO vulnerabilities 
                        (cve_id, title, description, severity_level, check_type, remediation_steps, 
                         affected_software, cvss_score, external_reference_url, created_at, last_updated)
                        VALUES (:cve_id, :title, :desc, :severity, :check_type, :remediation, 
                                :software, :cvss, :url, :created, :updated)
                    """),
                    {
                        'cve_id': cve['cve_id'],
                        'title': cve['title'],
                        'desc': cve['description'],
                        'severity': cve['severity'],
                        'check_type': cve['check_type'],
                        'remediation': cve['remediation'],
                        'software': cve['affected_software'],
                        'cvss': cve['cvss_score'],
                        'url': cve['external_reference'],
                        'created': datetime.utcnow(),
                        'updated': datetime.utcnow()
                    }
                )
        
        db.commit()
        print(f"✓ Successfully populated {len(COMMON_CVES)} CVEs into database")
        
    except Exception as e:
        print(f"✗ Error populating CVEs: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    populate_cves()
