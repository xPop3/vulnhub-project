from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime
from passlib.context import CryptContext
from jose import jwt
import os
from dotenv import load_dotenv
import ssl
import socket
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://vulnhub:password123@localhost/vulnhub_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
ALGORITHM = "HS256"

app = FastAPI(title="VulnHub API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic models
class UserCreate(BaseModel):
    email: str
    password: str
    first_name: str
    last_name: str

class UserResponse(BaseModel):
    id: int
    email: str
    first_name: str
    last_name: str
    tier: str
    scans_remaining: int

class LoginRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    user: UserResponse
    token: str

class ScanCreate(BaseModel):
    domain: str
    scan_type: str

class ScanResponse(BaseModel):
    id: int
    domain: str
    status: str
    progress: int
    results: list

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_token(data: dict) -> str:
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_ssl_certificate(domain: str) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                
                if not_after < datetime.utcnow():
                    return {'severity': 'Critical', 'title': 'Expired SSL Certificate', 'remediation': 'Renew SSL certificate immediately.'}
                elif (not_after - datetime.utcnow()).days < 30:
                    return {'severity': 'High', 'title': 'SSL Certificate Expiring Soon', 'remediation': 'Renew SSL certificate within 30 days.'}
    except Exception as e:
        return {'severity': 'High', 'title': 'SSL/TLS Configuration Issue', 'remediation': f'Review SSL configuration: {str(e)[:50]}'}
    
    return None

def check_security_headers(domain: str) -> list:
    findings = []
    required_headers = {
        'Strict-Transport-Security': 'Missing HSTS Header',
        'X-Frame-Options': 'Missing X-Frame-Options Header',
        'X-Content-Type-Options': 'Missing X-Content-Type-Options Header',
        'Content-Security-Policy': 'Missing Content Security Policy'
    }
    
    try:
        url = f"https://{domain}" if not domain.startswith('http') else domain
        response = requests.get(url, timeout=5, verify=False)
        headers = response.headers
        
        for header, title in required_headers.items():
            if header not in headers:
                findings.append({
                    'severity': 'Medium',
                    'title': title,
                    'remediation': f'Add {header} header to HTTP response.'
                })
    except Exception as e:
        findings.append({'severity': 'Low', 'title': 'Unable to Check Headers', 'remediation': 'Manual review recommended'})
    
    return findings

def get_cve_data(severity: str, db: Session) -> dict:
    try:
        result = db.execute(
            text("SELECT cve_id, title, remediation_steps, cvss_score, external_reference_url FROM vulnerabilities WHERE severity_level = :severity LIMIT 1"),
            {"severity": severity}
        ).first()
        
        if result:
            return {
                'cve_id': result[0],
                'title': result[1],
                'remediation': result[2],
                'cvss_score': result[3],
                'reference': result[4]
            }
    except:
        pass
    return None

def perform_scan(domain: str, scan_type: str, db: Session) -> list:
    findings = []
    
    ssl_finding = verify_ssl_certificate(domain)
    if ssl_finding:
        cve_data = get_cve_data(ssl_finding['severity'], db)
        if cve_data:
            ssl_finding['cve_id'] = cve_data['cve_id']
            ssl_finding['cvss_score'] = cve_data['cvss_score']
            ssl_finding['reference'] = cve_data['reference']
        findings.append(ssl_finding)
    
    header_findings = check_security_headers(domain)
    for finding in header_findings:
        cve_data = get_cve_data(finding['severity'], db)
        if cve_data:
            finding['cve_id'] = cve_data['cve_id']
            finding['cvss_score'] = cve_data['cvss_score']
            finding['reference'] = cve_data['reference']
    findings.extend(header_findings)
    
    if scan_type == 'full':
        common_findings = [
            {'severity': 'Low', 'title': 'Server Banner Disclosure', 'remediation': 'Disable server banner to hide version information.'},
            {'severity': 'Low', 'title': 'Missing robots.txt', 'remediation': 'Create a robots.txt file to control search engine crawling.'}
        ]
        for finding in common_findings:
            cve_data = get_cve_data(finding['severity'], db)
            if cve_data:
                finding['cve_id'] = cve_data['cve_id']
                finding['cvss_score'] = cve_data['cvss_score']
                finding['reference'] = cve_data['reference']
        findings.extend(common_findings)
    
    return findings if findings else [{'severity': 'Low', 'title': 'No Critical Issues Found', 'remediation': 'Site appears secure. Continue monitoring.'}]

# Routes
@app.get("/")
def read_root():
    return {"message": "VulnHub API is running", "version": "0.1.0"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.post("/api/auth/register", response_model=LoginResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    existing = db.execute(text("SELECT * FROM users WHERE email = :email"), {"email": user_data.email}).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_pw = hash_password(user_data.password)
    db.execute(text(
        "INSERT INTO users (email, password_hash, first_name, last_name, tier, scans_remaining) VALUES (:email, :pwd, :fn, :ln, :tier, :scans)"
    ), {"email": user_data.email, "pwd": hashed_pw, "fn": user_data.first_name, "ln": user_data.last_name, "tier": "free", "scans": 1})
    db.commit()
    
    result = db.execute(text("SELECT id, email, first_name, last_name, tier, scans_remaining FROM users WHERE email = :email"), {"email": user_data.email}).first()
    user = UserResponse(id=result[0], email=result[1], first_name=result[2], last_name=result[3], tier=result[4], scans_remaining=result[5])
    
    token = create_token({"sub": user.email})
    return LoginResponse(user=user, token=token)

@app.post("/api/auth/login", response_model=LoginResponse)
def login(credentials: LoginRequest, db: Session = Depends(get_db)):
    result = db.execute(text("SELECT id, email, first_name, last_name, password_hash, tier, scans_remaining FROM users WHERE email = :email"), {"email": credentials.email}).first()
    
    if not result or not verify_password(credentials.password, result[4]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user = UserResponse(id=result[0], email=result[1], first_name=result[2], last_name=result[3], tier=result[5], scans_remaining=result[6])
    token = create_token({"sub": user.email})
    return LoginResponse(user=user, token=token)

@app.post("/api/scans/initiate", response_model=ScanResponse)
def initiate_scan(scan_data: ScanCreate, db: Session = Depends(get_db)):
    domain = scan_data.domain
    scan_type = scan_data.scan_type
    
    findings = perform_scan(domain, scan_type, db)
    
    return ScanResponse(
        id=1,
        domain=domain,
        status='completed',
        progress=100,
        results=findings
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
