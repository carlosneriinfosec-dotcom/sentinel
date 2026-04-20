from fastapi import FastAPI, Depends, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, JSON, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
import datetime
from typing import List, Optional
import json
import os
import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
from reportlab.lib.units import inch

# --- CONFIGURAÇÕES ---
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DATA_PATH = os.getenv("DATA_PATH", "../../data/knowledge_base.json")

if DB_USER and DB_PASSWORD and DB_HOST and DB_NAME:
    SQLALCHEMY_DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
else:
    SQLALCHEMY_DATABASE_URL = "sqlite:///./sentinel_v6.db"
    engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- MODELOS ---
class KnowledgeBase(Base):
    __tablename__ = "knowledge_base"
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, unique=True, index=True)
    title = Column(String)
    description = Column(String)
    content = Column(String)
    severity = Column(String, default="Médio")
    verification_instructions = Column(String)
    rules = Column(JSON)
    mapping = Column(JSON)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class RequirementStatus(Base):
    __tablename__ = "requirement_status"
    id = Column(Integer, primary_key=True, index=True)
    requirement_code = Column(String, unique=True, index=True)
    status = Column(String, default="Pendente")
    notes = Column(String, default="")
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)

# --- FastAPI SETUP ---
app = FastAPI(title="Sentinel SRaC API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

class StatusUpdate(BaseModel):
    status: str
    notes: Optional[str] = ""

# --- ENDPOINTS ---
@app.get("/requirements", response_model=List[dict])
def get_requirements(
    language: str, pii_data: bool = False, database: str = "sql",
    web_api: bool = False, web_frontend: bool = False,
    mobile_app: bool = False, business_criticality: str = "media",
    top10_only: bool = False, rigor: str = "essencial",
    db: Session = Depends(get_db)
):
    all_requirements = db.query(KnowledgeBase).all()
    
    INTEL_MATRIX = {
        "java": {"A08:2021": 2.0, "CWE-502": 2.0, "A06:2021": 1.5},
        "dotnet": {"A03:2021": 1.5, "A05:2021": 1.5, "XXE": 2.0},
        "javascript": {"XSS": 2.0, "A01:2021": 1.5, "A03:2021": 1.5},
        "python": {"A08:2021": 1.5, "A03:2021": 1.5},
        "php": {"A03:2021": 2.0, "RCE": 2.0, "A01:2021": 2.0},
        "c_cpp": {"BUFFER": 2.0, "MEMORY": 2.0},
        "go": {"RACE": 1.5}, "ruby": {"A08:2021": 2.0}
    }
    
    context = {"language": language, "pii_data": pii_data, "database": database, "web_api": web_api, "web_frontend": web_frontend, "mobile_app": mobile_app}
    
    filtered = []
    for req in all_requirements:
        if top10_only and (not req.mapping or "OWASP" not in str(req.mapping).upper()): continue
        
        if rigor == "essencial":
            is_critical = req.severity == "Crítico"
            is_owasp = req.mapping and "OWASP" in str(req.mapping).upper()
            if not (is_critical or is_owasp): continue
        elif rigor == "padrao" and req.severity == "Baixo": continue
        
        match = True
        rules = req.rules or {}
        for k, v in rules.items():
            user_val = context.get(k)
            if k == "language" and v != language: match = False; break
            if k == "database":
                if isinstance(v, str) and v != user_val: match = False; break
                elif v is True and user_val is False: match = False; break
            elif isinstance(v, bool) and v and user_val is False: match = False; break
        
        if match:
            category = "Sistema"
            mapping_str = str(req.mapping).upper()
            title_upper = req.title.upper()
            if "MASVS" in mapping_str or "ROOT" in req.title.upper(): category = "Mobile"
            elif "API" in mapping_str or "ASVS-V13" in req.code or "13." in mapping_str: category = "API"

            severity = req.severity
            lang_intel = INTEL_MATRIX.get(language.lower(), {})
            boost = 1.0
            for vk, w in lang_intel.items():
                if vk.upper() in mapping_str: boost = max(boost, w)
            
            if boost >= 2.0:
                if severity == "Alto": severity = "Crítico"
                elif severity == "Médio": severity = "Alto"
                elif severity == "Baixo": severity = "Médio"
            elif boost >= 1.5:
                if severity == "Médio": severity = "Alto"
                elif severity == "Baixo": severity = "Médio"

            status_obj = db.query(RequirementStatus).filter(RequirementStatus.requirement_code == req.code).first()
            filtered.append({
                "id": req.code, "title": req.title, "category": category, "description": req.description,
                "content": req.content, "severity": severity, "verification": req.verification_instructions,
                "mapping": req.mapping, "status": status_obj.status if status_obj else "Pendente", "notes": status_obj.notes if status_obj else ""
            })
            
    weights = { "Crítico": 4, "Alto": 3, "Médio": 2, "Baixo": 1 }
    filtered.sort(key=lambda x: weights.get(x["severity"], 0), reverse=True)
    return filtered

@app.post("/requirements/{code}/status")
def update_status(code: str, data: StatusUpdate, db: Session = Depends(get_db)):
    s = db.query(RequirementStatus).filter(RequirementStatus.requirement_code == code).first()
    if not s: 
        s = RequirementStatus(requirement_code=code)
        db.add(s)
    s.status = data.status
    s.notes = data.notes
    db.commit()
    return {"ok": True}

from xml.sax.saxutils import escape

@app.get("/export/pdf")
def export_pdf(
    language: str, pii_data: bool = False, database: str = "sql",
    web_api: bool = False, web_frontend: bool = False,
    mobile_app: bool = False, business_criticality: str = "media",
    top10_only: bool = False, rigor: str = "essencial",
    db: Session = Depends(get_db)
):
    """Gera um relatório PDF com os requisitos filtrados."""
    requirements = get_requirements(
        language, pii_data, database, web_api, web_frontend, mobile_app, 
        business_criticality, top10_only, rigor, db
    )
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Estilos customizados
    title_style = styles['Heading1']
    subtitle_style = styles['Heading2']
    body_style = styles['BodyText']
    
    elements = []
    
    # Cabeçalho
    elements.append(Paragraph(escape("Relatório de Requisitos de Segurança - LeftArrow"), title_style))
    elements.append(Paragraph(escape(f"Gerado em: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"), body_style))
    
    # Cálculo de Risco para o PDF
    severity_counts = {"Crítico": 0, "Alto": 0, "Médio": 0, "Baixo": 0}
    for r in requirements:
        sev = r.get("severity", "Médio")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    risk_summary = f"<b>Resumo de Risco:</b> {severity_counts['Crítico']} Críticos, {severity_counts['Alto']} Altos, {severity_counts['Médio']} Médios"
    elements.append(Paragraph(risk_summary, body_style))
    elements.append(Spacer(1, 0.25 * inch))
    
    current_cat = None
    for req in requirements:
        # Seção por Categoria
        if req['category'] != current_cat:
            current_cat = req['category']
            cat_label = { "Mobile": "SEGURANÇA MOBILE", "API": "SEGURANÇA DE APIS", "Sistema": "SEGURANÇA DE SISTEMA" }.get(current_cat, current_cat)
            elements.append(Spacer(1, 0.2 * inch))
            elements.append(Paragraph(f"--- {escape(cat_label)} ---", subtitle_style))
            elements.append(Spacer(1, 0.1 * inch))

        # Cor baseada na severidade
        sev_color = "black"
        if req['severity'] == "Crítico": sev_color = "red"
        elif req['severity'] == "Alto": sev_color = "orange"
        
        # Título do Requisito
        title_text = f"[{req['id']}] {req['title']} - <font color='{sev_color}'>{req['severity']}</font>"
        elements.append(Paragraph(title_text, styles['Heading3']))
        
        # Status
        elements.append(Paragraph(f"Status: <b>{escape(req['status'])}</b>", body_style))
        
        # Conteúdo
        elements.append(Paragraph(f"<b>Instrução:</b> {escape(req['content'])}", body_style))
        
        # Descrição
        if req.get('description'):
            elements.append(Paragraph(f"<i><b>Por que:</b> {escape(req['description'])}</i>", body_style))
        
        # Como Testar
        if req.get('verification'):
            elements.append(Paragraph(f"<b>Teste:</b> {escape(req['verification'])}", body_style))
            
        # Mapeamento
        mapping_text = json.dumps(req['mapping'])
        elements.append(Paragraph(f"<font size='8' color='grey'>Mapeamento: {escape(mapping_text)}</font>", body_style))
        
        # Notas
        if req.get('notes'):
            elements.append(Paragraph(f"<b>Notas:</b> {escape(req['notes'])}", body_style))
            
        elements.append(Spacer(1, 0.1 * inch))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
        elements.append(Spacer(1, 0.1 * inch))
        
    doc.build(elements)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    return Response(content=pdf_bytes, media_type="application/pdf", headers={
        "Content-Disposition": "attachment; filename=requirements.pdf"
    })

@app.post("/seed")
def seed_data(db: Session = Depends(get_db)):
    init_db()
    db.query(KnowledgeBase).delete(); db.commit()
    try:
        with open(DATA_PATH, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
            for item in data:
                db.add(KnowledgeBase(code=item["id"], title=item["title"], description=item.get("description", ""), content=item["content"], severity=item.get("severity", "Médio"), verification_instructions=item.get("verification", ""), rules=item["rules"], mapping=item["mapping"]))
            db.commit()
        return {"message": f"Seed OK: {len(data)}"}
    except Exception as e: return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=8000)
