"""
app.py
======
FastAPI Server & BIS-SHIELD Interactive Investigation Platform.
Serves:
1. REST API endpoints for image forensics, text audit, and enforcement dossier generation
2. Interactive Single Page Application with dynamic benchmark test case loading
"""

import os
import json
import base64
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from bis_shield_engine import BISShieldEngine
from image_forensics_module import PackagingVisionForensics

app = FastAPI(title="BIS-SHIELD Forensic Intelligence", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize engines
engine = BISShieldEngine("real_bis_standards.json")
vision_engine = PackagingVisionForensics()

# Ensure directories exist
os.makedirs("sample_packaging", exist_ok=True)
os.makedirs("uploads", exist_ok=True)
app.mount("/samples", StaticFiles(directory="sample_packaging"), name="samples")
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# Preloaded Benchmark Cases for Judges
BENCHMARKS = [
    {
        "id": "TC-01",
        "title": "Packaged Water — Forged 4-Digit CM/L",
        "product": "Packaged Drinking Water",
        "claim": "Pure Himalayan Spring Water conforming to IS 14543 CM/L-1234 genuine pure mineral water.",
        "image": "/samples/tc01_water_forged_cml.png",
        "has_logo": True,
        "expected_issue": "Forged CM/L license format (4 digits instead of 7-8)"
    },
    {
        "id": "TC-02",
        "title": "Motorcycle Helmet — Phantom ISI Mark",
        "product": "Motorcycle Helmet",
        "claim": "Ultra-light aerodynamic crash helmet with high durability ISI Mark protection.",
        "image": "/samples/tc02_helmet_phantom_isi.png",
        "has_logo": True,
        "expected_issue": "Phantom mark: ISI logo present but CM/L number missing"
    },
    {
        "id": "TC-03",
        "title": "Electric Iron — Deceptive Marketing Copy",
        "product": "Electric Iron",
        "claim": "Top quality dry electric iron, manufactured as per ISI standards for maximum thermal efficiency.",
        "image": "/samples/tc03_iron_deceptive_copy.png",
        "has_logo": False,
        "expected_issue": "Prohibited deceptive phrase 'manufactured as per ISI' without license"
    },
    {
        "id": "TC-04",
        "title": "Baby Toys — Standard Hijacking / Mismatch",
        "product": "Baby Infant Toy",
        "claim": "Non-toxic musical baby rattle IS 4151 CM/L-9876543 certified child safe.",
        "image": "/samples/tc04_toy_standard_mismatch.png",
        "has_logo": True,
        "expected_issue": "Product mismatch: Helmet standard (IS 4151) printed on toy (IS 9873)"
    },
    {
        "id": "TC-05",
        "title": "Fast Charger — Compliant CRS Declaration",
        "product": "Power Adapter / Charger",
        "claim": "Turbo 65W GaN Fast Charger conforming to IS 13252 (Part 1):2010 R-41001234 short circuit safe.",
        "image": "/samples/tc05_charger_genuine_crs.png",
        "has_logo": False,
        "expected_issue": "None (Fully compliant CRS registration)"
    },
    {
        "id": "TC-06",
        "title": "Protective Helmet — Genuine Certified ISI",
        "product": "Motorcycle Helmet",
        "claim": "Full face motor bike helmet tested rigorously as per IS 4151:2015 CM/L-8765432 with safety visor.",
        "image": "/samples/tc06_helmet_genuine_isi.png",
        "has_logo": True,
        "expected_issue": "None (Fully compliant Scheme-I ISI Mark)"
    }
]

from ecommerce_scraper import fetch_product_from_url, SAMPLE_ECOMMERCE_LINKS

@app.get("/api/benchmarks")
def get_benchmarks():
    return BENCHMARKS

@app.get("/api/sample_links")
def get_sample_links():
    return list(SAMPLE_ECOMMERCE_LINKS.values())

@app.post("/api/fetch_url")
def fetch_url(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    data = fetch_product_from_url(url)
    return data

@app.get("/api/registry")
def get_registry():
    return list(engine.license_registry.values())

@app.get("/api/standards")
def get_standards(q: str = ""):
    if not q:
        return engine.standards[:20]
    q_lower = q.lower()
    matches = [
        s for s in engine.standards
        if q_lower in s.get("standard_number", "").lower() or
           q_lower in s.get("short_title", "").lower() or
           q_lower in s.get("product_category", "").lower()
    ]
    return matches[:25]

@app.post("/api/audit")
def audit_claim(
    product_name: str = Form(""),
    claim_text: str = Form(...),
    has_logo: bool = Form(False),
    image_path: str = Form("")
):
    # Vision forensics if image provided
    vision_data = None
    if image_path:
        # strip leading slash
        clean_path = image_path.lstrip("/")
        if os.path.exists(clean_path):
            vision_data = vision_engine.analyze_image_file(clean_path)
            if vision_data.get("has_potential_mark"):
                has_logo = True

    analysis = engine.analyze_claim(
        claim_text=claim_text,
        product_name=product_name,
        image_has_logo=has_logo
    )
    
    # Generate formal dossier text
    dossier = engine.generate_enforcement_dossier(analysis, product_name or "Unspecified Product")
    
    return {
        "analysis": analysis,
        "vision_forensics": vision_data,
        "dossier_text": dossier
    }

import asyncio
import winocr
from PIL import Image

@app.post("/api/upload_image")
async def upload_image(file: UploadFile = File(...)):
    filename = file.filename
    save_path = os.path.join("uploads", filename)
    with open(save_path, "wb") as f:
        f.write(await file.read())
        
    vision_data = vision_engine.analyze_image_file(save_path)
    
    # Run real hardware-accelerated OCR
    extracted_text = ""
    try:
        pil_img = Image.open(save_path)
        ocr_res = await winocr.recognize_pil(pil_img, 'en')
        extracted_text = ocr_res.text
    except Exception as e:
        print("OCR error:", e)
        extracted_text = ""
        
    return {
        "url": f"/uploads/{filename}",
        "local_path": save_path,
        "extracted_text": extracted_text,
        "vision_forensics": vision_data
    }

@app.get("/", response_class=HTMLResponse)
def index_page():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
