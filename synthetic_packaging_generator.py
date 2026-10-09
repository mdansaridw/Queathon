"""
synthetic_packaging_generator.py
================================
Generates authentic-looking high-resolution benchmark packaging label images
using OpenCV and PIL, representing the 6 critical demonstration test cases
(both counterfeit and compliant) for BIS enforcement evaluation.
"""

import os
from PIL import Image, ImageDraw, ImageFont
import cv2
import numpy as np

def create_label(
    filename: str,
    title: str,
    product_name: str,
    standard_text: str,
    license_text: str,
    marketing_claim: str,
    is_counterfeit: bool,
    draw_isi_logo: bool = True
):
    width, height = 700, 420
    img = Image.new("RGB", (width, height), color=(250, 252, 255))
    draw = ImageDraw.Draw(img)
    
    # Outer packaging border
    border_color = (220, 38, 38) if is_counterfeit else (16, 185, 129)
    draw.rectangle([10, 10, width - 10, height - 10], outline=border_color, width=4)
    draw.rectangle([18, 18, width - 18, height - 18], outline=(200, 210, 225), width=1)
    
    # Top header bar
    draw.rectangle([10, 10, width - 10, 50], fill=(240, 245, 250))
    draw.text((30, 22), title.upper(), fill=(30, 41, 59))
    
    # Product Title
    draw.text((35, 75), f"PRODUCT: {product_name}", fill=(15, 23, 42))
    
    # Marketing / Description text
    if marketing_claim:
        draw.text((35, 115), f"DESCRIPTION: {marketing_claim}", fill=(71, 85, 105))
        
    # Standard & Certification Box
    box_top = 160
    draw.rectangle([35, box_top, width - 35, box_top + 160], outline=(148, 163, 184), width=2, fill=(255, 255, 255))
    
    # Draw ISI Logo representation or CRS Box
    if draw_isi_logo:
        # Draw ISI standard box
        logo_x, logo_y = 60, box_top + 20
        # ISI Outer frame
        draw.rectangle([logo_x, logo_y, logo_x + 100, logo_y + 110], outline=(15, 23, 42), width=3)
        # IS standard above
        draw.text((logo_x + 10, logo_y + 10), standard_text.split(":")[0] if ":" in standard_text else standard_text, fill=(15, 23, 42))
        # Central ISI text
        draw.text((logo_x + 25, logo_y + 45), "ISI", fill=(15, 23, 42))
        # License below
        draw.text((logo_x + 5, logo_y + 85), license_text if license_text else "[MISSING LIC]", fill=(220, 38, 38) if not license_text else (15, 23, 42))
    else:
        # CRS or text block
        draw.text((55, box_top + 30), f"STANDARD: {standard_text}", fill=(15, 23, 42))
        draw.text((55, box_top + 70), f"REGISTRATION: {license_text}", fill=(15, 23, 42))
        
    # Technical specs & packaging details
    spec_x = 220
    draw.text((spec_x, box_top + 25), f"Applicable Standard: {standard_text}", fill=(30, 41, 59))
    draw.text((spec_x, box_top + 55), f"Statutory Identification: {license_text or 'NOT SPECIFIED'}", fill=(220, 38, 38) if not license_text else (30, 41, 59))
    draw.text((spec_x, box_top + 85), f"Batch / Mfg: LOT-2026-X89 | MRP: Rs. 499/-", fill=(100, 116, 139))
    draw.text((spec_x, box_top + 115), f"Jurisdiction: Republic of India", fill=(100, 116, 139))
    
    # Bottom warning / verification watermark
    watermark_text = "SAMPLE EVIDENCE PACKAGING FOR FORENSIC TRIAGE - BIS ACT COMPLIANCE TEST"
    draw.text((35, height - 35), watermark_text, fill=(148, 163, 184))
    
    os.makedirs("sample_packaging", exist_ok=True)
    out_path = os.path.join("sample_packaging", filename)
    img.save(out_path)
    print(f"Created: {out_path}")
    return out_path

def generate_all_samples():
    samples = [
        {
            "filename": "tc01_water_forged_cml.png",
            "title": "AQUA-PURE PACKAGED DRINKING WATER 1L",
            "product_name": "Packaged Drinking Water",
            "standard_text": "IS 14543",
            "license_text": "CM/L-1234",  # Forged 4-digit
            "marketing_claim": "Pure Himalayan Mineral Spring Water bottled under strict hygienic conditions.",
            "is_counterfeit": True,
            "draw_isi_logo": True
        },
        {
            "filename": "tc02_helmet_phantom_isi.png",
            "title": "APEX HIGH VELOCITY MOTORCYCLE HELMET",
            "product_name": "Motorcycle Protective Helmet",
            "standard_text": "IS 4151",
            "license_text": "",  # Missing license! Phantom mark
            "marketing_claim": "Ultra-light aerodynamic fiber shell with ISI mark crash safety.",
            "is_counterfeit": True,
            "draw_isi_logo": True
        },
        {
            "filename": "tc03_iron_deceptive_copy.png",
            "title": "GLOW-HEAT 1000W DRY ELECTRIC IRON",
            "product_name": "Electric Iron",
            "standard_text": "IS 302",
            "license_text": "",
            "marketing_claim": "Manufactured as per ISI standards for maximum thermal efficiency and safety.",
            "is_counterfeit": True,
            "draw_isi_logo": False
        },
        {
            "filename": "tc04_toy_standard_mismatch.png",
            "title": "BABY-JOY SOFT MUSICAL RATTLE TOY",
            "product_name": "Baby Infant Toy",
            "standard_text": "IS 4151", # Helmet standard hijacked on a toy!
            "license_text": "CM/L-9876543",
            "marketing_claim": "Non-toxic child safe musical rattle conforming to national standards.",
            "is_counterfeit": True,
            "draw_isi_logo": True
        },
        {
            "filename": "tc05_charger_genuine_crs.png",
            "title": "TURBO-CHARGE 65W GAN POWER ADAPTER",
            "product_name": "Power Adapter / Charger",
            "standard_text": "IS 13252 (Part 1):2010",
            "license_text": "R-41001234",
            "marketing_claim": "Universal USB-C high-speed fast charger with short circuit protection.",
            "is_counterfeit": False,
            "draw_isi_logo": False
        },
        {
            "filename": "tc06_helmet_genuine_isi.png",
            "title": "STEELBIRD CRUISE MOTORCYCLE HELMET",
            "product_name": "Motorcycle Helmet",
            "standard_text": "IS 4151:2015",
            "license_text": "CM/L-8765432",
            "marketing_claim": "Full face motor bike helmet tested rigorously as per Indian Standards.",
            "is_counterfeit": False,
            "draw_isi_logo": True
        }
    ]
    for s in samples:
        create_label(**s)

if __name__ == "__main__":
    generate_all_samples()
