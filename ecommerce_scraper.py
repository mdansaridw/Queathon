"""
ecommerce_scraper.py
====================
Fetches and parses product listings from Amazon, Flipkart, or generic e-commerce URLs.
Includes fallback parsing and resilient mock fixtures to prevent anti-bot blocking
during live hackathon demos.
"""

import re
import urllib.request
import urllib.parse
from bs4 import BeautifulSoup
from typing import Dict, Any

# Curated mock listings in case Amazon/Flipkart trigger a CAPTCHA during live judging
SAMPLE_ECOMMERCE_LINKS = {
    "amazon_helmet_fake": {
        "url": "https://www.amazon.in/dp/B0FAKEHLM1",
        "title": "RoadRider Aerodynamic Bike Helmet with ISI Mark Crash Resistance",
        "description": "Premium lightweight motorcycle helmet. Features ISI mark for road safety, aerodynamic air vents, and high-impact polycarbonate shell. Manufactured to strict ISI quality specifications. (No CM/L provided on listing).",
        "image_url": "/samples/tc02_helmet_phantom_isi.png",
        "source": "Amazon India (Listing Sample)"
    },
    "amazon_cooker_genuine": {
        "url": "https://www.amazon.in/dp/B0REALCKR2",
        "title": "Hawkins Classic 5 Litre Pressure Cooker (Aluminium)",
        "description": "Hawkins genuine domestic pressure cooker. Certified under IS 2347:2017 with BIS Licence CM/L-3141592. Features 'goof-proof' lid and pressure regulator. Genuine ISI certified kitchenware.",
        "image_url": "https://images.unsplash.com/photo-1584990347449-399a9b699e71?w=400&q=80",
        "source": "Amazon India (Listing Sample)"
    },
    "flipkart_water_fake": {
        "url": "https://www.flipkart.com/pure-himalaya-packaged-water/p/itm123fake",
        "title": "Himalaya Fresh Packaged Drinking Water 1 Litre (Pack of 12)",
        "description": "Pure mineral packaged water processed through multi-stage RO and UV. Claims IS 14543 certification. License displayed on box: CM/L-1234.",
        "image_url": "/samples/tc01_water_forged_cml.png",
        "source": "Flipkart (Listing Sample)"
    }
}

def fetch_product_from_url(url: str) -> Dict[str, Any]:
    """
    Fetches title, description, and images from an e-commerce URL.
    Handles bot protection by extracting keywords or falling back gracefully.
    """
    clean_url = url.strip()
    
    # 1. Check if it's one of the demo keys or links
    for key, data in SAMPLE_ECOMMERCE_LINKS.items():
        if key in clean_url or data["url"] == clean_url:
            return data
            
    # 2. Real Web Fetching
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    }
    
    try:
        req = urllib.request.Request(clean_url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            
        soup = BeautifulSoup(html, "html.parser")
        
        # Title Extraction
        title = ""
        # Amazon selector
        title_el = soup.find(id="productTitle") or soup.find("h1", class_="product-title") or soup.find("h1")
        if title_el:
            title = title_el.get_text().strip()
            
        # Description Extraction
        description_parts = []
        # Bullet points
        feature_bullets = soup.find(id="feature-bullets")
        if feature_bullets:
            for li in feature_bullets.find_all("li"):
                t = li.get_text().strip()
                if t:
                    description_parts.append(t)
                    
        # General product description
        prod_desc = soup.find(id="productDescription") or soup.find("div", class_="description")
        if prod_desc:
            description_parts.append(prod_desc.get_text().strip())
            
        full_description = "\n".join(description_parts)
        if not full_description:
            # Fallback to meta description
            meta = soup.find("meta", attrs={"name": "description"}) or soup.find("meta", attrs={"property": "og:description"})
            if meta and meta.get("content"):
                full_description = meta["content"].strip()
                
        # Image Extraction
        img_url = ""
        img_el = soup.find(id="landingImage") or soup.find("meta", attrs={"property": "og:image"})
        if img_el:
            img_url = img_el.get("src") or img_el.get("content") or ""
            
        if not title:
            # Extract from URL slug if blocked by CAPTCHA
            parsed = urllib.parse.urlparse(clean_url)
            slug = parsed.path.strip("/").split("/")[-1]
            title = re.sub(r"[-_]", " ", slug).title()
            full_description = f"Product extracted from marketplace listing: {clean_url}"
            
        return {
            "url": clean_url,
            "title": title[:200] if title else "E-Commerce Product Listing",
            "description": full_description if full_description else title,
            "image_url": img_url,
            "source": urllib.parse.urlparse(clean_url).netloc
        }
        
    except Exception as e:
        # Graceful fallback: Extract from URL keywords
        parsed = urllib.parse.urlparse(clean_url)
        path_parts = [p for p in parsed.path.split("/") if p and len(p) > 2]
        slug = path_parts[-1] if path_parts else "Product"
        title = re.sub(r"[-_+]", " ", slug).title()
        
        return {
            "url": clean_url,
            "title": title,
            "description": f"Extracted from {parsed.netloc}: {title}. (Protected listing; analyze keywords or paste full description).",
            "image_url": "",
            "source": parsed.netloc or "Web Link",
            "warning": f"Marketplace protected page: {str(e)}"
        }

if __name__ == "__main__":
    res = fetch_product_from_url("amazon_helmet_fake")
    print("Scraper Test:", res["title"])
