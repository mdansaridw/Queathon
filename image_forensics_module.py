"""
image_forensics_module.py
=========================
Performs image-based packaging forensics using OpenCV:
1. Logo area detection & contour analysis (extracts geometric stamp signatures)
2. Quality / Color degradation metrics (counterfeits often have low print fidelity)
3. Preprocessing pipeline for optical character recognition
"""

import cv2
import numpy as np
from typing import Dict, Any, Tuple
from pathlib import Path

class PackagingVisionForensics:
    def __init__(self):
        pass
        
    def analyze_image_file(self, image_path: str) -> Dict[str, Any]:
        """
        Runs computer vision inspection on a packaging image.
        """
        p = Path(image_path)
        if not p.exists():
            return {"error": f"File not found: {image_path}"}
            
        img = cv2.imread(str(p))
        if img is None:
            return {"error": "Failed to decode image"}
            
        h, w, c = img.shape
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # 1. Edge Density & Contour Analysis
        edges = cv2.Canny(gray, 50, 150)
        edge_density = float(np.sum(edges > 0)) / (h * w)
        
        # 2. Potential Certification Stamp / Logo Regions
        # Look for enclosed rectangular or circular contours corresponding to standard marks
        contours, _ = cv2.findContours(edges, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
        potential_mark_boxes = []
        for cnt in contours:
            x, y, bw, bh = cv2.boundingRect(cnt)
            aspect_ratio = bw / float(bh)
            area = bw * bh
            # Filter contours that match the aspect ratio and size of an ISI or CRS stamp
            if 0.5 < aspect_ratio < 1.8 and (0.01 * h * w) < area < (0.25 * h * w):
                potential_mark_boxes.append({
                    "x": int(x), "y": int(y), "width": int(bw), "height": int(bh),
                    "aspect_ratio": round(aspect_ratio, 2),
                    "relative_area": round(area / (h * w), 3)
                })
                
        # 3. Blur / Sharpness Metric (Laplacian variance)
        laplacian_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        is_sharp = laplacian_var > 100.0
        
        return {
            "dimensions": {"width": w, "height": h, "channels": c},
            "edge_density": round(edge_density, 4),
            "sharpness_score": round(laplacian_var, 2),
            "is_sharp": is_sharp,
            "detected_stamp_regions": potential_mark_boxes[:5], # top candidates
            "has_potential_mark": len(potential_mark_boxes) > 0
        }

if __name__ == "__main__":
    vf = PackagingVisionForensics()
    sample = "sample_packaging/tc01_water_forged_cml.png"
    res = vf.analyze_image_file(sample)
    print("Forensics for TC01:", res)
