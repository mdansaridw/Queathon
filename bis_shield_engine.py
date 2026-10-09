"""
bis_shield_engine.py
====================
Core Verification & Forensics Engine for BIS-SHIELD.
Implements:
1. Fault-tolerant Entity Extraction (IS codes, CM/L licenses, CRS R-numbers, HUIDs)
2. Ground-truth Gazette standards cross-referencing (real_bis_standards.json)
3. BIS License Registry Verification (bis_license_registry.json):
   - Active Operative check
   - Expired / Cancelled / Suspended detection
   - Licensee & Product category mismatch detection (Hijacking)
4. Deceptive euphemism & terminology detection
5. Non-BIS Document detection (e.g., student ID cards, non-commercial documents)
6. Statutory Misuse Risk Index (0 - 100%)
7. Enforcement Dossier generator citing BIS Act 2016 Sections 14, 15, 16, 29, 30
"""

import json
import re
from typing import Dict, List, Any, Optional
from pathlib import Path
from rapidfuzz import fuzz

class BISShieldEngine:
    def __init__(self, standards_path: str = "real_bis_standards.json", registry_path: str = "bis_license_registry.json"):
        self.standards: List[Dict[str, Any]] = []
        self.standard_map: Dict[str, Dict[str, Any]] = {}
        self.license_registry: Dict[str, Dict[str, Any]] = {}
        
        self.load_standards(standards_path)
        self.load_registry(registry_path)
        
        # Deceptive / Misleading Lexicon strictly scrutinized under BIS Act Sec 14/15
        self.deceptive_patterns = [
            (r"\bisi\s+(?:grade|quality|style|standard|type)\b", "Deceptive claim of 'ISI grade/quality' without statutory certification licence."),
            (r"\bmanufactured\s+(?:as\s+per|to|according\s+to)\s+(?:isi|bis)\b", "Misleading claim 'manufactured as per ISI/BIS' without displaying licence number."),
            (r"\b(?:bis|isi)\s+approved\b", "False term 'BIS/ISI Approved' (BIS 'certifies' or 'registers', does not 'approve')."),
            (r"\bequivalent\s+to\s+(?:isi|bis)\b", "Ambiguous equivalence claim prohibited under Section 15."),
            (r"\bcomplies\s+with\s+(?:isi|bis)\s+standards\b", "Conformity claim without verified certification identification."),
            (r"\biso\s*\/?\s*isi\s+certified\b", "Conflating ISO management certification with BIS/ISI product mark.")
        ]
        
    def load_standards(self, path: str):
        p = Path(path)
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                self.standards = json.load(f)
            for std in self.standards:
                std_num = std.get("standard_number", "").strip().upper()
                if std_num:
                    self.standard_map[std_num] = std
                    norm = re.sub(r"\s+", "", std_num)
                    self.standard_map[norm] = std

    def load_registry(self, path: str):
        p = Path(path)
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                entries = json.load(f)
            for item in entries:
                cml = str(item.get("cml_number", "")).strip()
                if cml:
                    self.license_registry[cml] = item
                    
    def extract_entities(self, text: str) -> Dict[str, Any]:
        """
        Extracts compliance identifiers from OCR or input text with fault-tolerant OCR noise correction.
        """
        clean_text = text.replace("\n", " ")
        
        # 1. Indian Standard Code extraction: IS 14543, IS 4151:2015, IS:4151, IS-2347, etc.
        is_pattern = re.compile(r"\bIS\s*[:\-\.]?\s*(\d{3,5}(?:\s*\([^\)]+\))?(?::\d{4})?)\b", re.IGNORECASE)
        is_matches = is_pattern.findall(clean_text)
        found_standards = []
        for m in is_matches:
            std_str = f"IS {m.strip()}"
            if std_str not in found_standards:
                found_standards.append(std_str)
                
        # 2. CM/L License Number with Fault-Tolerant OCR Error Correction:
        # Matches: CM/L, CWL, CML, CNL, CMI/L, CM.L, followed by digits/confusable characters
        cml_fuzzy = re.compile(r"\bC[MWNV][\/\\]?[LI1]?\s*[:\-\.]?\s*([0-9a-zA-Z]{5,10})\b", re.IGNORECASE)
        fuzzy_matches = cml_fuzzy.findall(clean_text)
        
        # Also detect naked 7/8 digit numbers if labeled as lic / license
        lic_pattern = re.compile(r"\b(?:lic(?:ence)?|licence\s*no|lic\s*no)[\s:\-\.]*([0-9a-zA-Z]{6,10})\b", re.IGNORECASE)
        lic_matches = lic_pattern.findall(clean_text)
        
        all_raw_cml = list(set(fuzzy_matches + lic_matches))
        ocr_substitutions = {
            'f': '1', 'l': '1', 'I': '1', '|': '1', '!': '1',
            'O': '0', 'o': '0', 'D': '0',
            'S': '5', 's': '5',
            'B': '8',
            'Z': '2', 'z': '2',
            'G': '6', 'g': '9'
        }
        
        normalized_cml = []
        ocr_corrections_made = []
        for raw in all_raw_cml:
            norm = ''.join(ocr_substitutions.get(ch, ch) for ch in raw)
            digits_only = re.sub(r'[^0-9]', '', norm)
            if len(digits_only) in (7, 8):
                normalized_cml.append(digits_only)
                if digits_only != raw:
                    ocr_corrections_made.append(f"Normalized OCR token '{raw}' -> 'CM/L-{digits_only}'")
            elif digits_only:
                # keep malformed digits to flag invalid length
                normalized_cml.append(digits_only)
                
        all_cml = list(set(normalized_cml))
        
        # 3. CRS Registration Number: R-12345678, R - 41001234
        crs_pattern = re.compile(r"\bR\s*[\-:]\s*(\d{6,10})\b", re.IGNORECASE)
        crs_matches = crs_pattern.findall(clean_text)
        
        # 4. Hallmark HUID: 6 alphanumeric characters e.g., HUID AB1234
        huid_pattern = re.compile(r"\b(?:HUID|HALLMARK)[\s:\-\.]*([A-Z0-9]{6})\b", re.IGNORECASE)
        huid_matches = huid_pattern.findall(clean_text)
        
        # 5. Mark Mentions
        mentions_isi = bool(re.search(r"\b(?:ISI|ISI\s*MARK|CWL|CML|CM\/L)\b", clean_text, re.IGNORECASE))
        mentions_bis = bool(re.search(r"\b(?:BIS|BUREAU\s*OF\s*INDIAN\s*STANDARDS)\b", clean_text, re.IGNORECASE))
        mentions_crs = bool(re.search(r"\b(?:CRS|COMPULSORY\s*REGISTRATION)\b", clean_text, re.IGNORECASE))
        mentions_hallmark = bool(re.search(r"\b(?:HALLMARK|HALLMARKED)\b", clean_text, re.IGNORECASE))
        
        return {
            "standards_claimed": found_standards,
            "cml_numbers": all_cml,
            "crs_numbers": crs_matches,
            "huid_codes": huid_matches,
            "mentions_isi": mentions_isi,
            "mentions_bis": mentions_bis,
            "mentions_crs": mentions_crs,
            "mentions_hallmark": mentions_hallmark,
            "ocr_corrections": ocr_corrections_made,
            "raw_text_length": len(text.strip())
        }
        
    def check_deceptive_lexicon(self, text: str) -> List[Dict[str, str]]:
        violations = []
        for pat, desc in self.deceptive_patterns:
            matches = re.findall(pat, text, re.IGNORECASE)
            if matches:
                violations.append({
                    "matched_phrase": matches[0] if isinstance(matches[0], str) else "deceptive claim",
                    "explanation": desc
                })
        return violations

    def analyze_claim(self, 
                      claim_text: str, 
                      product_name: str = "", 
                      image_has_logo: bool = False) -> Dict[str, Any]:
        """
        Executes forensic analysis on product text/packaging claim.
        """
        entities = self.extract_entities(claim_text)
        deceptive_flags = self.check_deceptive_lexicon(claim_text)
        
        risk_score = 0
        violations = []
        evidentiary_findings = []
        registry_matches = []
        
        # Check: Is this a non-commercial / non-BIS document? (e.g. ID card, unrelated text)
        has_any_bis_indicator = (
            entities["mentions_isi"] or 
            entities["mentions_bis"] or 
            entities["mentions_crs"] or 
            entities["mentions_hallmark"] or 
            len(entities["standards_claimed"]) > 0 or 
            len(entities["cml_numbers"]) > 0 or 
            len(entities["crs_numbers"]) > 0 or 
            image_has_logo or
            len(deceptive_flags) > 0
        )
        
        # If user uploaded text/image with NO BIS indicators at all
        if not has_any_bis_indicator:
            # Check if product belongs to mandatory QCO
            matched_mandatory = None
            if product_name:
                for std in self.standards:
                    if std.get("mandatory_qco"):
                        scope_text = (std.get("short_title", "") + " " + std.get("product_category", "") + " " + " ".join(std.get("keywords", []))).lower()
                        if fuzz.token_set_ratio(product_name.lower(), scope_text) > 75:
                            matched_mandatory = std
                            break
                            
            if matched_mandatory:
                # Missing mandatory mark on a regulated product
                risk_score = 60
                violations.append({
                    "statute": "Section 16, Bureau of Indian Standards Act, 2016 (Mandatory QCO Order)",
                    "severity": "CRITICAL",
                    "issue": "Missing Mandatory BIS Certification on Regulated Product",
                    "detail": f"Product '{product_name}' falls under mandatory Quality Control Order ({matched_mandatory['standard_number']} - {matched_mandatory['short_title']}) but displays zero BIS/ISI certification marks."
                })
                evidentiary_findings.append(f"Regulated item under {matched_mandatory['standard_number']} lacks compulsory marking.")
                status_verdict = "MANDATORY_QCO_VIOLATION"
            else:
                # Truly non-BIS document (e.g. ID card, resume, generic photo)
                return {
                    "misuse_risk_score": 0,
                    "risk_level": "NO BIS MARKS DETECTED (NON-REGULATED DOCUMENT)",
                    "recommended_action": "No BIS standard claims or certification marks found on this document/image. Not subject to BIS Act enforcement.",
                    "status_verdict": "NON_BIS_DOCUMENT",
                    "entities_detected": entities,
                    "violations": [],
                    "evidentiary_findings": ["No Indian Standards, ISI marks, or CM/L numbers detected on the submitted evidence."],
                    "verified_standards": [],
                    "registry_matches": []
                }
        else:
            status_verdict = "BIS_CLAIM_DETECTED"

        # Factor 1: Unauthorised ISI / CRS Mark (Mark claimed, but CM/L missing)
        mark_claimed = entities["mentions_isi"] or image_has_logo or entities["mentions_bis"]
        has_cml = len(entities["cml_numbers"]) > 0
        has_crs = len(entities["crs_numbers"]) > 0
        
        if mark_claimed and not has_cml and not has_crs:
            risk_score += 45
            violations.append({
                "statute": "Section 14 & 15, Bureau of Indian Standards Act, 2016",
                "severity": "CRITICAL",
                "issue": "Phantom Standard Mark Claim (Missing License)",
                "detail": "Product displays or claims the BIS/ISI Standard Mark but fails to provide a statutory CM/L or CRS registration number."
            })
            evidentiary_findings.append("Mark claimed without obligatory license identifier.")
            
        # Factor 2: CM/L Format & Licence Registry Verification
        for cml in entities["cml_numbers"]:
            cml_len = len(cml)
            if cml_len not in (7, 8):
                risk_score += 40
                violations.append({
                    "statute": "Section 14 & 29, Bureau of Indian Standards Act, 2016",
                    "severity": "CRITICAL",
                    "issue": "Fabricated or Invalid CM/L License Number",
                    "detail": f"Claimed license number '{cml}' has {cml_len} digits. Genuine BIS CM/L numbers strictly consist of 7 or 8 numeric digits."
                })
                evidentiary_findings.append(f"Invalid license digit length ({cml_len} digits detected).")
            else:
                # Check License in Registry
                if cml in self.license_registry:
                    lic_info = self.license_registry[cml]
                    registry_matches.append(lic_info)
                    
                    if lic_info["status"] == "OPERATIVE":
                        evidentiary_findings.append(f"Valid Operative License: CM/L {cml} held by {lic_info['licensee_name']} ({lic_info['brand']}). Valid till: {lic_info['valid_till']}.")
                        
                        # Product category mismatch with license holder
                        if product_name:
                            p_score = fuzz.partial_ratio(product_name.lower(), lic_info["product_category"].lower())
                            if p_score < 40:
                                risk_score += 50
                                violations.append({
                                    "statute": "Section 14 & 29, Bureau of Indian Standards Act, 2016",
                                    "severity": "CRITICAL",
                                    "issue": "Licence Hijacking / Licensee Product Mismatch",
                                    "detail": f"CM/L {cml} is registered to '{lic_info['licensee_name']}' for '{lic_info['product_category']}', but is being applied to '{product_name}'."
                                })
                                evidentiary_findings.append(f"Licence hijacking detected: License is for {lic_info['product_category']}, not {product_name}.")
                    elif lic_info["status"] in ("CANCELLED", "SUSPENDED"):
                        risk_score += 60
                        violations.append({
                            "statute": "Section 14(1) & 29, Bureau of Indian Standards Act, 2016",
                            "severity": "CRITICAL",
                            "issue": f"Unlawful Use of {lic_info['status']} Licence",
                            "detail": f"CM/L {cml} was {lic_info['status'].lower()} by BIS. Reason: {lic_info['status_description']} (Valid till was: {lic_info['valid_till']})."
                        })
                        evidentiary_findings.append(f"Licence status is {lic_info['status']}: {lic_info['status_description']}")
                else:
                    # License format is 7/8 digits, but not found in registry
                    risk_score += 35
                    violations.append({
                        "statute": "Section 14, Bureau of Indian Standards Act, 2016",
                        "severity": "HIGH",
                        "issue": "Unverified CM/L Licence (Not in Central Registry)",
                        "detail": f"CM/L '{cml}' format is 7/8 digits, but does not match any operative licensee in the BIS central database."
                    })
                    evidentiary_findings.append(f"CM/L {cml} not recognized in active registry records.")
                
        # Factor 3: Deceptive / Misleading Lexicon
        if deceptive_flags:
            risk_score += min(35, len(deceptive_flags) * 20)
            for d in deceptive_flags:
                violations.append({
                    "statute": "Section 15(1), Bureau of Indian Standards Act, 2016",
                    "severity": "HIGH",
                    "issue": "Prohibited Misleading Compliance Terminology",
                    "detail": f"Product uses illegal marketing euphemism: '{d['matched_phrase']}'. {d['explanation']}"
                })
                evidentiary_findings.append(f"Prohibited deceptive phrasing detected: '{d['matched_phrase']}'.")
                
        # Factor 4: Ground-Truth Standard Verification
        verified_standards_info = []
        if entities["standards_claimed"]:
            for std_claim in entities["standards_claimed"]:
                norm_key = re.sub(r"\s+", "", std_claim.upper().split(":")[0])
                found_meta = None
                
                for k, v in self.standard_map.items():
                    if norm_key in k.upper() or k.upper() in norm_key:
                        found_meta = v
                        break
                        
                if found_meta:
                    verified_standards_info.append(found_meta)
                    evidentiary_findings.append(f"Recognized Standard: {found_meta['standard_number']} ({found_meta['short_title']}). Mandatory QCO: {found_meta.get('mandatory_qco', False)}.")
                    
                    # Product Scope Mismatch
                    if product_name:
                        target = (found_meta['short_title'] + " " + found_meta.get('product_category', '')).lower()
                        score = fuzz.partial_ratio(product_name.lower(), target)
                        if score < 40:
                            risk_score += 40
                            violations.append({
                                "statute": "Section 14(2), Bureau of Indian Standards Act, 2016",
                                "severity": "HIGH",
                                "issue": "Standard Scope Mismatch / Standard Hijacking",
                                "detail": f"Claimed standard {found_meta['standard_number']} covers '{found_meta['short_title']}', which conflicts with stated product '{product_name}'."
                            })
                            evidentiary_findings.append(f"Mismatch between product '{product_name}' and standard scope '{found_meta['short_title']}'.")
                else:
                    risk_score += 40
                    violations.append({
                        "statute": "Section 15, Bureau of Indian Standards Act, 2016",
                        "severity": "CRITICAL",
                        "issue": "Non-Existent / Unrecognized Indian Standard Code",
                        "detail": f"Standard '{std_claim}' does not match any recognized standard in official Gazette records."
                    })
                    evidentiary_findings.append(f"Unrecognized standard code: {std_claim}.")
                    
        # Bound risk score [0, 100]
        final_risk = min(100, risk_score)
        
        # Risk Category
        if final_risk >= 51:
            risk_level = "HIGH RISK (LIKELY VIOLATION)"
            action = "Immediate Investigation & Notice under Section 29/30 recommended."
        elif final_risk >= 25:
            risk_level = "MODERATE RISK (SUSPICIOUS)"
            action = "Clarification notice required. Request proof of valid licence."
        else:
            risk_level = "LOW RISK (APPARENTLY COMPLIANT)"
            action = "No prima facie violation detected. Routine monitoring."
            
        return {
            "misuse_risk_score": final_risk,
            "risk_level": risk_level,
            "recommended_action": action,
            "status_verdict": status_verdict,
            "entities_detected": entities,
            "violations": violations,
            "evidentiary_findings": evidentiary_findings,
            "verified_standards": verified_standards_info,
            "registry_matches": registry_matches
        }

    def generate_enforcement_dossier(self, analysis_result: Dict[str, Any], product_title: str) -> str:
        dossier = [
            "=======================================================================",
            "       BUREAU OF INDIAN STANDARDS - PRELIMINARY ENFORCEMENT DOSSIER    ",
            "             GENERATED UNDER BIS ACT, 2016 ENFORCEMENT RULES          ",
            "=======================================================================",
            f"SUBJECT: Inspection Report for Product: {product_title}",
            f"MISUSE RISK INDEX: {analysis_result['misuse_risk_score']}% [{analysis_result['risk_level']}]",
            f"RECOMMENDED ACTION: {analysis_result['recommended_action']}",
            "-----------------------------------------------------------------------",
            "1. EXTRACTED REGULATORY IDENTIFIERS:",
            f"   - Standards Claimed  : {', '.join(analysis_result['entities_detected']['standards_claimed']) or 'None'}",
            f"   - CM/L License No(s) : {', '.join(analysis_result['entities_detected']['cml_numbers']) or 'None'}",
            f"   - CRS Registration   : {', '.join(analysis_result['entities_detected']['crs_numbers']) or 'None'}",
            f"   - HUID (Hallmarking) : {', '.join(analysis_result['entities_detected']['huid_codes']) or 'None'}",
            "-----------------------------------------------------------------------",
            "2. CENTRAL REGISTRY CROSS-VERIFICATION:"
        ]
        
        if analysis_result.get("registry_matches"):
            for reg in analysis_result["registry_matches"]:
                dossier.append(f"   * CM/L {reg['cml_number']} -> {reg['licensee_name']} ({reg['brand']})")
                dossier.append(f"     Status: {reg['status']} | Valid Till: {reg['valid_till']}")
                dossier.append(f"     Licensed For: {reg['product_category']}")
        else:
            dossier.append("   [No matching operative records found in Central License Registry]")
            
        dossier.extend([
            "-----------------------------------------------------------------------",
            "3. STATUTORY VIOLATION AUDIT TRAIL:"
        ])
        
        if not analysis_result["violations"]:
            dossier.append("   [No prima facie statutory violations identified]")
        else:
            for idx, v in enumerate(analysis_result["violations"], 1):
                dossier.append(f"   [{idx}] ISSUE: {v['issue']} ({v['severity']})")
                dossier.append(f"       STATUTE: {v['statute']}")
                dossier.append(f"       DETAIL : {v['detail']}")
                
        dossier.extend([
            "-----------------------------------------------------------------------",
            "4. FORENSIC FINDINGS SUMMARY:"
        ])
        for finding in analysis_result["evidentiary_findings"]:
            dossier.append(f"   * {finding}")
            
        dossier.extend([
            "-----------------------------------------------------------------------",
            "LEGAL CITATION NOTE:",
            "Unauthorised use of the Standard Mark is a cognizable offence under",
            "Section 29 of the BIS Act, 2016, punishable with imprisonment up to",
            "two years or fine up to ten times the value of goods.",
            "======================================================================="
        ])
        return "\n".join(dossier)
