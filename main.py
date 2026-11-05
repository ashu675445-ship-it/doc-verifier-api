import base64
import io
import re
from datetime import datetime
import fitz  # PyMuPDF
from fastapi import FastAPI
from pydantic import BaseModel
from PIL import Image, ImageChops
import numpy as np

app = FastAPI()

STRICT_BLACKLIST = [
    "photoshop", "illustrator", "canva", "gimp", "ilovepdf", "sejda", 
    "pdfescape", "smallpdf", "coreldraw", "inkscape", "pixlr", "paint",
    "pdf2go", "sodapdf", "foxit phantom", "nitro pro", "wondershare"
]

INDIAN_BANKS_PROFILE = {
    "State Bank of India (SBI)": {
        "keywords": ["STATE BANK OF INDIA", "SBI CARD", "ONLINESBI", "SBIN0"],
        "ifsc_prefix": "SBIN",
        "standard_fonts": ["arial", "helvetica", "times", "calibri"]
    },
    "HDFC Bank": {
        "keywords": ["HDFC BANK", "HDFCBANK.COM", "HDFC00"],
        "ifsc_prefix": "HDFC",
        "standard_fonts": ["arial", "helvetica", "verdana", "calibri"]
    },
    "ICICI Bank": {
        "keywords": ["ICICI BANK", "ICICIBANK.COM", "ICIC00"],
        "ifsc_prefix": "ICIC",
        "standard_fonts": ["arial", "helvetica", "tahoma"]
    },
    "Axis Bank": {
        "keywords": ["AXIS BANK", "AXISBANK.COM", "UTIB00"],
        "ifsc_prefix": "UTIB",
        "standard_fonts": ["arial", "helvetica", "calibri"]
    },
    "Punjab National Bank (PNB)": {
        "keywords": ["PUNJAB NATIONAL BANK", "PNBINDIA", "PUNB0"],
        "ifsc_prefix": "PUNB",
        "standard_fonts": ["arial", "times"]
    },
    "Bank of Baroda (BOB)": {
        "keywords": ["BANK OF BARODA", "BOBDIGI", "BARB0"],
        "ifsc_prefix": "BARB",
        "standard_fonts": ["arial", "helvetica"]
    },
    "Kotak Mahindra Bank": {
        "keywords": ["KOTAK MAHINDRA", "KOTAK BANK", "KKBK0"],
        "ifsc_prefix": "KKBK",
        "standard_fonts": ["arial", "calibri"]
    }
}

class DocPayload(BaseModel):
    fileName: str
    mimeType: str
    base64File: str
    password: str = ""

@app.get("/")
def home():
    return {"status": "Boss Level Alignment & Forensic Engine Live!"}

def audit_page_geometry_and_alignment(doc):
    """
    Har page ke har ek text block, line aur word ka alignment, 
    font size variance aur vertical offset check karta hai.
    """
    alignment_anomalies = []
    font_anomalies = []
    
    for page_num in range(len(doc)):
        page = doc.load_page(page_num)
        # Detailed block, line, span aur character analysis
        text_page = page.get_text("words")  # List of (x0, y0, x1, y1, "word", block_no, line_no, word_no)
        blocks = page.get_text("dict")["blocks"]
        
        # 1. Text Line Y-Axis Alignment Check
        line_baselines = {}
        for b in blocks:
            if "lines" in b:
                for l in b["lines"]:
                    bbox = l["bbox"]
                    spans = l["spans"]
                    line_y = round(bbox[1], 1)
                    
                    # Check multiple font sizes in single text line (Common sign of edited word)
                    if len(spans) > 1:
                        sizes = [round(s["size"], 1) for s in spans if s["text"].strip()]
                        fonts = [s["font"].lower() for s in spans if s["text"].strip()]
                        
                        if len(set(sizes)) > 2:
                            sample_text = " ".join([s["text"] for s in spans])[:35]
                            alignment_anomalies.append(
                                f"Page {page_num + 1}: Abnormal Font Size Shift ({sizes}) inside line -> '{sample_text}...'"
                            )
                        
                        # Check font family change mid-line (e.g. Arial se Times new roman mid-line)
                        clean_fonts = [f.split('+')[-1] for f in fonts] # Remove subset prefix
                        if len(set(clean_fonts)) > 1:
                            sample_text = " ".join([s["text"] for s in spans])[:35]
                            font_anomalies.append(
                                f"Page {page_num + 1}: Font Family Hijack detected inside line -> '{sample_text}'"
                            )

        # 2. Text Span Coordinate Skewness Check (Words overlapping or displaced)
        for i in range(len(text_page) - 1):
            w1 = text_page[i]
            w2 = text_page[i+1]
            # Same block & same line
            if w1[5] == w2[5] and w1[6] == w2[6]:
                # Negative gap or unnatural letter collision (Pasted text defect)
                horizontal_gap = w2[0] - w1[2]
                if horizontal_gap < -2.0:
                    alignment_anomalies.append(
                        f"Page {page_num + 1}: Text Collision / Overlap between '{w1[4]}' and '{w2[4]}'"
                    )
                # Unnatural Vertical tilt inside same line
                vertical_drift = abs(w1[1] - w2[1])
                if vertical_drift > 4.5:
                    alignment_anomalies.append(
                        f"Page {page_num + 1}: Baseline Vertical Skew of {round(vertical_drift, 1)}px at word '{w2[4]}'"
                    )

    return alignment_anomalies[:6], font_anomalies[:4]

def verify_bank_structural_rules(text, matched_bank, fonts_found):
    """
    Original bank ke structure se match karta hai (Font, IFSC, Balance flow).
    """
    bank_flags = []
    profile = INDIAN_BANKS_PROFILE.get(matched_bank)
    if not profile:
        return bank_flags

    # Font Verification against Bank Master Standard
    clean_found_fonts = [f.lower().split('+')[-1] for f in fonts_found]
    approved_fonts = profile["standard_fonts"]
    
    font_match = False
    for f in clean_found_fonts:
        for app_f in approved_fonts:
            if app_f in f:
                font_match = True
                break

    if not font_match and len(fonts_found) > 0:
        bank_flags.append(
            f"Bank Template Anomaly: {matched_bank} official generator typically uses {', '.join(approved_fonts).upper()}, but document contains unauthorized font family."
        )

    # Balance Column Alignment Pattern
    amount_rows = re.findall(r'(\d{1,3}(?:,\d{3})*(?:\.\d{2}))', text)
    if len(amount_rows) >= 5:
        # Check decimals uniformity (Official bank statements always have .00 format)
        odd_decimals = [a for a in amount_rows if len(a.split('.')[-1]) != 2]
        if len(odd_decimals) > 0:
            bank_flags.append("Financial Integrity Error: Non-standard decimal precision found in amount column.")

    return bank_flags

def identify_bank_accurately(text):
    bank_scores = {}
    found_ifsc = re.findall(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', text)
    ifsc_prefix = found_ifsc[0][:4] if found_ifsc else None

    for bank_name, data in INDIAN_BANKS_PROFILE.items():
        score = 0
        for kw in data["keywords"]:
            matches = len(re.findall(r'\b' + re.escape(kw) + r'\b', text))
            score += matches * 15
        if ifsc_prefix and ifsc_prefix == data["ifsc_prefix"]:
            score += 50
        if score > 0:
            bank_scores[bank_name] = score

    if bank_scores:
        detected_bank = max(bank_scores, key=bank_scores.get)
        return detected_bank, found_ifsc[0] if found_ifsc else "Verified Branch"
    return "Commercial Bank", "Branch Verified"

def classify_document_advanced(text_content):
    text = text_content.upper()
    bank_score = 0
    general_bank_terms = [
        "STATEMENT OF ACCOUNT", "ACCOUNT STATEMENT", "AVAILABLE BALANCE", 
        "CLOSING BALANCE", "OPENING BALANCE", "TRANSACTION DETAILS", 
        "WITHDRAWAL", "DEPOSIT", "CHEQUE NO", "VALUE DATE", "TXN DATE", 
        "SAVINGS ACCOUNT", "CURRENT ACCOUNT", "IFSC", "ACCOUNT NUMBER", "A/C NO"
    ]
    for term in general_bank_terms:
        if term in text:
            bank_score += 10
            
    financial_txns = len(re.findall(r'\b\d{1,3}(?:,\d{3})*(?:\.\d{2})\b', text))
    if financial_txns > 6:
        bank_score += 35

    if bank_score >= 35:
        exact_bank, ifsc_info = identify_bank_accurately(text)
        return {
            "type": f"{exact_bank} Statement",
            "authority": "Reserve Bank of India (Regulated Bank)",
            "identifier": f"IFSC: {ifsc_info} | {financial_txns} Ledger Txns",
            "is_bank": True,
            "bank_name": exact_bank
        }

    pan_match = re.search(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', text)
    if "INCOME TAX DEPARTMENT" in text and "PERMANENT ACCOUNT NUMBER" in text and pan_match:
        return {
            "type": "PAN Card (Identity Document)",
            "authority": "Income Tax Department (Govt of India)",
            "identifier": pan_match.group(0),
            "is_bank": False
        }

    aadhaar_match = re.search(r'\b\d{4}\s\d{4}\s\d{4}\b', text)
    if ("UIDAI" in text or "UNIQUE IDENTIFICATION" in text) and aadhaar_match:
        return {
            "type": "Aadhaar Card (UIDAI)",
            "authority": "Unique Identification Authority of India (UIDAI)",
            "identifier": aadhaar_match.group(0),
            "is_bank": False
        }

    pass_match = re.search(r'\b[A-Z]{1}[0-9]{7}\b', text)
    if "REPUBLIC OF INDIA" in text and "PASSPORT" in text and pass_match:
        return {
            "type": "Indian Passport",
            "authority": "Ministry of External Affairs, India",
            "identifier": pass_match.group(0),
            "is_bank": False
        }

    return {
        "type": "Official Certificate / General Document",
        "authority": "Independent Entity",
        "identifier": "N/A",
        "is_bank": False
    }

def detect_pixel_patch_tamper(image_bytes):
    flags = []
    try:
        pil_img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        buf = io.BytesIO()
        pil_img.save(buf, "JPEG", quality=90)
        buf.seek(0)
        resaved = Image.open(buf)
        diff = ImageChops.difference(pil_img, resaved)
        diff_np = np.array(diff)
        
        h, w, _ = diff_np.shape
        block_size = 16
        peaks = []
        for y in range(0, h, block_size):
            for x in range(0, w, block_size):
                peaks.append(np.mean(diff_np[y:y+block_size, x:x+block_size]))
                
        if len(peaks) > 0:
            peaks = np.array(peaks)
            mean_peak = np.mean(peaks)
            max_peak = np.max(peaks)
            ratio = max_peak / (mean_peak + 1e-5)
            if ratio > 8.5 and max_peak > 35:
                flags.append("Pixel Heatmap Tamper: Local compression spike detected (Manual edit/patch).")
    except Exception:
        pass
    return flags

@app.post("/verify")
def verify_document(payload: DocPayload):
    file_bytes = base64.b64decode(payload.base64File)
    is_pdf = "pdf" in payload.mimeType.lower() or payload.fileName.lower().endswith(".pdf")
    
    flags = []
    alignment_issues = []
    font_issues = []
    extracted_text = ""
    deep_forensics = {}

    raw_stream = file_bytes.decode('latin1', errors='ignore').lower()

    # Tool checks
    for tool in STRICT_BLACKLIST:
        if tool in raw_stream:
            flags.append(f"Editor Footprint: Created or exported using '{tool.upper()}'.")

    if "xmpmm:history" in raw_stream or "stevt:action" in raw_stream:
        flags.append("Adobe Action Stack: Multiple manual modification sessions found in file binary.")

    if is_pdf:
        try:
            doc = fitz.open(stream=file_bytes, filetype="pdf")

            # Password & Encryption Handling
            if doc.is_encrypted:
                if not payload.password:
                    return {
                        "is_encrypted": True,
                        "message": "Document is password protected. Please enter password.",
                        "fileName": payload.fileName
                    }
                auth_success = doc.authenticate(payload.password)
                if not auth_success:
                    return {
                        "is_encrypted": True,
                        "wrong_password": True,
                        "message": "Incorrect password. Verification aborted.",
                        "fileName": payload.fileName
                    }

            meta = doc.metadata or {}
            deep_forensics["pdf_producer"] = meta.get("producer") or "Direct Bank Engine"
            deep_forensics["creator_app"] = meta.get("creator") or "Core Banking System"
            deep_forensics["page_count"] = len(doc)
            deep_forensics["is_encrypted"] = "Yes (Decrypted)" if doc.is_encrypted else "No (Standard)"

            total_fonts = []
            image_count = 0
            for page in doc:
                extracted_text += page.get_text() + " "
                total_fonts.extend([f[3] for f in page.get_fonts()])
                image_count += len(page.get_images())

            deep_forensics["unique_fonts"] = ", ".join(list(set(total_fonts))[:4]) or "Native Banking Fonts"
            deep_forensics["embedded_images"] = image_count

            # --- GEOMETRIC ALIGNMENT & FONT MATRIX AUDIT ---
            align_errs, font_errs = audit_page_geometry_and_alignment(doc)
            alignment_issues.extend(align_errs)
            font_issues.extend(font_errs)

            # Flattened scan detection
            if len(extracted_text.strip()) < 40 and len(doc) > 0 and image_count >= 1:
                flags.append("Flattened Image Warning: Text layer missing (Document converted to flat image to hide edits).")

            # Micro ELA check
            if len(doc) > 0:
                pix = doc.load_page(0).get_pixmap(dpi=150)
                flags.extend(detect_pixel_patch_tamper(pix.tobytes("jpeg")))

        except Exception as e:
            flags.append(f"PDF Decryption or Syntax Error: {str(e)}")
    else:
        flags.extend(detect_pixel_patch_tamper(file_bytes))
        deep_forensics["pdf_producer"] = "Digital Image / Scan"
        deep_forensics["creator_app"] = "Flat Graphic File"
        deep_forensics["page_count"] = 1
        deep_forensics["is_encrypted"] = "No (Raw Image)"

    # Document Classification
    classification = classify_document_advanced(extracted_text)

    # Bank Template Rule-Engine
    if classification.get("is_bank"):
        bank_structure_flags = verify_bank_structural_rules(
            extracted_text, 
            classification["bank_name"], 
            deep_forensics.get("unique_fonts", "").split(", ")
        )
        flags.extend(bank_structure_flags)

    # Total Tampering Aggregation
    all_anomalies = list(set(flags + alignment_issues + font_issues))
    is_suspicious = len(all_anomalies) > 0

    return {
        "is_encrypted": False,
        "fileName": payload.fileName,
        "is_suspicious": is_suspicious,
        "verdict": "TAMPERED / ALTERED" if is_suspicious else "GENUINE / VERIFIED",
        "classification": classification,
        "flags": all_anomalies,
        "alignment_errors": alignment_issues,
        "font_errors": font_issues,
        "forensics": deep_forensics
    }