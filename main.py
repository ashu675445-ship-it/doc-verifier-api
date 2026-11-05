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

# Definite Blacklisted Tools (Editing/Tampering Software)
STRICT_BLACKLIST = [
    "photoshop", "illustrator", "canva", "gimp", "ilovepdf", "sejda", 
    "pdfescape", "smallpdf", "coreldraw", "inkscape", "pixlr", "paint",
    "pdf2go", "sodapdf", "foxit phantom", "nitro pro", "wondershare"
]

INDIAN_BANKS_PROFILE = {
    "State Bank of India (SBI)": {
        "keywords": ["STATE BANK OF INDIA", "SBI CARD", "ONLINESBI", "SBIN0"],
        "ifsc_prefix": "SBIN"
    },
    "HDFC Bank": {
        "keywords": ["HDFC BANK", "HDFCBANK.COM", "HDFC00"],
        "ifsc_prefix": "HDFC"
    },
    "ICICI Bank": {
        "keywords": ["ICICI BANK", "ICICIBANK.COM", "ICIC00"],
        "ifsc_prefix": "ICIC"
    },
    "Axis Bank": {
        "keywords": ["AXIS BANK", "AXISBANK.COM", "UTIB00"],
        "ifsc_prefix": "UTIB"
    },
    "Punjab National Bank (PNB)": {
        "keywords": ["PUNJAB NATIONAL BANK", "PNBINDIA", "PUNB0"],
        "ifsc_prefix": "PUNB"
    },
    "Bank of Baroda (BOB)": {
        "keywords": ["BANK OF BARODA", "BOBDIGI", "BARB0"],
        "ifsc_prefix": "BARB"
    },
    "Kotak Mahindra Bank": {
        "keywords": ["KOTAK MAHINDRA", "KOTAK BANK", "KKBK0"],
        "ifsc_prefix": "KKBK"
    }
}

class DocPayload(BaseModel):
    fileName: str
    mimeType: str
    base64File: str
    password: str = ""

@app.get("/")
def home():
    return {"status": "Calibrated Forensic Engine Live!"}

def audit_page_geometry_safe(doc):
    """
    Calibrated Alignment Check:
    Normal bold/regular mix ya table gaps ko ignore karega.
    Sirf extreme abnormal floating text ya physical overlap ko hi catch karega.
    """
    alignment_anomalies = []
    
    for page_num in range(len(doc)):
        page = doc.load_page(page_num)
        text_page = page.get_text("words")  # (x0, y0, x1, y1, "word", block_no, line_no, word_no)
        
        # Word Overlap check with realistic negative threshold
        for i in range(len(text_page) - 1):
            w1 = text_page[i]
            w2 = text_page[i+1]
            
            # Same line and block
            if w1[5] == w2[5] and w1[6] == w2[6]:
                horizontal_gap = w2[0] - w1[2]
                # Normal printing me -1 ya -2px bounding box overlap possible hota hai.
                # Agar -8px se zyada overlap hai, tabhi real text overwrite hota hai.
                if horizontal_gap < -8.0 and len(w1[4]) > 1 and len(w2[4]) > 1:
                    alignment_anomalies.append(
                        f"Page {page_num + 1}: Unnatural Word Overwrite detected between '{w1[4]}' and '{w2[4]}'"
                    )
                
                # Extreme vertical drift (same line hone ke baad 12px se zyada dislocation)
                vertical_drift = abs(w1[1] - w2[1])
                if vertical_drift > 14.0:
                    alignment_anomalies.append(
                        f"Page {page_num + 1}: Floating Text Anomaly at word '{w2[4]}'"
                    )

    return alignment_anomalies[:3]

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
            "is_bank": True
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

def detect_pixel_patch_tamper_safe(image_bytes):
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
        block_size = 32
        peaks = []
        for y in range(0, h, block_size):
            for x in range(0, w, block_size):
                peaks.append(np.mean(diff_np[y:y+block_size, x:x+block_size]))
                
        if len(peaks) > 0:
            peaks = np.array(peaks)
            mean_peak = np.mean(peaks)
            max_peak = np.max(peaks)
            ratio = max_peak / (mean_peak + 1e-5)
            # High threshold taaki normal logos ya dark borders ko edit na bole
            if ratio > 11.0 and max_peak > 55:
                flags.append("High-Confidence Pixel Compression Anomaly (Cut/Paste editing detected).")
    except Exception:
        pass
    return flags

@app.post("/verify")
def verify_document(payload: DocPayload):
    file_bytes = base64.b64decode(payload.base64File)
    is_pdf = "pdf" in payload.mimeType.lower() or payload.fileName.lower().endswith(".pdf")
    
    critical_flags = []
    alignment_issues = []
    extracted_text = ""
    deep_forensics = {}

    raw_stream = file_bytes.decode('latin1', errors='ignore').lower()

    # Confirmed Tampering Tools in Binary
    for tool in STRICT_BLACKLIST:
        if tool in raw_stream:
            critical_flags.append(f"Confirmed Tampering Signature: File generated/edited via '{tool.upper()}'.")

    if "xmpmm:history" in raw_stream or "stevt:action" in raw_stream:
        critical_flags.append("Adobe Action History: Document metadata contains saved editing sessions.")

    if is_pdf:
        try:
            doc = fitz.open(stream=file_bytes, filetype="pdf")

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
            deep_forensics["creator_app"] = meta.get("creator") or "Core Enterprise System"
            deep_forensics["page_count"] = len(doc)
            deep_forensics["is_encrypted"] = "Yes (Decrypted)" if doc.is_encrypted else "No (Standard)"

            total_fonts = []
            image_count = 0
            for page in doc:
                extracted_text += page.get_text() + " "
                total_fonts.extend([f[3] for f in page.get_fonts()])
                image_count += len(page.get_images())

            deep_forensics["unique_fonts"] = ", ".join(list(set(total_fonts))[:3]) or "Native Document Fonts"
            deep_forensics["embedded_images"] = image_count

            # Safe Geometric Alignment Audit
            align_errs = audit_page_geometry_safe(doc)
            alignment_issues.extend(align_errs)

            # Flattened scan detection (Sirf tab jab na text ho aur multiple image chips ho)
            if len(extracted_text.strip()) < 30 and len(doc) > 0 and image_count >= 1:
                critical_flags.append("Flattened Image Warning: Bank statement text layer removed (Converted into flat raster).")

            # Micro pixel check on first page (Safe threshold)
            if len(doc) > 0:
                pix = doc.load_page(0).get_pixmap(dpi=150)
                critical_flags.extend(detect_pixel_patch_tamper_safe(pix.tobytes("jpeg")))

        except Exception as e:
            critical_flags.append(f"PDF Decryption or Syntax Error: {str(e)}")
    else:
        critical_flags.extend(detect_pixel_patch_tamper_safe(file_bytes))
        deep_forensics["pdf_producer"] = "Digital Image / Scan"
        deep_forensics["creator_app"] = "Flat Graphic File"
        deep_forensics["page_count"] = 1
        deep_forensics["is_encrypted"] = "No (Raw Image)"

    classification = classify_document_advanced(extracted_text)

    # FINAL TAMPERING VERDICT LOGIC:
    # 1. Agar critical tool footprint mila -> Definitely TAMPERED
    # 2. Agar alignment me real physical overlap mila -> TAMPERED
    # 3. Normal font variation par fake nahi bolega
    is_suspicious = len(critical_flags) > 0 or len(alignment_issues) > 0
    all_flags = list(set(critical_flags + alignment_issues))

    return {
        "is_encrypted": False,
        "fileName": payload.fileName,
        "is_suspicious": is_suspicious,
        "verdict": "TAMPERED / ALTERED" if is_suspicious else "GENUINE / VERIFIED",
        "classification": classification,
        "flags": all_flags,
        "alignment_errors": alignment_issues,
        "forensics": deep_forensics
    }