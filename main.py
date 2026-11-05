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

class DocPayload(BaseModel):
    fileName: str
    mimeType: str
    base64File: str
    password: str = ""

@app.get("/")
def home():
    return {"status": "Advanced Cognitive Forensic API is Live!"}

def classify_document_advanced(text_content):
    """
    Weighted Context Scoring:
    Ab single PAN number dekhkar confuse nahi hoga. Pure document ka weight count karega.
    """
    text = text_content.upper()
    
    # 1. Bank Statement Scoring Signals
    bank_score = 0
    bank_keywords = [
        "STATEMENT OF ACCOUNT", "ACCOUNT STATEMENT", "AVAILABLE BALANCE", 
        "CLOSING BALANCE", "OPENING BALANCE", "TRANSACTION DETAILS", 
        "DEBIT", "CREDIT", "WITHDRAWAL", "DEPOSIT", "CHEQUE NO", 
        "VALUE DATE", "TXN DATE", "SAVINGS ACCOUNT", "CURRENT ACCOUNT", 
        "IFSC", "MICR", "BRANCH CODE", "ACCOUNT NUMBER", "A/C NO"
    ]
    for kw in bank_keywords:
        if kw in text:
            bank_score += 10
            
    # Indian Banks Name Matching
    bank_names = [
        "HDFC BANK", "STATE BANK OF INDIA", "SBI", "ICICI BANK", 
        "AXIS BANK", "PUNJAB NATIONAL BANK", "PNB", "KOTAK MAHINDRA", 
        "BANK OF BARODA", "CANARA BANK", "UNION BANK", "INDUSIND"
    ]
    matched_bank = None
    for b in bank_names:
        if b in text:
            bank_score += 25
            matched_bank = b
            break

    # Transaction regex check (Numbers with balance pattern e.g. 12,450.00)
    financial_numbers = len(re.findall(r'\b\d{1,3}(?:,\d{3})*(?:\.\d{2})\b', text))
    if financial_numbers > 8:
        bank_score += 30

    # 2. PAN Card Scoring Signals
    pan_score = 0
    pan_match = re.search(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', text)
    if "INCOME TAX DEPARTMENT" in text:
        pan_score += 50
    if "PERMANENT ACCOUNT NUMBER" in text or "GOVT. OF INDIA" in text:
        pan_score += 30
    if "FATHER'S NAME" in text or "DATE OF BIRTH" in text:
        pan_score += 15
    if pan_match and bank_score < 20: # Sirf tab count hoga jab bank indicators na ho
        pan_score += 25

    # 3. Aadhaar Scoring Signals
    aadhaar_score = 0
    aadhaar_match = re.search(r'\b\d{4}\s\d{4}\s\d{4}\b', text)
    if "UIDAI" in text or "UNIQUE IDENTIFICATION" in text:
        aadhaar_score += 60
    if "MERA AADHAAR" in text or "ENROLMENT NO" in text:
        aadhaar_score += 30
    if aadhaar_match:
        aadhaar_score += 20

    # --- FINAL DECISION ARBITRATION ---
    
    # Priority 1: Bank Statement (Agar ledger transaction data hai toh bank hi hoga)
    if bank_score >= 30:
        bank_label = matched_bank if matched_bank else "Indian Commercial Bank"
        return {
            "type": f"{bank_label} Statement",
            "authority": "Reserve Bank of India (Regulated Bank)",
            "identifier": f"Active Ledger ({financial_numbers} transactions parsed)",
            "format_valid": True
        }

    # Priority 2: Genuine PAN Card Document
    elif pan_score >= 40 and pan_match:
        return {
            "type": "PAN Card (Identity Document)",
            "authority": "Income Tax Department (Govt of India)",
            "identifier": pan_match.group(0),
            "format_valid": True
        }

    # Priority 3: Aadhaar Card
    elif aadhaar_score >= 35:
        return {
            "type": "Aadhaar Card (UIDAI)",
            "authority": "Unique Identification Authority of India (UIDAI)",
            "identifier": aadhaar_match.group(0) if aadhaar_match else "Masked/Verified",
            "format_valid": True
        }

    # Priority 4: Indian Passport
    elif "REPUBLIC OF INDIA" in text and "PASSPORT" in text:
        pass_match = re.search(r'\b[A-Z]{1}[0-9]{7}\b', text)
        return {
            "type": "Indian Passport",
            "authority": "Ministry of External Affairs, India",
            "identifier": pass_match.group(0) if pass_match else "Extracted",
            "format_valid": bool(pass_match)
        }

    # Fallback
    return {
        "type": "General Financial / Enterprise Document",
        "authority": "Independent Issuer",
        "identifier": "N/A",
        "format_valid": True
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
                flags.append("Local Compression Mismatch: Specific text/number area re-compressed separately (Cut/Paste).")
    except Exception:
        pass
    return flags

@app.post("/verify")
def verify_document(payload: DocPayload):
    file_bytes = base64.b64decode(payload.base64File)
    is_pdf = "pdf" in payload.mimeType.lower() or payload.fileName.lower().endswith(".pdf")
    
    flags = []
    is_suspicious = False
    extracted_text = ""
    deep_forensics = {}

    raw_stream = file_bytes.decode('latin1', errors='ignore').lower()

    # Tool checks
    for tool in STRICT_BLACKLIST:
        if tool in raw_stream:
            flags.append(f"Editor Footprint Detected: Created or exported using '{tool.upper()}'.")
            is_suspicious = True

    if "xmpmm:history" in raw_stream or "stevt:action" in raw_stream:
        flags.append("Active Adobe Edit Stack: Internal XMP history reveals multiple manual modification sessions.")
        is_suspicious = True

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
            deep_forensics["pdf_producer"] = meta.get("producer") or "Not Declared"
            deep_forensics["creator_app"] = meta.get("creator") or "Not Declared"
            deep_forensics["creation_date"] = meta.get("creationDate") or "Unknown"
            deep_forensics["modification_date"] = meta.get("modDate") or "Unknown"
            deep_forensics["page_count"] = len(doc)
            deep_forensics["pdf_format"] = f"v{meta.get('format', '1.4')}"
            deep_forensics["is_encrypted"] = "Yes (Password Protected / Decrypted)" if doc.is_encrypted else "No (Standard)"

            total_fonts = []
            image_count = 0
            for page in doc:
                extracted_text += page.get_text() + " "
                total_fonts.extend([f[3] for f in page.get_fonts()])
                image_count += len(page.get_images())

            deep_forensics["unique_fonts"] = ", ".join(list(set(total_fonts))[:4]) or "Standard Raster"
            deep_forensics["embedded_images"] = image_count

            # Flattened scan detection
            if len(extracted_text.strip()) < 40 and len(doc) > 0 and image_count >= 1:
                flags.append("Flattened Image Warning: Bank document text layer removed (Converted into a flat raster).")
                is_suspicious = True

            if len(doc) > 0:
                pix = doc.load_page(0).get_pixmap(dpi=150)
                flags.extend(detect_pixel_patch_tamper(pix.tobytes("jpeg")))

        except Exception as e:
            flags.append(f"PDF Decryption or Syntax Error: {str(e)}")
            is_suspicious = True
    else:
        flags.extend(detect_pixel_patch_tamper(file_bytes))
        deep_forensics["pdf_producer"] = "Digital Image / Camera"
        deep_forensics["creator_app"] = "Flat Graphic File"
        deep_forensics["page_count"] = 1
        deep_forensics["is_encrypted"] = "No (Raw Image)"

    if len(flags) > 0:
        is_suspicious = True

    # Advance Cognitive Classification Call
    classification = classify_document_advanced(extracted_text)
    unique_flags = list(set(flags))

    return {
        "is_encrypted": False,
        "fileName": payload.fileName,
        "is_suspicious": is_suspicious,
        "verdict": "TAMPERED / FORGED" if is_suspicious else "GENUINE / VERIFIED",
        "classification": classification,
        "flags": unique_flags,
        "forensics": deep_forensics
    }