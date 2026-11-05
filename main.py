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

# Known Govt & Enterprise Trusted Engines
TRUSTED_ISSUERS = {
    "DigiLocker": ["digilocker", "meity", "national e-governance"],
    "UIDAI (Aadhaar)": ["uidai", "aadhaar", "cdac"],
    "Income Tax / NSDL (PAN)": ["protean", "nsdl", "utiitsl", "income tax department"],
    "Indian Banks": ["itext", "jasperreports", "apache fop", "oracle", "birt", "quartz", "skia", "wkhtmltopdf", "cups"]
}

class DocPayload(BaseModel):
    fileName: str
    mimeType: str
    base64File: str

@app.get("/")
def home():
    return {"status": "Universal Forensic Classifier & Verifier is Live!"}

def classify_document(text_content):
    """Document ke text patterns se identify karta hai ki document kya hai."""
    text = text_content.upper()
    
    # 1. PAN Card Check
    if "INCOME TAX DEPARTMENT" in text or "PERMANENT ACCOUNT NUMBER" in text or re.search(r'[A-Z]{5}[0-9]{4}[A-Z]', text):
        pan_match = re.search(r'[A-Z]{5}[0-9]{4}[A-Z]', text)
        pan_num = pan_match.group(0) if pan_match else "Not Extracted"
        return {
            "type": "PAN Card (Identity Document)",
            "authority": "Income Tax Department (Govt of India)",
            "identifier": pan_num,
            "format_valid": bool(pan_match)
        }

    # 2. Aadhaar Card Check
    elif "UIDAI" in text or "UNIQUE IDENTIFICATION AUTHORITY" in text or "AADHAAR" in text or "MERA AADHAAR" in text:
        aadhaar_match = re.search(r'\b\d{4}\s\d{4}\s\d{4}\b', text)
        return {
            "type": "Aadhaar Card (UIDAI)",
            "authority": "Unique Identification Authority of India (UIDAI)",
            "identifier": aadhaar_match.group(0) if aadhaar_match else "Masked/Extracted",
            "format_valid": True
        }

    # 3. Passport
    elif "REPUBLIC OF INDIA" in text and "PASSPORT" in text:
        pass_match = re.search(r'[A-Z]{1}[0-9]{7}', text)
        return {
            "type": "Indian Passport",
            "authority": "Ministry of External Affairs, India",
            "identifier": pass_match.group(0) if pass_match else "Extracted",
            "format_valid": bool(pass_match)
        }

    # 4. Driving License
    elif "DRIVING LICENCE" in text or "UNION OF INDIA DRIVING" in text or "SARATHI" in text:
        return {
            "type": "Driving Licence (MoRTH)",
            "authority": "Ministry of Road Transport and Highways (Sarathi)",
            "identifier": "License Document",
            "format_valid": True
        }

    # 5. Bank Statement
    elif any(bank in text for bank in ["HDFC", "STATE BANK OF INDIA", "SBI", "ICICI", "AXIS BANK", "PUNJAB NATIONAL BANK", "ACCOUNT STATEMENT"]):
        bank_name = "Indian Banking System"
        for b in ["HDFC", "SBI", "STATE BANK OF INDIA", "ICICI", "AXIS BANK", "PNB"]:
            if b in text:
                bank_name = b
                break
        return {
            "type": f"{bank_name} Account Statement",
            "authority": "Reserve Bank of India (Regulated Bank)",
            "identifier": "Financial Ledger",
            "format_valid": True
        }

    # 6. Salary Slip / Invoice
    elif "PAYSLIP" in text or "SALARY SLIP" in text or "TAX INVOICE" in text:
        return {
            "type": "Commercial / Payroll Document",
            "authority": "Corporate Entity / Employer",
            "identifier": "Invoice/Payslip",
            "format_valid": True
        }

    return {
        "type": "General Certificate / Unclassified Document",
        "authority": "Unknown External Entity",
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
            
            if ratio > 8.0 and max_peak > 35:
                flags.append("Local Inconsistency: Specific field/text area exhibits irregular compression (Cut-Paste / Re-typed).")
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
    metadata_info = {}
    
    raw_stream = file_bytes.decode('latin1', errors='ignore').lower()

    # Rule 1: Deep Binary Signature Scan for Tampering Tools
    for tool in STRICT_BLACKLIST:
        if tool in raw_stream:
            flags.append(f"Editor Footprint Detected: Created or exported using '{tool.upper()}'.")
            is_suspicious = True

    # Rule 2: Adobe XMP Lifecycle Logs
    if "xmpmm:history" in raw_stream or "stevt:action" in raw_stream:
        flags.append("Active Adobe Edit Stack: Internal XMP history reveals multiple manual modification sessions.")
        is_suspicious = True

    # PDF Processing
    if is_pdf:
        try:
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            meta = doc.metadata or {}
            metadata_info["producer"] = meta.get("producer") or "Not Declared"
            metadata_info["creator"] = meta.get("creator") or "Not Declared"
            metadata_info["pages"] = len(doc)

            for page in doc:
                extracted_text += page.get_text() + " "

            # Check if official doc is flattened into a dumb image
            if len(extracted_text.strip()) < 40 and len(doc) > 0:
                first_page = doc.load_page(0)
                if len(first_page.get_images()) >= 1:
                    flags.append("Flattened Image Structure: Official document has zero readable text layer (Pura image layer me convert kiya gaya hai).")
                    is_suspicious = True

            # Micro pixel check on first page
            if len(doc) > 0:
                pix = doc.load_page(0).get_pixmap(dpi=150)
                flags.extend(detect_pixel_patch_tamper(pix.tobytes("jpeg")))

        except Exception as e:
            flags.append(f"PDF Parsing Exception: {str(e)}")
            is_suspicious = True
    else:
        # Image Processing (JPG/PNG)
        flags.extend(detect_pixel_patch_tamper(file_bytes))
        metadata_info["producer"] = "Digital Image / Scan"
        metadata_info["creator"] = "Graphic File"
        metadata_info["pages"] = 1

    if len(flags) > 0:
        is_suspicious = True

    # Classify Document
    classification = classify_document(extracted_text)

    # Specific Sanity Checks per Document
    if classification["type"].startswith("PAN Card") and not classification["format_valid"]:
        flags.append("PAN Format Failure: Text contains PAN header but alphanumeric pattern is invalid.")
        is_suspicious = True

    unique_flags = list(set(flags))

    return {
        "fileName": payload.fileName,
        "is_suspicious": is_suspicious,
        "verdict": "TAMPERED / FORGED" if is_suspicious else "GENUINE / VERIFIED",
        "classification": classification,
        "flags": unique_flags,
        "metadata": metadata_info
    }