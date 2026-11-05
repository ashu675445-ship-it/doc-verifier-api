import base64
import io
import re
import fitz  # PyMuPDF
from fastapi import FastAPI
from pydantic import BaseModel
from PIL import Image, ImageChops, ExifTags
import numpy as np
import cv2

app = FastAPI()

SUSPICIOUS_TOOLS = [
    "photoshop", "illustrator", "canva", "gimp", "ilovepdf", "sejda", 
    "pdfescape", "smallpdf", "paint", "pixlr", "coreldraw", "inkscape",
    "acrobat distiller", "pdfcpu", "itext", "wkhtmltopdf", "skia"
]

class DocPayload(BaseModel):
    fileName: str
    mimeType: str
    base64File: str

@app.get("/")
def home():
    return {"status": "Forensic Master API is Live!"}

def parse_pdf_date(date_str):
    """PDF raw date (D:YYYYMMDDHHmmSSOHH'mm') ko clean readable text me convert karta hai."""
    if not date_str:
        return "Not Available"
    clean = date_str.replace("D:", "")
    match = re.match(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", clean)
    if match:
        y, m, d, hh, mm, ss = match.groups()
        return f"{d}-{m}-{y} {hh}:{mm}:{ss} UTC"
    return date_str

def extract_deep_metadata(file_bytes, is_pdf=True):
    forensic_data = {
        "created_at": "Unknown",
        "modified_at": "Unknown",
        "software_used": "Unknown / Stripped",
        "os_platform": "Not explicitly tagged",
        "hardware_device": "Digital Generation / Flat File",
        "color_profile": "Standard (sRGB)",
        "pdf_producer": "N/A",
        "pdf_version": "N/A",
        "has_history_log": False,
        "raw_xmp_history": []
    }
    
    raw_str = file_bytes.decode('latin1', errors='ignore')
    
    # 1. XMP History Parsing (Photoshop/Illustrator action stack)
    if "xmpMM:History" in raw_str or "stEvt:action" in raw_str:
        forensic_data["has_history_log"] = True
        actions = re.findall(r'stEvt:action="([^"]+)"', raw_str)
        softwares = re.findall(r'stEvt:softwareAgent="([^"]+)"', raw_str)
        times = re.findall(r'stEvt:when="([^"]+)"', raw_str)
        
        history_summary = []
        for i in range(min(len(actions), len(softwares))):
            t = times[i] if i < len(times) else "Unknown Time"
            history_summary.append(f"Action: {actions[i]} | App: {softwares[i]} | Date: {t}")
        forensic_data["raw_xmp_history"] = history_summary[:5]

    # 2. PDF Deep Inspection
    if is_pdf:
        try:
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            meta = doc.metadata or {}
            forensic_data["created_at"] = parse_pdf_date(meta.get("creationDate"))
            forensic_data["modified_at"] = parse_pdf_date(meta.get("modDate"))
            forensic_data["software_used"] = meta.get("creator") or "Unknown"
            forensic_data["pdf_producer"] = meta.get("producer") or "Unknown"
            forensic_data["pdf_version"] = f"v{doc.metadata.get('format', '1.4')}"
        except Exception:
            pass
            
    # 3. Image EXIF Parsing
    else:
        try:
            pil_img = Image.open(io.BytesIO(file_bytes))
            exif = pil_img.getexif()
            if exif:
                exif_dict = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
                forensic_data["created_at"] = exif_dict.get("DateTimeOriginal", exif_dict.get("DateTime", "Unknown"))
                forensic_data["modified_at"] = exif_dict.get("DateTime", "Unknown")
                forensic_data["software_used"] = exif_dict.get("Software", "Unknown")
                forensic_data["hardware_device"] = f"{exif_dict.get('Make', '')} {exif_dict.get('Model', '')}".strip() or "Digital Flat Render"
        except Exception:
            pass

    return forensic_data

def micro_tamper_detection(image_bytes):
    flags = []
    
    # 1. Local Block ELA Check
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
            ratio = np.max(peaks) / (np.mean(peaks) + 1e-5)
            if ratio > 4.5 and np.max(peaks) > 15:
                flags.append("Localized Compression Spike: Single word/number modification detected in image grid.")
    except Exception:
        pass

    # 2. Local Font Sharpness & Resolution Variance
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img_cv is not None:
            gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
            grad_x = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
            grad_y = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
            grad_mag = cv2.magnitude(grad_x, grad_y)
            
            _, thresh = cv2.threshold(gray, 200, 255, cv2.THRESH_BINARY_INV)
            contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            scores = []
            for c in contours:
                cx, cy, cw, ch = cv2.boundingRect(c)
                if 8 < ch < 60 and cw > 8:
                    scores.append(np.std(grad_mag[cy:cy+ch, cx:cx+cw]))
            if len(scores) > 10:
                scores = np.array(scores)
                if len(np.where(scores > (np.median(scores) * 3.2))[0]) >= 1:
                    flags.append("Font Sharpness Inconsistency: Pasted text detected with mismatched edge DPI.")
    except Exception:
        pass

    return flags

@app.post("/verify")
def verify_document(payload: DocPayload):
    file_bytes = base64.b64decode(payload.base64File)
    flags = []
    is_pdf = "pdf" in payload.mimeType.lower() or payload.fileName.lower().endswith(".pdf")
    
    forensics = extract_deep_metadata(file_bytes, is_pdf=is_pdf)
    
    # Check suspicious software in metadata
    combined_meta_str = f"{forensics['software_used']} {forensics['pdf_producer']}".lower()
    for tool in SUSPICIOUS_TOOLS:
        if tool in combined_meta_str:
            flags.append(f"Editor Signature: Generated/Exported via '{tool.upper()}'.")

    # Timestamp mismatch check
    if forensics["created_at"] != "Unknown" and forensics["modified_at"] != "Unknown":
        if forensics["created_at"] != forensics["modified_at"]:
            flags.append(f"Timestamp Mismatch: Original created at {forensics['created_at']}, but re-saved at {forensics['modified_at']}.")

    # Micro pixel checks
    if is_pdf:
        try:
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            for page in doc:
                pix = page.get_pixmap(dpi=150)
                img_flags = micro_tamper_detection(pix.tobytes("jpeg"))
                flags.extend(img_flags)
                break
        except Exception as e:
            flags.append(f"PDF Parsing Warning: {str(e)}")
    else:
        flags.extend(micro_tamper_detection(file_bytes))

    unique_flags = list(set(flags))
    
    return {
        "fileName": payload.fileName,
        "is_suspicious": len(unique_flags) > 0,
        "flags": unique_flags,
        "forensics": forensics
    }