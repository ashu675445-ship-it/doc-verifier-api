import base64
import io
import fitz  # PyMuPDF
from fastapi import FastAPI
from pydantic import BaseModel
from PIL import Image, ImageChops, ImageStat
import numpy as np
import cv2

app = FastAPI()

SUSPICIOUS_TOOLS = [
    "photoshop", "gimp", "canva", "ilovepdf", "sejda", 
    "pdfescape", "smallpdf", "paint", "pixlr"
]

# AI aur Generative tools ke traces
AI_MARKERS = [
    "midjourney", "stable diffusion", "dall-e", "comfyui", 
    "automatic1111", "adobe firefly", "c2pa", "generator", "inpainting"
]

class DocPayload(BaseModel):
    fileName: str
    mimeType: str
    base64File: str

@app.get("/")
def home():
    return {"status": "Doc Verifier API is Live!"}

def check_ai_and_noise_anomalies(img_bytes):
    flags = []
    
    # 1. Image EXIF & Raw Header String Check
    raw_str = img_bytes.decode('latin1', errors='ignore').lower()
    for marker in AI_MARKERS:
        if marker in raw_str:
            flags.append(f"AI Generation marker found: {marker.upper()}")

    # 2. Convert to OpenCV Image
    nparr = np.frombuffer(img_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        return flags

    # 3. Noise & Laplacian Variance Check (AI Inpainting Detection)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
    
    # Real camera/scanned documents have sensor noise (variance usually > 150)
    # AI generated text/document areas often have unnaturally flat noise (< 40)
    if laplacian_var < 45.0:
        flags.append("Abnormal smoothness detected (Possible AI generation or heavy smoothing).")

    # 4. Error Level Analysis (ELA)
    pil_img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    buffer = io.BytesIO()
    pil_img.save(buffer, "JPEG", quality=90)
    buffer.seek(0)
    resaved = Image.open(buffer)
    
    diff = ImageChops.difference(pil_img, resaved)
    stat = ImageStat.Stat(diff)
    max_channel_diff = max(stat.mean)
    
    if max_channel_diff > 12.0:
        flags.append("Multi-layer compression mismatch (Document parts re-compressed separately).")

    return flags

@app.post("/verify")
def verify_document(payload: DocPayload):
    file_bytes = base64.b64decode(payload.base64File)
    flags = []
    metadata_info = {}
    is_suspicious = False
    
    # PDF Processing
    if "pdf" in payload.mimeType.lower() or payload.fileName.lower().endswith(".pdf"):
        try:
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            meta = doc.metadata or {}
            producer = (meta.get("producer") or "").lower()
            creator = (meta.get("creator") or "").lower()
            
            metadata_info = {
                "producer": meta.get("producer", "Unknown"),
                "creator": meta.get("creator", "Unknown"),
                "pages": len(doc)
            }
            
            for tool in SUSPICIOUS_TOOLS:
                if tool in producer or tool in creator:
                    flags.append(f"Tampering tool detected in metadata: {tool.upper()}")
            
            # Check for AI markers in raw PDF streams
            raw_pdf = file_bytes.decode('latin1', errors='ignore').lower()
            for ai in AI_MARKERS:
                if ai in raw_pdf:
                    flags.append(f"AI trace detected in PDF internals: {ai.upper()}")

            if doc.is_repaired:
                flags.append("PDF structure has been modified or repaired.")

            # PDF ke first page ko image me convert karke visual check karo
            page = doc.load_page(0)
            pix = page.get_pixmap()
            img_bytes = pix.tobytes("jpeg")
            img_flags = check_ai_and_noise_anomalies(img_bytes)
            flags.extend(img_flags)

        except Exception as e:
            flags.append(f"PDF read error: {str(e)}")

    # Image Processing (JPG/PNG)
    elif "image" in payload.mimeType.lower():
        try:
            img_flags = check_ai_and_noise_anomalies(file_bytes)
            flags.extend(img_flags)
        except Exception as e:
            flags.append(f"Image analysis error: {str(e)}")

    if len(flags) > 0:
        is_suspicious = True

    return {
        "fileName": payload.fileName,
        "is_suspicious": is_suspicious,
        "flags": flags,
        "details": metadata_info
    }