import base64
import io
import fitz  # PyMuPDF
from fastapi import FastAPI
from pydantic import BaseModel
from PIL import Image, ImageChops
import numpy as np
import cv2

app = FastAPI()

SUSPICIOUS_TOOLS = [
    "photoshop", "illustrator", "canva", "gimp", "ilovepdf", "sejda", 
    "pdfescape", "smallpdf", "paint", "pixlr", "coreldraw", "acrobat distiller",
    "pdfcpu", "itext", "inkscape"
]

AI_AND_EDIT_TAGS = [
    "adobe", "photoshop", "illustrator", "xmp", "creatoratom", "history:action",
    "stevt:action", "saved", "derivedfrom", "c2pa", "midjourney", "inpaint"
]

class DocPayload(BaseModel):
    fileName: str
    mimeType: str
    base64File: str

@app.get("/")
def home():
    return {"status": "Deep Forensic Verifier API is Live!"}

def micro_tamper_detection(image_bytes):
    flags = []
    
    # 1. Byte Stream Me Deep Adobe / XMP History Check
    # (Photoshop/Illustrator export ke baad bhi XMP packet binary me chhod dete hain)
    raw_bytes = image_bytes.decode('latin1', errors='ignore').lower()
    for tag in AI_AND_EDIT_TAGS:
        if tag in raw_bytes:
            if tag in ["photoshop", "illustrator", "canva", "stevt:action", "derivedfrom"]:
                flags.append(f"Deep Software Footprint Detected in Binary: {tag.upper()}")
                break

    # 2. Localized Patch-Level ELA (Word-Level Editing Catch)
    pil_img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    buffer = io.BytesIO()
    pil_img.save(buffer, "JPEG", quality=90)
    buffer.seek(0)
    resaved = Image.open(buffer)
    
    diff = ImageChops.difference(pil_img, resaved)
    diff_np = np.array(diff)
    
    # Pure image ki jagah 16x16 ke blocks me check karo
    h, w, _ = diff_np.shape
    block_size = 16
    local_peaks = []
    
    for y in range(0, h, block_size):
        for x in range(0, w, block_size):
            block = diff_np[y:y+block_size, x:x+block_size]
            local_peaks.append(np.mean(block))
            
    if len(local_peaks) > 0:
        local_peaks = np.array(local_peaks)
        peak_ratio = np.max(local_peaks) / (np.mean(local_peaks) + 1e-5)
        # Agar koi ek chota block baki image ke comparison me achanak zyada chamak raha ho
        if peak_ratio > 4.5 and np.max(local_peaks) > 15:
            flags.append("Localized Content Tampering: Single word/number modification detected via micro-compression difference.")

    # 3. OpenCV Local Sharpness & Inconsistent Font Edges
    nparr = np.frombuffer(image_bytes, np.uint8)
    img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    
    if img_cv is not None:
        gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        
        # Sobel gradient se har text block ki sharpness alag-alag measure karna
        grad_x = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
        grad_y = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
        grad_mag = cv2.magnitude(grad_x, grad_y)
        
        # Bounding box extraction text blocks ke liye
        _, thresh = cv2.threshold(gray, 200, 255, cv2.THRESH_BINARY_INV)
        contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        sharpness_scores = []
        for c in contours:
            cx, cy, cw, ch = cv2.boundingRect(c)
            # Sirf words/letters ke size wale blocks filter karo
            if 8 < ch < 60 and cw > 8:
                roi_grad = grad_mag[cy:cy+ch, cx:cx+cw]
                sharpness_scores.append(np.std(roi_grad))
                
        if len(sharpness_scores) > 10:
            sharpness_scores = np.array(sharpness_scores)
            median_val = np.median(sharpness_scores)
            # Agar koi letter/word document ke baaki text se abnormal sharp ya alag resolution ka hai
            anomalies = np.where(sharpness_scores > (median_val * 3.0))[0]
            if len(anomalies) >= 1:
                flags.append("Font / Text Resolution Mismatch: Ek ya zyada words alag resolution/sharpness ke paste kiye gaye hain.")

    return flags

@app.post("/verify")
def verify_document(payload: DocPayload):
    file_bytes = base64.b64decode(payload.base64File)
    flags = []
    metadata_info = {}
    
    # PDF Verification
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
                    flags.append(f"Software metadata signature matched: {tool.upper()}")

            # PDF Layer check (Kya isme multi-layer text overwrite hua hai?)
            for page_index in range(len(doc)):
                page = doc.load_page(page_index)
                fonts = page.get_fonts()
                # Agar multiple unusual font families use hui hain ek hi page par
                if len(fonts) > 8:
                    flags.append("Irregular Font Variations: Page contains multiple stitched font layers.")
                    break
                
                # Render to high-res image and apply micro-forensics
                pix = page.get_pixmap(dpi=150)
                img_bytes = pix.tobytes("jpeg")
                img_flags = micro_tamper_detection(img_bytes)
                flags.extend(img_flags)

        except Exception as e:
            flags.append(f"PDF Analysis Error: {str(e)}")

    # Image Verification (JPG / PNG)
    elif "image" in payload.mimeType.lower():
        try:
            img_flags = micro_tamper_detection(file_bytes)
            flags.extend(img_flags)
        except Exception as e:
            flags.append(f"Image Analysis Error: {str(e)}")

    # Duplicate flags hatao
    unique_flags = list(set(flags))
    
    return {
        "fileName": payload.fileName,
        "is_suspicious": len(unique_flags) > 0,
        "flags": unique_flags,
        "details": metadata_info
    }