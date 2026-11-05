import base64
import io
import fitz  # PyMuPDF
from fastapi import FastAPI
from pydantic import BaseModel
from PIL import Image, ImageChops, ImageEnhance

app = FastAPI()

# Jin tools se editing pakadni hai
SUSPICIOUS_TOOLS = [
    "photoshop", "gimp", "canva", "ilovepdf", "sejda", 
    "pdfescape", "smallpdf", "paint", "pixlr"
]

class DocPayload(BaseModel):
    fileName: str
    mimeType: str
    base64File: str

@app.get("/")
def home():
    return {"status": "Doc Verifier API is Live!"}

@app.post("/verify")
def verify_document(payload: DocPayload):
    file_bytes = base64.b64decode(payload.base64File)
    flags = []
    metadata_info = {}
    is_suspicious = False
    
    # Check 1: Agar File PDF hai
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
            
            # Editing software footprint check
            for tool in SUSPICIOUS_TOOLS:
                if tool in producer or tool in creator:
                    flags.append(f"Tampering tool detected in metadata: {tool.upper()}")
            
            # Structural repair check
            if doc.is_repaired:
                flags.append("PDF structure has been modified or repaired internally.")
                
        except Exception as e:
            flags.append(f"PDF read error: {str(e)}")

    # Check 2: Agar File Image hai (JPG/PNG)
    elif "image" in payload.mimeType.lower():
        try:
            image = Image.open(io.BytesIO(file_bytes)).convert("RGB")
            # Basic ELA (Error Level Analysis) check
            temp_buffer = io.BytesIO()
            image.save(temp_buffer, "JPEG", quality=90)
            temp_buffer.seek(0)
            resaved = Image.open(temp_buffer)
            
            diff = ImageChops.difference(image, resaved)
            extrema = diff.getextrema()
            max_diff = max([ex[1] for ex in extrema])
            
            if max_diff > 80:  # High compression mismatch
                flags.append("Pixel compression anomaly detected (Possible edit/cut-paste).")
        except Exception as e:
            flags.append(f"Image read error: {str(e)}")

    if len(flags) > 0:
        is_suspicious = True

    return {
        "fileName": payload.fileName,
        "is_suspicious": is_suspicious,
        "flags": flags,
        "details": metadata_info
    }