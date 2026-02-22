"""Image analysis — PIL, QR, steganography, OCR."""
from __future__ import annotations
import io, logging
from ..models import ImageAnalysis
from ..constants import MAX_IMAGE_SIZE

log = logging.getLogger("sherlock.images")
PIL_OK = QR_OK = STEGANO_OK = OCR_OK = False

try:
    from PIL import Image as PilImage
    PilImage.MAX_IMAGE_PIXELS = 178_956_970
    PIL_OK = True
except ImportError: pass
try:
    from pyzbar.pyzbar import decode as decode_qr; QR_OK = True
except ImportError: pass
try:
    from stegano import lsb; STEGANO_OK = True
except ImportError: pass
try:
    import pytesseract; OCR_OK = True
except ImportError: pass


def analyze_image(part) -> ImageAnalysis:
    fname = part.get_filename() or "image"
    r = ImageAnalysis(filename=fname)
    try:
        data = part.get_payload(decode=True)
        if not data:
            return r
        if len(data) > MAX_IMAGE_SIZE:
            r.findings.append(f"Image too large ({len(data)//1024//1024}MB) — skipped")
            return r
        r.data = data
        if not PIL_OK:
            return r
        img = PilImage.open(io.BytesIO(data))
        r.fmt = img.format or ""
        r.size = img.size
        if img.size[0] <= 2 and img.size[1] <= 2:
            r.findings.append("Tracking pixel (<=2x2)")
        if QR_OK:
            try:
                for d in decode_qr(img):
                    url = d.data.decode('utf-8', 'ignore')
                    r.qr_links.append(url)
                    r.findings.append(f"QR: {url[:50]}")
            except Exception: pass
        if STEGANO_OK and r.fmt in ('PNG', 'BMP', 'TIFF'):
            try:
                if lsb.reveal(io.BytesIO(data)):
                    r.has_steg = True
                    r.findings.append("STEGANOGRAPHY: hidden LSB data")
            except Exception: pass
        if OCR_OK and r.fmt in ('PNG', 'JPEG', 'JPG', 'BMP', 'TIFF', 'GIF'):
            try:
                text = pytesseract.image_to_string(img, timeout=10)
                if text and len(text.strip()) > 20:
                    r.ocr_text = text.strip()
                    r.findings.append(f"OCR: {len(r.ocr_text)} chars")
            except Exception: pass
    except Exception as e:
        log.error(f"Image analysis: {e}")
    return r
