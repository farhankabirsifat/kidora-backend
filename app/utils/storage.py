from pathlib import Path
import os
import uuid
import shutil
from typing import List, Optional
from fastapi import UploadFile
from urllib.parse import urlparse
from urllib.request import urlopen

BASE_DIR = Path(__file__).resolve().parents[2]
MEDIA_ROOT = BASE_DIR / "media"

def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def save_upload_file(upload_file: UploadFile, subdir: str = "products") -> str:
    """Save a single UploadFile to media/subdir and return its URL path (/media/subdir/filename)."""
    if not upload_file or not upload_file.filename:
        raise ValueError("No file provided")
    ext = os.path.splitext(upload_file.filename)[1].lower()
    filename = f"{uuid.uuid4().hex}{ext}"
    dst_dir = MEDIA_ROOT / subdir
    _ensure_dir(dst_dir)
    file_path = dst_dir / filename
    with file_path.open("wb") as buffer:
        shutil.copyfileobj(upload_file.file, buffer)
    return f"/media/{subdir}/{filename}"

def save_multiple_upload_files(files: List[UploadFile], subdir: str = "products") -> List[str]:
    """Save multiple UploadFiles and return a list of URL paths."""
    urls: List[str] = []
    for f in files or []:
        if f and f.filename:
            urls.append(save_upload_file(f, subdir=subdir))
    return urls

# New: save from local path or URL

def _pick_ext_from_content_type(ct: Optional[str]) -> str:
    mapping = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/gif": ".gif",
        "image/webp": ".webp",
        "image/bmp": ".bmp",
    }
    return mapping.get((ct or "").split(";")[0].strip(), ".bin")

def save_from_path_or_url(src: str, subdir: str = "products") -> str:
    """Copy a file from a local path or download from HTTP(S)/file URL, save under media/subdir, return /media URL."""
    if not src:
        raise ValueError("Empty source")

    parsed = urlparse(src)
    dst_dir = MEDIA_ROOT / subdir
    _ensure_dir(dst_dir)

    # Determine extension
    ext = os.path.splitext(parsed.path if parsed.path else src)[1]

    filename = f"{uuid.uuid4().hex}{ext or ''}"
    file_path = dst_dir / filename

    if parsed.scheme in ("http", "https"):
        with urlopen(src) as resp, file_path.open("wb") as out:
            data = resp.read()
            out.write(data)
        # If no extension, try to use content-type header
        if not ext:
            ct = resp.headers.get("Content-Type") if 'resp' in locals() else None
            if ct:
                new_path = file_path.with_suffix(_pick_ext_from_content_type(ct))
                file_path.rename(new_path)
                file_path = new_path
    elif parsed.scheme == "file":
        local_path = Path(parsed.path)
        shutil.copyfile(local_path, file_path)
    else:
        # Treat as local filesystem path (Windows paths supported)
        local_path = Path(src)
        if not local_path.exists():
            raise FileNotFoundError(f"Source not found: {src}")
        shutil.copyfile(local_path, file_path)

    rel_url = f"/media/{subdir}/{file_path.name}"
    return rel_url


def save_multiple_from_paths_or_urls(sources: List[str], subdir: str = "products") -> List[str]:
    return [save_from_path_or_url(s, subdir=subdir) for s in (sources or []) if s]


def delete_media_file(rel_url: Optional[str]) -> bool:
    """Delete a single media file by its stored relative URL (e.g. /media/products/<file>). Returns True if removed.

    Safety rules:
    - Only operates inside MEDIA_ROOT
    - Ignores None/empty or non /media/ prefixed inputs
    - Silently ignores if file missing
    """
    if not rel_url or not isinstance(rel_url, str):
        return False
    if not rel_url.startswith('/media/'):
        return False
    try:
        # rel_url: /media/<subdir>/<filename>
        parts = rel_url.strip('/').split('/')  # [media, subdir, filename]
        if len(parts) < 3:
            return False
        target_path = MEDIA_ROOT / '/'.join(parts[1:])  # skip leading 'media'
        if target_path.is_file():
            target_path.unlink()
            return True
    except Exception:
        return False
    return False


def delete_media_files(urls: Optional[List[str]]) -> int:
    """Delete multiple media files; returns count of successfully removed files."""
    if not urls:
        return 0
    removed = 0
    for u in urls:
        if delete_media_file(u):
            removed += 1
    return removed
