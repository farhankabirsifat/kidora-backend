from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session
from typing import List, Optional

from app.models.user import get_db
from app.models.hero_banner import HeroBanner
from app.schemas.hero_banner import HeroBannerOut
from app.utils.security import get_current_user, ADMIN_EMAIL
from app.utils.storage import save_upload_file, save_from_path_or_url


router = APIRouter()


def _is_admin(email: str) -> bool:
    return email == ADMIN_EMAIL or email.endswith("@admin") or email == "admin@example.com"


def _to_out(b: HeroBanner) -> HeroBannerOut:
    return HeroBannerOut(
        id=b.id,
        title=b.title,
        subtitle=b.subtitle,
        imageUrl=b.image_url,
        linkUrl=b.link_url,
    )


@router.get("/", response_model=List[HeroBannerOut])
def get_hero_banners(db: Session = Depends(get_db)):
    banners = db.query(HeroBanner).order_by(HeroBanner.created_at.desc()).all()
    return [_to_out(b) for b in banners]


@router.post("/", response_model=HeroBannerOut)
def create_hero_banner(
    title: Optional[str] = Form(None),
    subtitle: Optional[str] = Form(None),
    linkUrl: Optional[str] = Form(None),
    image: UploadFile = File(None),
    imageUrl: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    if not _is_admin(current_user_email):
        raise HTTPException(status_code=403, detail="Admin access required")

    img = None
    if image and image.filename:
        img = save_upload_file(image, subdir="banners")
    elif imageUrl:
        img = save_from_path_or_url(imageUrl, subdir="banners")

    banner = HeroBanner(title=title, subtitle=subtitle, image_url=img, link_url=linkUrl)
    db.add(banner)
    db.commit()
    db.refresh(banner)
    return _to_out(banner)


@router.put("/{id}", response_model=HeroBannerOut)
def update_hero_banner(
    id: int,
    title: Optional[str] = Form(None),
    subtitle: Optional[str] = Form(None),
    linkUrl: Optional[str] = Form(None),
    image: UploadFile = File(None),
    imageUrl: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    if not _is_admin(current_user_email):
        raise HTTPException(status_code=403, detail="Admin access required")
    banner = db.query(HeroBanner).filter(HeroBanner.id == id).first()
    if not banner:
        raise HTTPException(status_code=404, detail="Banner not found")
    banner.title = title
    banner.subtitle = subtitle
    banner.link_url = linkUrl
    if image and image.filename:
        banner.image_url = save_upload_file(image, subdir="banners")
    elif imageUrl:
        banner.image_url = save_from_path_or_url(imageUrl, subdir="banners")
    db.commit()
    db.refresh(banner)
    return _to_out(banner)


@router.delete("/{id}")
def delete_hero_banner(id: int, db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    if not _is_admin(current_user_email):
        raise HTTPException(status_code=403, detail="Admin access required")
    banner = db.query(HeroBanner).filter(HeroBanner.id == id).first()
    if not banner:
        raise HTTPException(status_code=404, detail="Banner not found")
    db.delete(banner)
    db.commit()
    return {"message": "Banner deleted"}
