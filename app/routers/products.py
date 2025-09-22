from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.models.product import Product
from urllib.parse import urlparse, parse_qs


def _normalize_video_embed(url: Optional[str]) -> Optional[str]:
    """Convert common YouTube URLs (watch, youtu.be, shorts) to embeddable format.
    Returns the original URL if it doesn't match known patterns or is falsy."""
    if not url:
        return url
    try:
        u = str(url).strip()
        p = urlparse(u)
        host = (p.netloc or '').lower()
        path = (p.path or '').strip('/').split('/')

        # youtu.be/<id>
        if 'youtu.be' in host and path and path[0]:
            vid = path[0]
            return f"https://www.youtube.com/embed/{vid}"

        # youtube.com/shorts/<id>
        if 'youtube.com' in host and len(path) >= 2 and path[0] == 'shorts' and path[1]:
            vid = path[1]
            return f"https://www.youtube.com/embed/{vid}"

        # youtube.com/watch?v=<id>
        if 'youtube.com' in host and (path and path[0] == 'watch'):
            q = parse_qs(p.query or '')
            vid = (q.get('v') or [None])[0]
            if vid:
                return f"https://www.youtube.com/embed/{vid}"

        # Already embed or unknown — return as-is
        return u
    except Exception:
        return url
from sqlalchemy import func, or_
from app.models.user import get_db
from app.schemas.product import ProductOut
from app.utils.security import get_current_user, is_admin_email
from app.utils.storage import (
    save_upload_file,
    save_multiple_upload_files,
    save_from_path_or_url,
    save_multiple_from_paths_or_urls,
    delete_media_file,
    delete_media_files,
)

router = APIRouter()

# Helpers

def parse_images(images_json: Optional[List[str]]) -> List[str]:
    return images_json or []

def to_product_out(p: Product) -> ProductOut:
    return ProductOut(
        id=p.id,
        title=p.title,
        description=p.description,
        price=p.price,
        category=p.category,
        stock=p.stock,
        rating=p.rating,
        discount=p.discount,
        main_image=p.main_image,
        video=_normalize_video_embed(p.video_url),
        images=parse_images(p.images),
        sizes_stock=p.sizes_stock or None,
        free_shipping=bool(getattr(p, 'free_shipping', False)),
    )

# 6. Get All Products (with filters)
@router.get("/", response_model=List[ProductOut])
def get_all_products(
    page: int = Query(0, ge=0),
    size: int = Query(20, ge=1),
    category: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List products with optional case-insensitive category and title search."""
    query = db.query(Product)
    if category:
        # Support comma-separated categories for inclusive filter (e.g. "kids,girls,boys")
        cats = [c.strip().lower() for c in category.split(',') if c.strip()]
        if cats:
            partial_stems = {"kid", "girl", "boy", "child"}
            conditions = []
            for c in cats:
                if c in partial_stems:
                    # Allow exact, plural, and categories that start with the stem (avoids 'men' matching 'women')
                    conditions.append(func.lower(Product.category) == c)
                    conditions.append(func.lower(Product.category) == f"{c}s")
                    conditions.append(Product.category.ilike(f"{c}%"))
                else:
                    # Exact, case-insensitive match for non-stem categories like 'men'/'women'
                    conditions.append(func.lower(Product.category) == c)
            query = query.filter(or_(*conditions))
    if search:
        query = query.filter(Product.title.ilike(f"%{search}%"))
    products = query.offset(page * size).limit(size).all()
    return [to_product_out(p) for p in products]


@router.get("/categories", response_model=List[str])
def list_categories(db: Session = Depends(get_db)):
    """Return distinct product categories (lowercased, sorted)."""
    rows = db.query(func.lower(Product.category)).filter(Product.category.isnot(None)).distinct().all()
    cats = sorted({r[0] for r in rows if r and r[0]})
    return cats


@router.get("/category-counts")
def category_counts(db: Session = Depends(get_db)):
    """Return counts of products grouped by category (lowercased)."""
    rows = (
        db.query(func.lower(Product.category).label("category"), func.count().label("count"))
        .filter(Product.category.isnot(None))
        .group_by(func.lower(Product.category))
        .all()
    )
    return [{"category": r.category, "count": int(r.count)} for r in rows]

# 7. Get Product by ID
@router.get("/{id}", response_model=ProductOut)
def get_product_by_id(id: int, db: Session = Depends(get_db)):
    product = db.query(Product).filter(Product.id == id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return to_product_out(product)

# 10. Create Product (Admin)
@router.post("/admin", response_model=ProductOut)
def create_product(
    title: str = Form(...),
    description: str = Form(None),
    price: float = Form(...),
    category: str = Form(...),
    stock: int = Form(0),
    rating: float = Form(0.0),
    discount: int = Form(0),
    mainImage: UploadFile = File(...),
    images: List[UploadFile] = File([]),
    sizes_stock: str = Form(None, description="JSON string mapping size -> quantity"),
    video: str = Form(None, description="Embedded video URL e.g. https://www.youtube.com/embed/..."),
    free_shipping: bool = Form(False),
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    # Save images locally and store URLs in DB
    main_image_url = save_upload_file(mainImage, subdir="products")
    image_urls = save_multiple_upload_files(images, subdir="products")
    # Parse sizes_stock if provided
    sizes_map = None
    if sizes_stock:
        try:
            import json
            sizes_map = json.loads(sizes_stock)
        except Exception:
            sizes_map = None

    # Derive total stock from sizes_stock if provided; otherwise use provided stock
    derived_stock = None
    try:
        if sizes_map:
            derived_stock = int(sum(int(v or 0) for v in sizes_map.values()))
    except Exception:
        derived_stock = None

    product = Product(
        title=title,
        description=description,
        price=price,
        category=category,
        stock=derived_stock if derived_stock is not None else stock,
        rating=rating,
        discount=discount,
        main_image=main_image_url,
        video_url=_normalize_video_embed(video),
        images=image_urls,
        sizes_stock=sizes_map,
        free_shipping=free_shipping,
    )
    db.add(product)
    db.commit()
    db.refresh(product)
    return to_product_out(product)

# 11. Update Product (Admin)
@router.put("/admin/{id}", response_model=ProductOut)
def update_product(
    id: int,
    title: str = Form(...),
    description: str = Form(None),
    price: float = Form(...),
    category: str = Form(...),
    stock: int = Form(0),
    rating: float = Form(0.0),
    discount: int = Form(0),
    # Either upload or provide URLs
    main_image: UploadFile = File(None),
    images: List[UploadFile] = File([]),
    main_image_url: Optional[str] = Form(None),
    image_urls: List[str] = Form([]),
    sizes_stock: str = Form(None, description="JSON string mapping size -> quantity"),
    video: str = Form(None, description="Embedded video URL e.g. https://www.youtube.com/embed/..."),
    free_shipping: bool = Form(False),
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    product = db.query(Product).filter(Product.id == id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    product.title = title
    product.description = description
    product.price = price
    product.category = category
    # Set incoming stock (will be overridden if sizes_stock provided)
    product.stock = stock
    product.rating = rating
    product.discount = discount
    product.free_shipping = free_shipping
    # Video URL
    if video is not None:
        product.video_url = _normalize_video_embed(video) or None
    if sizes_stock is not None:
        try:
            import json
            parsed = json.loads(sizes_stock) if sizes_stock else None
            product.sizes_stock = parsed
            # When sizes are provided, derive total stock from sizes map (or 0 if empty dict)
            try:
                if isinstance(parsed, dict):
                    product.stock = int(sum(int(v or 0) for v in parsed.values()))
                else:
                    product.stock = 0
            except Exception:
                # Fallback: leave stock as-is if parsing numbers fails
                pass
        except Exception:
            pass

    # Update main image if provided
    if main_image and main_image.filename:
        product.main_image = save_upload_file(main_image, subdir="products")
    elif main_image_url:
        product.main_image = save_from_path_or_url(main_image_url, subdir="products")

    # Update gallery images if provided
    if images and any(f.filename for f in images):
        product.images = save_multiple_upload_files(images, subdir="products")
    elif image_urls:
        product.images = save_multiple_from_paths_or_urls(image_urls, subdir="products")

    db.commit()
    db.refresh(product)
    return to_product_out(product)

# 12. Delete Product (Admin)
@router.delete("/{id}")
def delete_product(id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    product = db.query(Product).filter(Product.id == id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    # Attempt file cleanup before deleting DB row
    try:
        if product.main_image:
            delete_media_file(product.main_image)
        if product.images and isinstance(product.images, list):
            delete_media_files(product.images)
    except Exception:
        # Silently ignore file deletion issues to avoid blocking core delete
        pass
    db.delete(product)
    db.commit()
    return {"message": "Product deleted"}

# 13. Get Low Stock Products (Admin)
@router.get("/low-stock", response_model=List[ProductOut])
def get_low_stock_products(
    threshold: int = Query(10, ge=0),
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    products = db.query(Product).filter(Product.stock < threshold).all()
    return [to_product_out(p) for p in products]

# Aliases for endpoints 8 and 9
@router.get("/by-category", response_model=List[ProductOut])
def get_products_by_category(
    category: str = Query(...),
    # page: int = Query(0, ge=0),
    # size: int = Query(20, ge=1),
    db: Session = Depends(get_db)
):
    # query = db.query(Product).filter(Product.category == category)
    # products = query.offset(page * size).limit(size).all()
    products = db.query(Product).filter(Product.category == category).all()
    return [to_product_out(p) for p in products]

@router.get("/search", response_model=List[ProductOut])
def search_products(
    search: str = Query(..., description="Search term"),
    # page: int = Query(0, ge=0),
    # size: int = Query(20, ge=1),
    db: Session = Depends(get_db)
):
    # query = db.query(Product).filter(Product.title.ilike(f"%{search}%"))
    # products = query.offset(page * size).limit(size).all()
    products = db.query(Product).filter(Product.title.ilike(f"%{search}%")).all()
    return [to_product_out(p) for p in products]


# 37. Upload File (Admin)
@router.post("/upload")
def upload_file(
    file: UploadFile = File(...),
    current_user: str = Depends(get_current_user),
):
    if not is_admin_email(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    url = save_upload_file(file, subdir="products")
    return {"url": url}
