from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import logging
from app.routers import auth, products
from app.routers import orders
from app.routers import cart
from app.routers import wishlist
from app.routers import addresses
from app.routers import admin_users
from app.routers import hero_banners
from app.routers import user as user_router
from app.routers import admin_dashboard
from app.routers import admin_returns
from app.utils.storage import MEDIA_ROOT
from sqlalchemy import text

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

app = FastAPI()

@app.on_event("startup")
def on_startup():
    # Ensure all DB tables exist after all models are imported
    from app.models.user import Base, engine  # Base/engine single source
    import app.models.product  # register Product model
    import app.models.cart  # register Cart/CartItem models
    import app.models.order  # register Order/OrderItem models
    import app.models.wishlist  # register Wishlist models
    import app.models.address  # register Address model
    import app.models.hero_banner  # register HeroBanner model
    import app.models.return_request  # register ReturnRequest model
    import app.models.payment_config  # register PaymentConfig model
    Base.metadata.create_all(bind=engine)

    # Lightweight, idempotent migrations for schema drift across environments
    # - Ensure hero_banners.updated_at exists (matches SQLAlchemy model)
    # - Ensure hero_banners.link_url exists and backfill from legacy button_link if present
    try:
        with engine.begin() as conn:
            conn.execute(text(
                "ALTER TABLE IF EXISTS hero_banners "
                "ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            ))
            conn.execute(text(
                "ALTER TABLE IF EXISTS hero_banners "
                "ADD COLUMN IF NOT EXISTS link_url VARCHAR(255)"
            ))
            # Best-effort backfill from previous column name if it exists
            # This UPDATE will be a no-op if button_link doesn't exist
            try:
                conn.execute(text(
                    "UPDATE hero_banners SET link_url = button_link "
                    "WHERE link_url IS NULL AND button_link IS NOT NULL"
                ))
            except Exception:
                # Ignore if button_link column isn't present
                pass

            # Ensure wishlist tables are aligned with models
            # Add missing wishlist_id column on wishlist_items if schema drifted
            conn.execute(text(
                "ALTER TABLE IF EXISTS wishlist_items "
                "ADD COLUMN IF NOT EXISTS wishlist_id INTEGER"
            ))
            # Add missing user_id column on wishlist_items for legacy compatibility
            conn.execute(text(
                "ALTER TABLE IF EXISTS wishlist_items "
                "ADD COLUMN IF NOT EXISTS user_id INTEGER"
            ))
            # Add missing created_at column on wishlist_items if schema drifted
            conn.execute(text(
                "ALTER TABLE IF EXISTS wishlist_items "
                "ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            ))
            # Helpful index for join/filter
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_wishlist_items_wishlist_id ON wishlist_items (wishlist_id)"
            ))
            # Attempt to add FK; ignore if it already exists
            try:
                conn.execute(text(
                    "ALTER TABLE IF EXISTS wishlist_items "
                    "ADD CONSTRAINT fk_wishlist_items_wishlist_id "
                    "FOREIGN KEY (wishlist_id) REFERENCES wishlists(id) ON DELETE CASCADE"
                ))
            except Exception:
                pass

            # --- Backfill and relax legacy wishlist_items.user_id column if present ---
            # Some environments previously used a user_id column on wishlist_items (NOT NULL).
            # Our current model uses wishlist_id instead. To avoid INSERT failures, we:
            # 1) Ensure each user referenced by wishlist_items has a wishlist row.
            # 2) Backfill missing wishlist_id from user_id.
            # 3) Backfill missing user_id from wishlist.user_id (best-effort).
            # 4) Drop NOT NULL from wishlist_items.user_id so inserts without user_id succeed.
            try:
                # 1) Create missing wishlists for legacy rows (only if user_id column exists)
                conn.execute(text(
                    "INSERT INTO wishlists (user_id) "
                    "SELECT DISTINCT wi.user_id FROM wishlist_items wi "
                    "LEFT JOIN wishlists w ON w.user_id = wi.user_id "
                    "WHERE wi.user_id IS NOT NULL AND w.id IS NULL"
                ))
            except Exception:
                pass
            try:
                # 2) Backfill wishlist_id where NULL using the user's wishlist
                conn.execute(text(
                    "UPDATE wishlist_items wi SET wishlist_id = w.id "
                    "FROM wishlists w "
                    "WHERE wi.wishlist_id IS NULL AND wi.user_id IS NOT NULL AND w.user_id = wi.user_id"
                ))
            except Exception:
                pass
            try:
                # 3) Backfill user_id where NULL using parent wishlist
                conn.execute(text(
                    "UPDATE wishlist_items wi SET user_id = w.user_id "
                    "FROM wishlists w "
                    "WHERE wi.user_id IS NULL AND wi.wishlist_id IS NOT NULL AND w.id = wi.wishlist_id"
                ))
            except Exception:
                pass
            try:
                # Drop legacy unique constraints on (user_id, product_id) if present
                conn.execute(text(
                    "ALTER TABLE IF EXISTS wishlist_items DROP CONSTRAINT IF EXISTS wishlist_items_user_id_product_id_key"
                ))
            except Exception:
                pass
            try:
                # Ensure unified unique constraint on (wishlist_id, product_id)
                conn.execute(text(
                    "ALTER TABLE IF EXISTS wishlist_items ADD CONSTRAINT uq_wishlist_product UNIQUE (wishlist_id, product_id)"
                ))
            except Exception:
                pass
            try:
                # 4) Drop NOT NULL on user_id so future inserts without user_id don't fail
                conn.execute(text(
                    "ALTER TABLE IF EXISTS wishlist_items ALTER COLUMN user_id DROP NOT NULL"
                ))
            except Exception:
                # Column may not exist; ignore
                pass

            # Ensure new payment columns exist on orders table for online payments
            try:
                conn.execute(text(
                    "ALTER TABLE IF EXISTS orders ADD COLUMN IF NOT EXISTS payment_provider VARCHAR(50)"
                ))
                conn.execute(text(
                    "ALTER TABLE IF EXISTS orders ADD COLUMN IF NOT EXISTS payment_sender_number VARCHAR(50)"
                ))
                conn.execute(text(
                    "ALTER TABLE IF EXISTS orders ADD COLUMN IF NOT EXISTS payment_transaction_id VARCHAR(100)"
                ))
                conn.execute(text(
                    "ALTER TABLE IF EXISTS orders ADD COLUMN IF NOT EXISTS shipping_name VARCHAR(255)"
                ))
                conn.execute(text(
                    "ALTER TABLE IF EXISTS orders ADD COLUMN IF NOT EXISTS shipping_phone VARCHAR(50)"
                ))
            except Exception:
                pass

            # Ensure per-size inventory column exists on products
            try:
                conn.execute(text(
                    "ALTER TABLE IF EXISTS products ADD COLUMN IF NOT EXISTS sizes_stock JSONB"
                ))
            except Exception:
                pass

            # Ensure video_url column exists on products
            try:
                conn.execute(text(
                    "ALTER TABLE IF EXISTS products ADD COLUMN IF NOT EXISTS video_url VARCHAR(500)"
                ))
            except Exception:
                pass

            # Ensure free_shipping column exists on products (boolean default false)
            try:
                conn.execute(text(
                    "ALTER TABLE IF EXISTS products ADD COLUMN IF NOT EXISTS free_shipping BOOLEAN DEFAULT FALSE"
                ))
            except Exception:
                pass

            # Ensure orders.status and orders.payment_status check constraints allow our canonical set
            # Normalize any existing lowercase/mismatched values before re-adding constraints
            try:
                conn.execute(text("UPDATE orders SET status = UPPER(status) WHERE status IS NOT NULL"))
                conn.execute(text("UPDATE orders SET payment_status = UPPER(payment_status) WHERE payment_status IS NOT NULL"))
            except Exception:
                pass
            try:
                # Drop existing constraints if present (names may vary; handle common names)
                conn.execute(text("ALTER TABLE IF EXISTS orders DROP CONSTRAINT IF EXISTS orders_status_check"))
            except Exception:
                pass
            try:
                conn.execute(text("ALTER TABLE IF EXISTS orders DROP CONSTRAINT IF EXISTS order_status_check"))
            except Exception:
                pass
            try:
                conn.execute(text("ALTER TABLE IF EXISTS orders DROP CONSTRAINT IF EXISTS orders_payment_status_check"))
            except Exception:
                pass
            try:
                conn.execute(text("ALTER TABLE IF EXISTS orders DROP CONSTRAINT IF EXISTS order_payment_status_check"))
            except Exception:
                pass

            # Recreate constraints with UPPER() to accept any case and enforce canonical values
            try:
                conn.execute(text(
                    "ALTER TABLE IF EXISTS orders "
                    "ADD CONSTRAINT orders_status_check CHECK (UPPER(status) IN ('PENDING','CONFIRMED','PACKED','OUT_FOR_DELIVERY','SHIPPED','DELIVERED','CANCELLED'))"
                ))
            except Exception:
                pass
            try:
                conn.execute(text(
                    "ALTER TABLE IF EXISTS orders "
                    "ADD CONSTRAINT orders_payment_status_check CHECK (UPPER(payment_status) IN ('PENDING','PAID','REFUNDED'))"
                ))
            except Exception:
                pass
    except Exception as e:
        logging.error(f"Startup migration failed: {e}")

# Ensure media directory exists before mounting
MEDIA_ROOT.mkdir(parents=True, exist_ok=True)

# Serve uploaded media files
app.mount("/media", StaticFiles(directory=str(MEDIA_ROOT)), name="media")

# CORS configuration for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(products.router, prefix="/api/products", tags=["products"])
app.include_router(orders.router, prefix="/api/orders", tags=["orders"])
app.include_router(orders.admin_router, prefix="/api/admin/orders", tags=["admin-orders"])
app.include_router(cart.router, prefix="/api/cart", tags=["cart"])
app.include_router(wishlist.router, prefix="/api/wishlist", tags=["wishlist"])
app.include_router(addresses.router, prefix="/api/addresses", tags=["addresses"])
app.include_router(admin_users.router, prefix="/api/admin/users", tags=["admin-users"])
app.include_router(hero_banners.router, prefix="/api/hero-banners", tags=["hero-banners"])
app.include_router(user_router.router, prefix="/api/user", tags=["user"])
app.include_router(admin_dashboard.router, prefix="/api/admin", tags=["admin-dashboard"])
app.include_router(admin_returns.router, prefix="/api/admin/returns", tags=["admin-returns"])
from app.routers import admin_payment_config
app.include_router(admin_payment_config.router, prefix="/api", tags=["payment-config"])


# --- Entry point for Railway / local ---
if __name__ == "__main__":
    import uvicorn, os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)