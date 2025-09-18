-- Active: 1757559148719@@127.0.0.1@5432@kidora
-- ===========================
-- USERS & AUTHENTICATION
-- ===========================
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone VARCHAR(50),
    password_hash VARCHAR(255),
    role VARCHAR(20) DEFAULT 'USER' CHECK (role IN ('USER','SUB_ADMIN','ADMIN')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE otps (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    code VARCHAR(10) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_otps_email ON otps(email);

CREATE TABLE token_blacklist (
    id SERIAL PRIMARY KEY,
    jti VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===========================
-- PRODUCTS
-- ===========================
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    price NUMERIC(10,2) NOT NULL,
    discount INT DEFAULT 0,
    stock INT DEFAULT 0,
    category VARCHAR(100),
    available_sizes JSONB,   -- ["S","M","L","XL"]
    main_image VARCHAR(255),
    images JSONB,            -- list of URLs
    video_url VARCHAR(255),
    rating NUMERIC(3,2) DEFAULT 0.0,
    reviews INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===========================
-- CART & WISHLIST
-- ===========================
CREATE TABLE cart_items (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    selected_size VARCHAR(32),
    quantity INT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, product_id, selected_size),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
);

CREATE TABLE wishlist_items (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    UNIQUE(user_id, product_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
);

-- ===========================
-- ADDRESSES
-- ===========================
CREATE TABLE addresses (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    street VARCHAR(255),
    city VARCHAR(100),
    state VARCHAR(100),
    zip_code VARCHAR(50),
    country VARCHAR(100),
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ===========================
-- ORDERS
-- ===========================
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    order_number VARCHAR(100) NOT NULL UNIQUE,
    status VARCHAR(30) DEFAULT 'PENDING'
        CHECK (status IN ('PENDING','PROCESSING','PACKED','SHIPPED','OUT_FOR_DELIVERY','DELIVERED','CANCELLED')),
    payment_method VARCHAR(50),
    total_amount NUMERIC(10,2) DEFAULT 0.0,
    subtotal NUMERIC(10,2) DEFAULT 0.0,
    shipping_cost NUMERIC(10,2) DEFAULT 0.0,
    shipping_address JSONB,  -- store address object
    sender_number VARCHAR(50),
    transaction_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    delivered_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE order_items (
    id SERIAL PRIMARY KEY,
    order_id INT NOT NULL,
    product_id INT NOT NULL,
    product_title VARCHAR(255),
    unit_price NUMERIC(10,2),
    quantity INT DEFAULT 1,
    selected_size VARCHAR(32),
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
);

-- ===========================
-- HERO BANNERS
-- ===========================
CREATE TABLE hero_banners (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255),
    subtitle VARCHAR(255),
    image_url VARCHAR(255),
    button_text VARCHAR(100),
    button_link VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    display_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===========================
-- RETURNS
-- ===========================
CREATE TABLE returns (
    id SERIAL PRIMARY KEY,
    order_id INT NOT NULL,
    product_id INT NOT NULL,
    user_id INT NOT NULL,
    reason VARCHAR(500),
    reason_category VARCHAR(30) DEFAULT 'OTHER'
        CHECK (reason_category IN ('SIZE_ISSUE','QUALITY_ISSUE','WRONG_ITEM','DAMAGED','OTHER')),
    status VARCHAR(30) DEFAULT 'PENDING'
        CHECK (status IN ('PENDING','APPROVED','REJECTED','COMPLETED')),
    images JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

ALTER TABLE users ADD COLUMN password VARCHAR(255) NOT NULL;



SELECT * FROM public.products LIMIT 20;