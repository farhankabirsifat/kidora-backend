-- Active: 1757559148719@@127.0.0.1@5432@kidora
-- Add created_at column to wishlist_items table
ALTER TABLE wishlist_items
ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'wishlist_items'
ORDER BY ordinal_position;

SELECT 1 FROM information_schema.tables WHERE table_name = 'wishlists';