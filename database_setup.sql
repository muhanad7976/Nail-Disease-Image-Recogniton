-- Database setup for Nail Disease Image Recognition

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS nail_diseases_db;
USE nail_diseases_db;

-- Create users table with role column
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create history table
CREATE TABLE IF NOT EXISTS history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    label VARCHAR(255) NOT NULL,
    definition TEXT,
    causes TEXT,
    prevention TEXT,
    curation TEXT,
    image_url VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
);

-- Create nail_diseases table
CREATE TABLE IF NOT EXISTS nail_diseases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nailDiseaseName VARCHAR(255) NOT NULL,
    definition TEXT,
    causes TEXT,
    prevention TEXT,
    curation TEXT
);

-- Insert sample nail diseases data
INSERT INTO nail_diseases (nailDiseaseName, definition, causes, prevention, curation) VALUES
('Acral_Lentiginous_Melanoma', 'A rare form of melanoma that occurs on the palms, soles, or under the nails.', 'UV exposure, genetic factors, trauma to the area', 'Regular skin checks, sun protection, avoiding trauma to nails', 'Surgical removal, chemotherapy, radiation therapy'),
('Bulging', 'Nails that appear raised or bulging from the nail bed.', 'Trauma, infection, underlying medical conditions', 'Proper nail care, avoiding trauma, regular checkups', 'Treatment of underlying cause, nail care'),
('Healthy_Nail', 'Normal, healthy nail appearance with proper growth and color.', 'Good nutrition, proper care, no underlying conditions', 'Balanced diet, proper nail care, regular hygiene', 'Maintain current care routine'),
('Onychogryphosis', 'Thickened, curved nails that resemble a ram\'s horn.', 'Trauma, poor circulation, fungal infection', 'Proper nail care, good circulation, regular trimming', 'Professional nail care, treatment of underlying conditions'),
('blue_finger', 'Nails or fingers with a bluish discoloration.', 'Poor circulation, cold exposure, underlying heart/lung conditions', 'Keep warm, good circulation, regular exercise', 'Treatment of underlying medical conditions'),
('pitting', 'Small depressions or pits in the nail surface.', 'Psoriasis, eczema, alopecia areata, trauma', 'Gentle nail care, moisturizing, avoiding trauma', 'Treatment of underlying skin conditions');

-- Create an admin user (password: admin123)
INSERT INTO users (name, email, password, role) VALUES 
('Admin User', 'admin@nailvision.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/9Q5sK6O', 'admin');

-- Note: The password hash above is for 'admin123'
-- You can change this by running: python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your_password'))" 