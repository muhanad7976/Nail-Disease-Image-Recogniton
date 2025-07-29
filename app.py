import os
import numpy as np
from flask import Flask, request, render_template, jsonify, redirect, url_for, send_from_directory, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.optimizers import Adamax
from PIL import Image
from werkzeug.utils import secure_filename

# Flask app setup
app = Flask(__name__)
app.secret_key = 'nailvision_secure_key_123'  # Required for session
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# MySQL database connection
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        database='nail_diseases_db'
    )

# Fetch nail condition details from DB
def fetch_nail_details(nailDiseaseName):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM nail_diseases WHERE nailDiseaseName = %s", (nailDiseaseName,))
    nail_details = cursor.fetchone()
    cursor.close()
    conn.close()
    return nail_details

# Home page
@app.route('/')
def home():
    return render_template('index.html')

# Login/Signup pages
@app.route('/login-page')
def loginPage():
    return render_template('login.html')

@app.route('/signup-page')
def signup_page():
    return render_template('signup.html')

# Signup API
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data['name']
    email = data['email']
    password = generate_password_hash(data['password'])

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, password))
        conn.commit()
        return jsonify(success=True, message="User registered successfully!")
    except mysql.connector.Error as err:
        return jsonify(success=False, message=f"An error occurred: {err}")
    finally:
        cursor.close()
        conn.close()

# Login API with session
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and check_password_hash(user['password'], password):
        session['email'] = email
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "message": "Check your email or password"})

# Predict Page UI
@app.route('/dashboard', methods=['GET'])
def display_recog():
    return render_template('dashboard.html')

# Prediction Endpoint (Save to History)
@app.route('/predict', methods=['POST'])
def predict():
    img_file = request.files['file']
    if img_file:
        filename = secure_filename(img_file.filename)
        img_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        img_file.save(img_path)

        # Load model
        model = load_model('models/Nail2.h5', compile=False)
        model.compile(optimizer=Adamax(learning_rate=0.001), loss='categorical_crossentropy', metrics=['accuracy'])

        # Predict
        predicted_nail, confidence = predict_nail(model, img_path)
        image_url = f'/uploads/{filename}'

        # Get condition info
        nail_details = fetch_nail_details(predicted_nail)
        if nail_details:
            definition = nail_details.get('definition', '')
            causes = nail_details.get('causes', '')
            prevention = nail_details.get('prevention', '')
            curation = nail_details.get('curation', '')
        else:
            definition = causes = prevention = curation = "Not available"

        # Save to history
        email = session.get('email')
        if not email:
            return redirect(url_for('loginPage'))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO history (email, label, definition, causes, prevention, curation, image_url)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (email, predicted_nail, definition, causes, prevention, curation, image_url))
        conn.commit()
        cursor.close()
        conn.close()

        return render_template('dashboard.html', label=predicted_nail,
                               definition=definition, causes=causes,
                               prevention=prevention, curation=curation,
                               image_url=image_url)
    return 'No image provided', 400

# History Page
@app.route('/history', methods=['GET'])
def history():
    email = session.get('email')
    if not email:
        return jsonify({"error": "Not logged in"}), 401

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM history WHERE email = %s ORDER BY created_at DESC", (email,))
    records = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(records)


# Predict nail condition
def predict_nail(model, image_path):
    class_labels = [
        "Acral_Lentiginous_Melanoma", "Bulging", "Healthy_Nail",
        "Onychogryphosis", "blue_finger", "pitting", "unknown"
    ]

    img = Image.open(image_path).convert('RGB').resize((224, 224))
    img_array = tf.keras.preprocessing.image.img_to_array(img)
    img_array = tf.expand_dims(img_array, 0)

    predictions = model.predict(img_array)
    score = tf.nn.softmax(predictions[0])
    predicted_class_index = np.argmax(score)

    predicted_class = class_labels[predicted_class_index]

    if predicted_class == "unknown":
        # Return Somali message instead of confidence
        return predicted_class, (
            "Marka aan baarnay sawirkan aad soo gelisay ma'ahan mid aan naqaan "
            "ama ma ahanba sawir cidi ah, sida darteed fadlan soo gali sawir cidi oo saxan."
        )

    return predicted_class, score[predicted_class_index].numpy() * 100


@app.route('/delete-history/<int:history_id>', methods=['DELETE'])
def delete_history(history_id):
    email = session.get('email')
    if not email:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM history WHERE id = %s AND email = %s", (history_id, email))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'success': True})


# Serve uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Run server
if __name__ == '__main__':
    app.run(debug=True, port=5050)
