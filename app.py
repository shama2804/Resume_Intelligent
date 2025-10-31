from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson import ObjectId
import os

app = Flask(__name__)

# === CONFIG ===
UPLOAD_FOLDER = 'uploads/hr_verifications'
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# === DATABASE ===
client = MongoClient("mongodb://localhost:27017/")
db = client["resume_db"]
hr_accounts = db["hr_accounts"]

# === HELPERS ===
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_company_email(email):
    personal_domains = {'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'}
    domain = email.split('@')[-1]
    return domain not in personal_domains

# === ROUTES ===
@app.route('/')
def main_page():
    return render_template('main.html')

@app.route('/signin')
def signin_page():
    return render_template('signin.html')

# HR Signup
@app.route('/hr_signup', methods=['POST'])
def hr_signup():
    try:
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirmPassword', '')
        company_name = request.form.get('companyName', '').strip()
        job_title = request.form.get('jobTitle', '').strip()
        company_website = request.form.get('companyWebsite', '').strip()
        file = request.files.get('verification')

        # === Validation ===
        if not all([name, email, password, confirm, company_name, job_title, file]):
            return render_template('signin.html', error='All required fields must be filled')

        if password != confirm:
            return render_template('signin.html', error='Passwords do not match')

        if not is_company_email(email):
            return render_template('signin.html', error='Please use your company email address')

        if hr_accounts.find_one({'email': email}):
            return render_template('signin.html', error='Email already registered')

        if not allowed_file(file.filename):
            return render_template('signin.html', error='Invalid file type (Allowed: PDF, JPG, PNG)')

        # === Save verification document ===
        filename = secure_filename(f"{email}_{file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # === Hash password and save ===
        hashed_pw = generate_password_hash(password)

        hr_data = {
            'name': name,
            'email': email,
            'password': hashed_pw,
            'company_name': company_name,
            'job_title': job_title,
            'company_website': company_website,
            'verification_doc': filename,  # only filename
            'verified': False
        }
        hr_accounts.insert_one(hr_data)

        return redirect(url_for('login_page'))

    except Exception as e:
        print("Error in /hr_signup:", e)
        return render_template('signin.html', error='Internal server error')

# HR Login (verified only)
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not email or not password:
            return render_template('login.html', error='Please enter both email and password.')

        hr = hr_accounts.find_one({'email': email})
        if not hr:
            return render_template('login.html', error='No account found with this email.')

        if not hr.get('verified', False):
            return render_template('login.html', error='Your account is pending verification by admin.')
        if not hr['verified']:
            return render_template('login.html', error='Your account is pending verification by admin.')

        if not check_password_hash(hr['password'], password):
            return render_template('login.html', error='Incorrect password.')

        # Login successful
        return render_template('dashboard.html', hr=hr)

    return render_template('login.html')

# === ADMIN ROUTES ===
@app.route('/admin/pending_hr')
def pending_hr():
    pending = list(hr_accounts.find({'verified': False}))
    return render_template('admin_pending.html', pending=pending)

@app.route('/admin/approve_hr/<hr_id>', methods=['POST'])
def approve_hr(hr_id):
    hr_accounts.update_one({'_id': ObjectId(hr_id)}, {'$set': {'verified': True}})
    return redirect(url_for('pending_hr'))

# Serve uploaded verification files
@app.route('/uploads/hr_verifications/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)
