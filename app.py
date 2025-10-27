import bleach, os, re, sqlite3, pyotp, qrcode, io
from cryptography.fernet import Fernet
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from flask import Flask, render_template, flash, request, redirect, url_for, session, jsonify, send_file, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Load environment variables from .env
load_dotenv()

# Initialize Flask
app = Flask(__name__)

# Load from .env
app.secret_key = os.getenv("SECRET_KEY")
DB_PATH = os.getenv("DATABASE_PATH")
FERNET_KEY = os.getenv("FERNET_KEY")
TOTP_ISSUER = os.getenv("TOTP_ISSUER", "Medcare App")
cipher = Fernet(FERNET_KEY)
limiter = Limiter(get_remote_address, app=app)

# Session configuration
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# =============================
# Session Timeout Management
# =============================
@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)

    # Use timezone-aware UTC timestamp
    now_ts = datetime.now(timezone.utc).timestamp()

    if 'last_activity' in session:
        last_activity_ts = session.get('last_activity')
        # If idle for more than 30 minutes → auto logout
        if (now_ts - last_activity_ts) > 1800:  # 1800 seconds = 30 mins
            session.clear()
            flash("Session expired due to inactivity. Please log in again.", "error")
            return redirect(url_for('login'))

    # Save current timestamp
    session['last_activity'] = now_ts

# =============================
# Database Connection Helper
# =============================
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# =============================
# 2FA
# =============================
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap

@app.route('/twofa_setup', methods=['GET', 'POST'])
@login_required
def twofa_setup():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE user_id = ?", (session['user_id'],))
    user = cur.fetchone()

    # If not yet generated, create a new base32 secret
    if not user['two_factor_secret']:
        secret = pyotp.random_base32()
        cur.execute(
            "UPDATE users SET two_factor_secret = ? WHERE user_id = ?",
            (secret, session['user_id'])
        )
        conn.commit()
        user = dict(user)
        user['two_factor_secret'] = secret

    secret = user['two_factor_secret']

    # Use decrypted email (unique) or fallback to unique user_id
    try:
        decrypted_email = cipher.decrypt(user['email'].encode()).decode()
        account_label = decrypted_email
    except Exception:
        account_label = f"user_{user['user_id']}"

    # Generate TOTP provisioning URI (shown in Authenticator app)
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=account_label,
        issuer_name=TOTP_ISSUER
    )

    # Handle form submission (verification)
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):  # allow 30s drift
            cur.execute("""
                UPDATE users
                SET two_factor_enabled = 1
                WHERE user_id = ?
            """, (session['user_id'],))
            conn.commit()
            flash("Two-Factor Authentication enabled.", "success")
            conn.close()
            return route_for_role()
        else:
            flash("Invalid code. Please try again.", "error")

    conn.close()
    return render_template('2fa_setup.html', otpauth_uri=uri)

@app.route('/twofa_qr')
@login_required
def twofa_qr():
    uri = request.args.get('uri', '')
    if not uri:
        abort(400)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/twofa_verify', methods=['GET','POST'])
def twofa_verify():
    pending_id = session.get('pending_user_id')
    if not pending_id:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id, name, role_id, two_factor_secret FROM users WHERE user_id= ? ", (pending_id,))
    user = cur.fetchone()
    if not user:
        conn.close()
        flash("User not found.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        totp = pyotp.TOTP(user['two_factor_secret'])
        if totp.verify(code, valid_window=1):
            # finalize login
            session.clear()
            session.permanent = True
            session['user_id'] = user['user_id']
            session['name'] = user['name']
            session['role_id'] = user['role_id']
            conn.close()
            flash("2FA verification successful!", "success")
            return route_for_role()
        else:
            flash("Invalid 2FA code.", "error")

    conn.close()
    return render_template('2fa_verify.html')

def route_for_role():
    """Redirect user to their respective dashboard based on role_id."""
    role_id = session.get('role_id')

    if role_id == 1:
        return redirect(url_for('admin_dashboard'))
    elif role_id == 2:
        return redirect(url_for('doctor_dashboard'))
    elif role_id == 3:
        return redirect(url_for('patient_dashboard'))
    else:
        # Unknown or missing role — fallback to login
        return redirect(url_for('login'))
    
@app.errorhandler(429)
def ratelimit_handler(e):
    flash("Too many login attempts. Please try again later.", "error")
    return render_template("login.html"), 429

# =============================
# Routes
# =============================
@app.route("/")
def home():
    return render_template("home.html")

@app.route('/login', methods=['GET','POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE LOWER(email) = ?", (email,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            if user['two_factor_enabled']:
                session.clear()
                session['pending_user_id'] = user['user_id']
                return redirect(url_for('twofa_verify'))
            else:
                session.clear()
                session.permanent = True
                session['user_id'] = user['user_id']
                session['name'] = user['name']
                session['role_id'] = user['role_id']
                flash("Login successful!", "success")
                return route_for_role()
        else:
            flash("Invalid email or password!", "error")

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def signup():
    if request.method == 'POST':
        name = bleach.clean(request.form.get('name', '').strip())
        email = request.form.get('email', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
         
        # Validation
        if not is_valid_email(email):
            flash("Invalid email format!", "error")
            return redirect(url_for('signup'))
        
        if not is_valid_phone(phone_number):
            flash("Invalid phone number format!", "error")
            return redirect(url_for('signup'))
        
        if len(email) > 255 or len(phone_number) > 30 or len(name) > 100:
            flash("Input too long!", "error")
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('signup'))
        
        if not is_strong_password(password):
            flash("Password must include upper, lower, and a number (min 8 chars).", "error")
            return redirect(url_for('signup'))

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Check duplicate email
            cur.execute("SELECT 1 FROM users WHERE LOWER(email) = LOWER(?)", (email,))
            if cur.fetchone():
                flash("Email already registered!", "error")
                return redirect(url_for('signup'))

            # Encrypt phone number
            encrypted_phone = cipher.encrypt(phone_number.encode()).decode()

            # Check for duplicate phone (decrypt compare)
            cur.execute("SELECT user_id, phone_number FROM users")
            existing_users = cur.fetchall()
            for user in existing_users:
                try:
                    if phone_number == cipher.decrypt(user['phone_number'].encode()).decode():
                        flash("Phone number already registered!", "error")
                        return redirect(url_for('signup'))
                except Exception:
                    continue  # skip invalid decrypts

            # Hash password securely
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

            cur.execute("""
                INSERT INTO users (name, email, password, phone_number, role_id)
                VALUES (?, ?, ?, ?, (SELECT id FROM roles WHERE role_name = 'patient'))
            """, (name, email, hashed_password, encrypted_phone))
            conn.commit()

            flash("Signup successful! Please log in.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            conn.rollback()
            flash(f"Error: {str(e)}", "error")

        finally:
            cur.close()
            conn.close()

    return render_template('signup.html')

@app.route('/patient_dashboard', methods=['GET'])
def patient_dashboard():
    if 'user_id' not in session:
        flash("Please log in to book an appointment", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Fetch logged-in user for 2FA info
    cur.execute("SELECT * FROM users WHERE user_id = ?", (session['user_id'],))
    user = cur.fetchone()

    # Fetch user's appointments
    cur.execute("""
        SELECT 
            a.id AS appointment_id,
            a.date,
            a.time,
            a.status,
            u.name AS doctor_name,
            d.specialization AS doctor_specialization
        FROM appointments a
        JOIN doctors d ON a.doctor_id = d.doctor_id
        JOIN users u ON d.user_id = u.user_id
        WHERE a.user_id = ?
        ORDER BY a.date, a.time
    """, (session['user_id'],))
    appointments = cur.fetchall()

    # Fetch doctor specializations
    cur.execute("SELECT DISTINCT specialization FROM doctors ORDER BY specialization")
    specializations = [row['specialization'] for row in cur.fetchall()]

    conn.close()

    return render_template(
        'patient_dashboard.html',
        name=session.get('name', 'User'),
        appointments=appointments,
        specializations=specializations,
        two_factor_enabled=user['two_factor_enabled']
    )

@app.route('/get_doctors/<specialization>')
def get_doctors(specialization):
    conn = get_db_connection()
    cur = conn.cursor()

    # Join doctor table + user table to get doctor names
    cur.execute("""
        SELECT d.doctor_id, u.name
        FROM doctors d
        JOIN users u ON d.user_id = u.user_id
        WHERE d.specialization = ?
    """, (specialization,))
    doctors = [dict(row) for row in cur.fetchall()]
    conn.close()
    return jsonify(doctors)

@app.route('/get_available_slots/<int:doctor_id>/<date>')
def get_available_slots(doctor_id, date):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT time FROM appointments WHERE doctor_id = ? AND date = ?", (doctor_id, date))
    booked_slots = [row['time'] for row in cur.fetchall()]
    conn.close()

    return jsonify({"booked": booked_slots})

@app.route('/book_appointment', methods=['POST'])
def book_appointment():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Please log in first."}), 401

    data = request.get_json(force=True)
    specialization = data.get('specialization')
    doctor_id = data.get('doctor_id')
    date = data.get('date')
    time_slot = data.get('time')

    # Validate input
    if not all([specialization, doctor_id, date, time_slot]):
        return jsonify({"success": False, "error": "All fields are required."}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Check if slot already booked
        cur.execute("""
            SELECT 1 FROM appointments
            WHERE doctor_id = ? AND date = ? AND time = ?
        """, (doctor_id, date, time_slot))
        if cur.fetchone():
            conn.close()
            return jsonify({"success": False, "error": "Selected time slot is already booked."}), 409

        # Insert new appointment
        cur.execute("""
            INSERT INTO appointments (user_id, doctor_id, date, time)
            VALUES (?, ?, ?, ?)
        """, (session['user_id'], doctor_id, date, time_slot))
        conn.commit()

        return jsonify({"success": True, "message": "Appointment booked successfully!"})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        conn.close()

@app.route('/cancel_booking', methods=['POST'])
def cancel_booking():
    if 'user_id' not in session:
        flash("Please log in to access your dashboard", "error")
        return redirect(url_for('login'))

    data = request.get_json(force=True)
    appointment_id = data.get("appointment_id")

    if not appointment_id:
        return jsonify({"success": False, "error": "Missing appointment ID"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    # Update the status to 'cancelled' only if this appointment belongs to the logged-in user
    cur.execute("""
        UPDATE appointments
        SET status = 'cancelled'
        WHERE id = ? AND user_id = ? AND status != 'cancelled'
    """, (appointment_id, session['user_id']))
    
    conn.commit()
    updated = cur.rowcount
    conn.close()

    if updated:
        return jsonify({"success": True, "message": "Appointment cancelled successfully"})
    else:
        return jsonify({"success": False, "error": "Appointment not found or already cancelled"}), 404
    
@app.route('/profile', methods=['GET'])
def profile():
    if 'user_id' not in session:
        flash("Please log in to access your profile", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Get user info
    cur.execute("""
        SELECT u.*, r.role_name
        FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE u.user_id = ?
    """, (session['user_id'],))
    user = cur.fetchone()

    if not user:
        conn.close()
        flash("User not found", "error")
        return redirect(url_for('login'))

    # Decrypt phone number
    try:
        user_phone = cipher.decrypt(user['phone_number'].encode()).decode()
    except Exception:
        user_phone = "N/A"

    # If doctor, fetch specialization & experience
    doctor_info = None
    if user['role_name'] == 'doctor':
        cur.execute("SELECT specialization, experience_years FROM doctors WHERE user_id = ?", (user['user_id'],))
        doctor_info = cur.fetchone()

    conn.close()

    return render_template(
        'profile.html',
        user=user,
        email=user['email'],  # plaintext
        phone=user_phone,
        doctor_info=doctor_info
    )


@app.route('/logout')
def logout():
    # Clear entire session
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for('home'))

# =============================
# Admin Routes
# =============================
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash("Please log in to access your dashboard", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch current admin user details (for 2FA info)
    cur.execute("SELECT * FROM users WHERE user_id = ?", (session['user_id'],))
    user = cur.fetchone()

    # Fetch doctors
    cur.execute("""
        SELECT d.doctor_id, u.name, u.email, u.phone_number, d.specialization, d.experience_years
        FROM doctors d
        JOIN users u ON d.user_id = u.user_id
        ORDER BY d.specialization, u.name
    """)
    doctors = cur.fetchall()

    decrypted_doctors = []
    for doc in doctors:
        decrypted_doc = dict(doc)
        try:
            decrypted_doc['phone_number'] = cipher.decrypt(doc['phone_number'].encode()).decode()
        except Exception:
            decrypted_doc['phone_number'] = "N/A"
        decrypted_doctors.append(decrypted_doc)

    # Fetch all appointments with doctor + patient info
    cur.execute("""
        SELECT 
            a.id AS appointment_id,
            a.date,
            a.time,
            a.status,
            u.name AS patient_name,
            du.name AS doctor_name,
            d.specialization AS doctor_specialization
        FROM appointments a
        JOIN users u ON a.user_id = u.user_id
        JOIN doctors d ON a.doctor_id = d.doctor_id
        JOIN users du ON d.user_id = du.user_id
        ORDER BY a.date DESC, a.time ASC
    """)
    appointments = cur.fetchall()
    conn.close()

    return render_template(
        'admin_dashboard.html',
        two_factor_enabled=user['two_factor_enabled'],
        doctors=decrypted_doctors,
        appointments=appointments
    )

@app.route('/add_doctor', methods=['POST'])
def add_doctor():
    data = request.get_json()
    name = bleach.clean(data.get('name', '').strip())
    email = data.get('email', '').strip()
    phone_number = data.get('phone_number', '').strip()
    specialization = data.get('specialization', '').strip()
    experience_years = data.get('experience_years')

    if not is_valid_email(email):
        return jsonify({"success": False, "error": "Invalid email format."}), 400

    if not is_valid_phone(phone_number):
        return jsonify({"success": False, "error": "Invalid phone number format."}), 400
 
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Check duplicate email (plaintext)
        cur.execute("SELECT 1 FROM users WHERE LOWER(email) = LOWER(?)", (email,))
        if cur.fetchone():
            return jsonify({"success": False, "error": "Email already exists."})

        # Encrypt phone number
        encrypted_phone = cipher.encrypt(phone_number.encode()).decode()

        # Check duplicate phone number (decrypt to compare)
        cur.execute("SELECT phone_number FROM users")
        existing_users = cur.fetchall()
        for user in existing_users:
            try:
                if phone_number == cipher.decrypt(user['phone_number'].encode()).decode():
                    return jsonify({"success": False, "error": "Phone number already exists."})
            except Exception:
                continue  # skip decryption errors

        # Hash a default password for new doctor
        hashed_password = generate_password_hash("Doctor123$", method='pbkdf2:sha256', salt_length=16)

        # Insert new doctor user
        cur.execute("""
            INSERT INTO users (name, email, password, phone_number, role_id)
            VALUES (?, ?, ?, ?, (SELECT id FROM roles WHERE role_name = 'doctor'))
        """, (name, email, hashed_password, encrypted_phone))
        user_id = cur.lastrowid

        # Add corresponding doctor record
        cur.execute("""
            INSERT INTO doctors (user_id, specialization, experience_years)
            VALUES (?, ?, ?)
        """, (user_id, specialization, experience_years))

        conn.commit()
        return jsonify({"success": True})

    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)})

    finally:
        conn.close()

@app.route('/delete_doctor', methods=['POST'])
def delete_doctor():
    data = request.get_json()
    doctor_id = data.get('doctor_id')

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Find the related user_id
        cur.execute("SELECT user_id FROM doctors WHERE doctor_id = ?", (doctor_id,))
        row = cur.fetchone()

        if not row:
            return jsonify({"success": False, "error": "Doctor not found"})

        user_id = row["user_id"]

        # Delete the doctor record
        cur.execute("DELETE FROM doctors WHERE doctor_id = ?", (doctor_id,))

        # Delete the linked user record
        cur.execute("DELETE FROM users WHERE user_id = ?", (user_id,))

        conn.commit()
        return jsonify({"success": True})

    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)})
    finally:
        conn.close()

# =============================
# Doctor Routes
# =============================
@app.route('/doctor_dashboard')
def doctor_dashboard():
    if 'user_id' not in session:
        flash("Please log in to access your dashboard", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch current doctor user (for 2FA status)
    cur.execute("SELECT * FROM users WHERE user_id = ?", (session['user_id'],))
    user = cur.fetchone()

    # Get this doctor's ID
    cur.execute("SELECT doctor_id FROM doctors WHERE user_id = ?", (session['user_id'],))
    doctor = cur.fetchone()
    if not doctor:
        flash("Doctor profile not found", "error")
        conn.close()
        return redirect(url_for('login'))

    # Fetch all appointments for this doctor
    cur.execute("""
        SELECT 
            a.id AS appointment_id,
            a.date,
            a.time,
            a.status,
            u.name AS patient_name,
            u.phone_number
        FROM appointments a
        JOIN users u ON a.user_id = u.user_id
        WHERE a.doctor_id = ?
        ORDER BY a.date, a.time
    """, (doctor['doctor_id'],))
    appointments = cur.fetchall()

    # Decrypt patient phone numbers safely
    decrypted_appointments = []
    for a in appointments:
        decrypted_a = dict(a)
        try:
            decrypted_a['phone_number'] = cipher.decrypt(a['phone_number'].encode()).decode()
        except Exception:
            decrypted_a['phone_number'] = "N/A"
        decrypted_appointments.append(decrypted_a)

    conn.close()

    # Render dashboard with 2FA info
    return render_template(
        'doctor_dashboard.html',
        name=session.get('name', 'Doctor'),
        appointments=decrypted_appointments,
        two_factor_enabled=user['two_factor_enabled']
    )

@app.route('/update_appointment_status', methods=['POST'])
def update_appointment_status():
    if 'user_id' not in session or session.get('role') != 'doctor':
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    data = request.get_json()
    appointment_id = data.get("appointment_id")
    status = data.get("status")

    if not appointment_id or status not in ['approved', 'rejected']:
        return jsonify({"success": False, "error": "Invalid data"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    # Verify that the appointment belongs to this doctor
    cur.execute("""
        SELECT a.id FROM appointments a
        JOIN doctors d ON a.doctor_id = d.doctor_id
        WHERE a.id = ? AND d.user_id = ?
    """, (appointment_id, session['user_id']))
    valid = cur.fetchone()

    if not valid:
        conn.close()
        return jsonify({"success": False, "error": "Unauthorized or appointment not found"}), 403

    cur.execute("UPDATE appointments SET status = ? WHERE id = ?", (status, appointment_id))
    conn.commit()
    conn.close()

    return jsonify({"success": True})

# =============================
# Helper Functions
# =============================
def is_valid_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

def is_valid_phone(phone):
    pattern = r"^\d{7,15}$"  # only digits, length between 7 and 15
    return re.match(pattern, phone) is not None

def is_strong_password(pw):
    return (
        len(pw) >= 8
        and any(c.islower() for c in pw)
        and any(c.isupper() for c in pw)
        and any(c.isdigit() for c in pw)
    )

if __name__ == '__main__':
    app.run(debug=True)
