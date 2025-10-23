from flask import Flask, render_template, flash, request, redirect, url_for, session, jsonify
import sqlite3

DB_PATH = 'db_folder/app.db'

app = Flask(__name__)
app.secret_key = 'my_super_secret_key_12345'

# DB helpers
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Routes
@app.route("/")
def home():
    return render_template("home.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        conn = get_db_connection()
        conn.row_factory = sqlite3.Row  # allows access by column name
        cur = conn.cursor()

        cur.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))
        user = cur.fetchone()

        if user:
            session['user_id'] = user['user_id']
            session['name'] = user['name']
            session['role_id'] = user['role_id']  # if using role_id now

            cur.close()
            conn.close()

            # redirect by role
            if user['role_id'] == 1:
                flash("Admin login successful ✅", "success")
                return redirect(url_for('admin_dashboard'))
            else:
                flash("Login successful ✅", "success")
                return redirect(url_for('dashboard'))
        else:
            cur.close()
            conn.close()
            flash("Invalid email or password ❌", "error")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        password = request.form.get('password', '').strip()

        conn = get_db_connection()
        cur = conn.cursor()

        # Check if user exists by email OR phone number
        cur.execute("SELECT 1 FROM users WHERE email = ? OR phone_number = ?", (email, phone_number))
        if cur.fetchone():
            cur.close()
            conn.close()
            flash("⚠️ Email or Phone Number already exists!", "error")
            return render_template('signup.html')

        try:
            # Only patients can register via this form
            cur.execute("""
                INSERT INTO users (name, email, password, phone_number, role_id)
                VALUES (?, ?, ?, ?, (SELECT id FROM roles WHERE role_name = 'patient'))
            """, (name, email, password, phone_number))
            conn.commit()

            flash("✅ Signup successful! Please log in.", "success")
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash("❌ There was an error during signup. Try again.", "error")
        finally:
            cur.close()
            conn.close()

    return render_template('signup.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access your dashboard ❌", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Fetch appointments for current user
    cur.execute("""
        SELECT 
            a.id AS appointment_id,
            a.date,
            a.time,
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

    # Handle booking form submission
    if request.method == 'POST':
        specialization = request.form.get('specialization')
        doctor_id = request.form.get('doctor_id')
        date = request.form.get('date')
        time_slot = request.form.get('time')

        if not all([specialization, doctor_id, date, time_slot]):
            flash("❌ Please fill in all fields!", "error")
        else:
            cur.execute("""
                SELECT 1 FROM appointments
                WHERE doctor_id = ? AND date = ? AND time = ?
            """, (doctor_id, date, time_slot))
            if cur.fetchone():
                flash("❌ Selected time slot is already booked!", "error")
            else:
                cur.execute("""
                    INSERT INTO appointments (user_id, doctor_id, date, time)
                    VALUES (?, ?, ?, ?)
                """, (session['user_id'], doctor_id, date, time_slot))
                conn.commit()
                flash("✅ Appointment booked successfully!", "success")

        cur.close()
        conn.close()
        return redirect(url_for('dashboard') + '#book-section')

    cur.close()
    conn.close()
    return render_template(
        'dashboard.html',
        name=session.get('name', 'User'),
        appointments=appointments,
        specializations=specializations
    )

@app.route('/get_doctors/<specialization>')
def get_doctors(specialization):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Join doctor table + user table to get doctor names
    cur.execute("""
        SELECT d.doctor_id, u.name
        FROM doctors d
        JOIN users u ON d.user_id = u.id
        WHERE d.specialization = ?
    """, (specialization,))
    doctors = [dict(row) for row in cur.fetchall()]
    conn.close()
    return jsonify(doctors)

@app.route('/get_available_slots/<int:doctor_id>/<date>')
def get_available_slots(doctor_id, date):
    all_slots = [
        "10:00 AM", "10:30 AM", "11:00 AM", "11:30 AM",
        "12:00 PM", "12:30 PM",
        "02:00 PM", "02:30 PM", "03:00 PM",
        "03:30 PM", "04:00 PM", "04:30 PM", "05:00 PM"
    ]

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT time FROM appointments WHERE doctor_id = ? AND date = ?", (doctor_id, date))
    booked_slots = [row['time'] for row in cur.fetchall()]
    conn.close()

    return jsonify({"booked": booked_slots})

@app.route('/cancel_booking', methods=['POST'])
def cancel_booking():
    if 'user_id' not in session:
        flash("Please log in to access your dashboard ❌", "error")
        return redirect(url_for('login'))

    data = request.get_json(force=True)
    appointment_id = data.get("appointment_id")

    if not appointment_id:
        return jsonify({"success": False, "error": "Missing appointment ID"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    # Only delete if this appointment belongs to the logged-in user
    cur.execute("""
        DELETE FROM appointments
        WHERE id = ? AND user_id = ?
    """, (appointment_id, session['user_id']))
    
    conn.commit()
    deleted = cur.rowcount
    conn.close()

    if deleted:
        return jsonify({"success": True, "message": "Appointment canceled successfully"})
    else:
        return jsonify({"success": False, "error": "Appointment not found or not authorized"}), 404

@app.route('/logout')
def logout():
    # Clear all session keys related to the user
    session.pop('user_id', None)
    session.pop('name', None)
    session.pop('role_id', None)
    
    flash("You have been logged out successfully ✅", "success")
    return redirect(url_for('home'))

# ------------------------------
# Admin Routes
# ------------------------------

@app.route('/admin_dashboard')
def admin_dashboard():
    # Require admin
    if 'admin' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM doctors ORDER BY specialization, name")
    rows = cur.fetchall()
    conn.close()

    # Convert stored comma text into list for template
    doctors = []
    for row in rows:
        doctors.append({
            'id': row['id'],
            'name': row['name'],
            'specialization': row['specialization'],
            'available_slots': [s.strip() for s in row['available_slots'].split(',') if s.strip()]
        })

    return render_template('admin_dashboard.html', doctors=doctors)

@app.route('/add_doctor', methods=['POST'])
def add_doctor():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    phone_number = data.get('phone_number')
    specialization = data.get('specialization')
    experience_years = data.get('experience_years')

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Create a new user with doctor role_id (assuming 2 = doctor)
        cur.execute("""
            INSERT INTO users (name, email, password, phone_number, role_id)
            VALUES (?, ?, ?, ?, (SELECT id FROM roles WHERE role_name = 'doctor'))
        """, (name, email, "doctor123", phone_number))
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
        # Delete doctor (cascade removes user too if defined in FK)
        cur.execute("DELETE FROM doctors WHERE doctor_id = ?", (doctor_id,))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)})
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)
