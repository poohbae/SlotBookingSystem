from flask import Flask, render_template, flash, request, redirect, url_for, session, jsonify
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session handling


# Function to get a database connection
def get_db_connection(db_name):
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row  # Enables dictionary-like row access
    return conn


# Function to validate login
def validate_login(username, password):
    conn = get_db_connection('db_folder/database_new.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()
    return user


# Helper Function to Get User Email (for Booking API)
def get_user_email(username):
    conn = get_db_connection('db_folder/database_new.db')
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM users WHERE username = ?", (username,))
    user_email = cursor.fetchone()
    conn.close()
    return user_email['email'] if user_email else None


# Home Route
@app.route("/")
def home():
    return render_template("home.html")

# Admin Dashboard Route
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))
    return render_template("admin_dashboard.html")

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        user = validate_login(username, password)

        if user:
            role = user['role'] if 'role' in user.keys() else user.get('roless')  # Handle different role column names
            session['user'] = user['username']

            if role == 'admin':  # Redirect admins
                session['admin'] = user['username']
                flash("Admin Login successful! ✅", "success")
                return redirect(url_for('admin_dashboard'))
            else:  # Redirect regular users
                flash("Login successful! ✅", "success")
                return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password ❌", "error")

    return render_template('login.html')


# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        email = request.form['email'].strip()

        conn = get_db_connection('db_folder/database_new.db')
        cursor = conn.cursor()

        # Check if user already exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            flash("User already exists!", "error")
            return render_template('signup.html')

        try:
            role = 'admin' if username.lower() == 'admin' else 'customer'
            cursor.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                           (username, password, email, role))
            conn.commit()
            flash("Signup successful! ✅ Please login.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or Email already exists!", "error")
        finally:
            conn.close()

    return render_template('signup.html')


# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection('db_folder/database_new.db')
    cursor = conn.cursor()

    cursor.execute("SELECT email FROM users WHERE username = ?", (session['user'],))
    user_email = cursor.fetchone()

    appointments = []
    if user_email:
        email = user_email['email']
        conn_appointments = get_db_connection('db_folder/appointments_database.db')
        cursor_appointments = conn_appointments.cursor()

        cursor_appointments.execute("SELECT name, phone_number, date, time FROM appointments WHERE email = ?", (email,))
        appointments = cursor_appointments.fetchall()

        conn_appointments.close()

    conn.close()
    return render_template('dashboard.html', username=session['user'], appointments=appointments)


# Booking Route
@app.route('/booking', methods=['GET', 'POST'])
def booking():
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection('db_folder/database_new.db')
    cursor = conn.cursor()

    cursor.execute("SELECT email FROM users WHERE username = ?", (session['user'],))
    user_email = cursor.fetchone()
    conn.close()

    if not user_email:
        flash("User email not found!", "error")
        return redirect(url_for('dashboard'))

    email = user_email['email']

    if request.method == 'POST':
        name = request.form.get('name')
        phone_number = request.form.get('phone_number')
        date = request.form.get('date')
        time = request.form.get('time')

        if not phone_number:
            flash("❌ Phone number is required!", "error")
            return redirect(url_for('booking'))

        conn = get_db_connection('db_folder/appointments_database.db')
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM appointments WHERE date = ? AND time = ?", (date, time))
        existing_appointment = cursor.fetchone()

        if existing_appointment:
            flash("❌ Selected time slot is already booked!", "error")
        else:
            cursor.execute("""
                INSERT INTO appointments (email, name, phone_number, date, time)
                VALUES (?, ?, ?, ?, ?)""", (email, name, phone_number, date, time))
            conn.commit()
            flash("✅ Appointment booked successfully!", "success")

        conn.close()
        return redirect(url_for('dashboard'))

    return render_template('booking.html')


# Cancel Booking Route
@app.route('/cancel_booking', methods=['POST'])
def cancel_booking():
    if 'user' not in session:
        return jsonify({"success": False, "error": "Not logged in"}), 403

    data = request.get_json()
    date, time = data.get("date"), data.get("time")

    if not all([date, time]):
        return jsonify({"success": False, "error": "Missing appointment details"}), 400

    conn = get_db_connection('db_folder/appointments_database.db')
    cursor = conn.cursor()

    cursor.execute("DELETE FROM appointments WHERE date = ? AND time = ?", (date, time))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Appointment canceled successfully"})


# Logout Route
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))


# API to Fetch Available Slots
@app.route('/api/available_slots', methods=['GET'])
def available_slots():
    if 'user' not in session:
        return jsonify({"success": False, "error": "Not logged in"}), 403

    date = request.args.get('date')
    if not date:
        return jsonify({"success": False, "error": "Date is required"}), 400

    # Fetch booked slots for the given date
    conn = get_db_connection('db_folder/appointments_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT time FROM appointments WHERE date = ?", (date,))
    booked_slots = {row['time'] for row in cursor.fetchall()}  # Using a set for faster lookup
    conn.close()

    # Define the possible slots (you can customize this based on your requirements)
    all_slots = [
        "09:00", "10:00", "11:00", "12:00", "13:00", "14:00", "15:00", "16:00", "17:00"
    ]

    # Filter out the booked slots
    available_slots = [slot for slot in all_slots if slot not in booked_slots]

    return jsonify({"success": True, "available_slots": available_slots})


# API to Book an Appointment
@app.route('/api/book_appointment', methods=['POST'])
def book_appointment():
    if 'user' not in session:
        return jsonify({"success": False, "error": "Not logged in"}), 403

    data = request.get_json()
    name = data.get('name')
    phone_number = data.get('phone_number')
    date = data.get('date')
    time = data.get('time')

    if not all([name, phone_number, date, time]):
        return jsonify({"success": False, "error": "All fields are required"}), 400

    # Check if the time slot is available
    conn = get_db_connection('db_folder/appointments_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM appointments WHERE date = ? AND time = ?", (date, time))
    existing_appointment = cursor.fetchone()

    if existing_appointment:
        conn.close()
        return jsonify({"success": False, "error": "Selected time slot is already booked"}), 409

    # Book the appointment
    user_email = get_user_email(session['user'])
    cursor.execute("""
        INSERT INTO appointments (email, name, phone_number, date, time)
        VALUES (?, ?, ?, ?, ?)""", (user_email, name, phone_number, date, time))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Appointment booked successfully"})


if __name__ == '__main__':
    app.run(debug=True)
