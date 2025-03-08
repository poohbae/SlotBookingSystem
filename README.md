
# Appointment Booking System

A simple web application built with Flask that allows users to log in, sign up, book appointments, and manage their bookings. This system also includes an admin dashboard for managing users and viewing their appointments.

## Features

- **User Authentication**: Users can sign up, log in, and log out.
- **Admin Dashboard**: Admins can access a dashboard to manage users and appointments.
- **Appointment Booking**: Users can book, view, and cancel appointments.
- **Slot Availability**: The app checks the availability of time slots for booking.
- **REST API**: Provides APIs to check available slots and book appointments.

## Prerequisites

- Python 3.x
- SQLite for database storage
- Flask (`pip install flask`)
- Jinja2 for templating (comes with Flask)

## Folder Structure

```plaintext
/Allotment Slot Booking System
│
├── db_folder
│   ├── database_new.db          # User data database
│   └── appointments_database.db # Appointments data
│
├── templates
│   ├── home.html               # Home page template
│   ├── login.html              # Login page template
│   ├── signup.html             # Signup page template
│   ├── admin_dashboard.html    # Admin Dashboard template
│   ├── dashboard.html          # User Dashboard template
│   └── booking.html            # Booking page template
│
├── app.py                       # Main Flask application
├── README.md                    # This file
└── requirements.txt             # Python dependencies (for virtual environments)
```

## Installation

1. Clone the repository or download the files.
2. Install dependencies:
   ```bash
   pip install flask
   ```
3. Set up the database:
   - Ensure SQLite is installed on your system.
   - Use `database_new.db` and `appointments_database.db` as your databases. You can use any SQLite tool to interact with the databases for testing.
4. Run the app:
   ```bash
   python app.py
   ```
   By default, the app will be available at `http://127.0.0.1:5000/`.

## Routes

1. **Home Route (`/`)**  
   The homepage of the application, accessible to all users.

2. **Login Route (`/login`)**  
   GET & POST methods allow users to log in. If successful, the user is redirected to the dashboard or admin dashboard.

3. **Signup Route (`/signup`)**  
   GET & POST methods for user registration. New users are required to provide a username, password, and email.

4. **Admin Dashboard Route (`/admin_dashboard`)**  
   Accessible only by admins, this page allows viewing and managing user information and appointments.

5. **Dashboard Route (`/dashboard`)**  
   The user’s personal dashboard to view upcoming appointments.

6. **Booking Route (`/booking`)**  
   Users can book appointments through this page. The available time slots for booking are defined and managed via the API.

7. **Cancel Booking Route (`/cancel_booking`)**  
   Allows users to cancel appointments. This route uses a POST request with appointment details.

8. **Logout Route (`/logout`)**  
   Logs the user out and redirects to the home page.

9. **API Endpoints**
   - **Get Available Slots**: `GET /api/available_slots`  
     Returns a list of available time slots for a specific date.
   - **Book an Appointment**: `POST /api/book_appointment`  
     Allows users to book an appointment by providing name, phone_number, date, and time.

## API Example

To fetch available slots:

```bash
GET http://127.0.0.1:5000/api/available_slots?date=2025-03-15
```

To book an appointment:

```bash
POST http://127.0.0.1:5000/api/book_appointment
{
  "name": "John Doe",
  "phone_number": "1234567890",
  "date": "2025-03-15",
  "time": "09:00"
}
```

## Functions

- **get_db_connection(db_name)**  
  This function establishes a connection to the SQLite database, allowing database interactions.

- **validate_login(username, password)**  
  Checks if a user exists in the database with the provided credentials (username and password).

- **get_user_email(username)**  
  Fetches the email associated with the given username.

- **cancel_booking()**  
  Handles the cancellation of an appointment, with JSON data passed for the date and time.

- **available_slots()**  
  Fetches the available slots for a specific date by querying the appointments database.

- **book_appointment()**  
  Books an appointment for the logged-in user after verifying that the requested time slot is available.

## Database Schema

**Users Table (`database_new.db`):**

| Column Name  | Type     | Description                            |
|--------------|----------|----------------------------------------|
| id           | INTEGER  | Primary Key                            |
| username     | TEXT     | User's unique username                 |
| password     | TEXT     | User's password                        |
| email        | TEXT     | User's email                           |
| role         | TEXT     | Role of the user ('admin' or 'customer')|

**Appointments Table (`appointments_database.db`):**

| Column Name  | Type     | Description                            |
|--------------|----------|----------------------------------------|
| id           | INTEGER  | Primary Key                            |
| email        | TEXT     | Email of the user booking the appointment |
| name         | TEXT     | Name of the user booking the appointment |
| phone_number | TEXT     | Phone number of the user booking the appointment |
| date         | TEXT     | Date of the appointment                |
| time         | TEXT     | Time of the appointment                |

## Security Considerations

- **Password Security**: The application currently stores passwords in plain text. It is recommended to use hashing algorithms (e.g., bcrypt) to store passwords securely.
- **Session Management**: The app uses Flask's built-in session handling for authentication. It's important to keep the session key (`app.secret_key`) secure.

## Contributing

Feel free to fork and submit pull requests to improve the project. Please ensure your changes are well-documented.

## License

This project is open-source and available under the MIT License.
