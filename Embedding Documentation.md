
# Embedding the Appointment Booking System in Your Website

This section will guide you through integrating the appointment booking system into your existing website.

## Prerequisites
Ensure that you have the following:
- A running Flask application (see the **Installation** section of the README).
- A website where you want to embed the appointment booking system.

## Steps to Embed the Booking System

### 1. Set Up the Flask Application
Ensure that your Flask application is running locally or on a server. By default, it will be accessible at `http://127.0.0.1:5000/`. If you have deployed it to a live server, make sure to use the live URL.

### 2. Create an Embed Container in Your Website

In the HTML of your website where you want the booking system to appear, create a container element (like a `div`) where the booking system will be embedded.

```html
<div id="appointment-booking-container">
  <iframe src="http://127.0.0.1:5000/booking" width="100%" height="600px" frameborder="0"></iframe>
</div>
```

If the Flask app is hosted online, replace the `src` URL with the live URL.

### 3. Adjust Size and Styling
You may need to adjust the iframe's `width`, `height`, and `border` attributes to fit the design and layout of your website.

You can also apply additional CSS to style the container as needed:

```html
<style>
  #appointment-booking-container {
    max-width: 100%;
    margin: 20px 0;
    padding: 0;
    background-color: #f9f9f9;
  }
  iframe {
    width: 100%;
    height: 600px;
    border: none;
  }
</style>
```

### 4. Testing the Embedded System
Once the iframe is added to your website, visit your website's page where the appointment booking system is embedded. Verify the following:
- The booking page is displayed correctly within the iframe.
- Users can log in, sign up, and book appointments without any issues.

## Using Customization or API Endpoints
You may also wish to use the available API endpoints (`/api/available_slots` and `/api/book_appointment`) to embed the functionality directly into your website without an iframe.

For example, you could make AJAX calls to these endpoints from your site’s frontend, manage slots dynamically, and handle appointments without using the iframe. You will need JavaScript for this:

```javascript
// Fetch available slots for a given date
fetch('http://127.0.0.1:5000/api/available_slots?date=2025-03-15')
  .then(response => response.json())
  .then(data => {
    // Use the data to dynamically display available slots
    console.log(data.available_slots);
  });

// Book an appointment
fetch('http://127.0.0.1:5000/api/book_appointment', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    name: 'John Doe',
    phone_number: '1234567890',
    date: '2025-03-15',
    time: '09:00'
  })
})
  .then(response => response.json())
  .then(data => {
    console.log(data.message);
  });
```

## Security Considerations for Embedding

- **CORS (Cross-Origin Resource Sharing)**: If you're embedding the system from a different domain, ensure that your Flask application is configured to allow cross-origin requests.
- **Session Management**: The embedded system relies on Flask’s session management. Ensure the session cookies are handled correctly in the iframe to maintain user authentication.

### Example for Enabling CORS in Flask:

```python
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
```
