document.addEventListener("DOMContentLoaded", function () {
    console.log("Scripts loaded!");

    // Cancel Appointment Function
    window.cancelAppointment = function (button) {
        let appointmentDetails = {
            date: button.getAttribute("data-date"),
            time: button.getAttribute("data-time"),
            name: button.getAttribute("data-name"),
            phone_number: button.getAttribute("data-phone_number")
        };

        if (!appointmentDetails.date || !appointmentDetails.time || !appointmentDetails.name) {
            console.error("Missing appointment details!", appointmentDetails);
            alert("Error: Appointment details are incomplete.");
            return;
        }

        if (!confirm(`Are you sure you want to cancel the appointment for ${appointmentDetails.name} on ${appointmentDetails.date} at ${appointmentDetails.time}?`)) {
            return;
        }

        console.log("Cancelling appointment with details:", appointmentDetails);

        fetch("/cancel_booking", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(appointmentDetails)
        })
        .then(response => response.json())
        .then(data => {
            console.log("Server response:", data);

            if (data.success) {
                alert("Appointment canceled successfully!");
                button.closest(".appointment-item").remove(); // Remove from UI
            } else {
                alert("Failed to cancel appointment: " + (data.error || "Unknown error"));
            }
        })
        .catch(error => {
            console.error("Error:", error);
            alert("There was an error while cancelling the appointment.");
        });
    };

    document.querySelector('.nav-btn')?.addEventListener('click', function(event) {
        event.preventDefault();  // Prevents the default action (scrolling)
        document.getElementById('contact-form').scrollIntoView({ behavior: 'smooth' });
    });
    
    // Admin Dashboard Scripts
    document.getElementById("addDoctorForm")?.addEventListener("submit", function(event) {
        event.preventDefault();
        
        let name = document.getElementById("name").value.trim();
        let department = document.getElementById("department").value.trim();
        let slots = document.getElementById("slots").value.split(",").map(slot => slot.trim());

        fetch('/add_doctor', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, department, slots })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert("Doctor added successfully!");
                location.reload();
            } else {
                alert("Error: " + data.error);
            }
        });
    });

    function deleteDoctor(id) {
        if (!confirm("Are you sure you want to delete this doctor?")) return;

        fetch('/delete_doctor', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert("Doctor deleted successfully!");
                location.reload();
            } else {
                alert("Error: " + data.error);
            }
        });
    }

    // Base.html Form Validation
    function validateForm() {
        let name = document.getElementById("name").value.trim();
        let email = document.getElementById("email").value.trim();
        let phone = document.getElementById("phone").value.trim();
        let message = document.getElementById("message").value.trim();
        let button = document.getElementById("submit-btn");
        let successMsg = document.getElementById("success-msg");

        if (name && email && phone && message) {
            button.style.background = "#00ff00";
            button.innerText = "✅ SUBMITTED";
            button.style.animation = "scaleUp 0.5s ease-in-out";

            successMsg.style.display = "block";

            setTimeout(() => {
                button.style.background = "#002F6C";
                button.innerText = "SUBMIT YOUR INQUIRY";
                successMsg.style.display = "none";
            }, 3000);
        } else {
            alert("Please fill in all fields before submitting!");
        }
    }

    // Booking.html Success/Error Messages
    window.onload = function() {
        const successMessage = document.getElementById("successMessage");
        const errorMessage = document.getElementById("errorMessage");

        if (successMessage) {
            successMessage.style.display = "block";
            setTimeout(() => {
                successMessage.style.opacity = "1";
                successMessage.style.transform = "translateY(0)";
                successMessage.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 300);
            setTimeout(() => {
                window.location.href = "{{ url_for('dashboard') }}";
            }, 5000);
        }

        if (errorMessage) {
            errorMessage.style.display = "block";
            setTimeout(() => {
                errorMessage.style.opacity = "1";
                errorMessage.style.transform = "translateY(0)";
                errorMessage.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 300);
        }
    };

    // Auto-hide Flash Messages
    setTimeout(function() {
        document.querySelectorAll('.flash-message').forEach(msg => {
            msg.style.transition = "opacity 0.5s";
            msg.style.opacity = "0";
            setTimeout(() => msg.remove(), 500);
        });
    }, 3000);
});
