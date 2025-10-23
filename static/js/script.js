document.addEventListener("DOMContentLoaded", function () {
    console.log("Scripts loaded!");

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
