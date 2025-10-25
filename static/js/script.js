document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ script.js loaded successfully!");

    // ===============================
    //  Auto-hide Flash Messages
    // ===============================
    setTimeout(function () {
        document.querySelectorAll(".flash-message").forEach((msg) => {
            msg.style.transition = "opacity 0.5s";
            msg.style.opacity = "0";
            setTimeout(() => msg.remove(), 500);
        });
    }, 3000);

    // ===============================
    //  Signup Password Confirmation
    // ===============================
    const signupForm = document.getElementById("signupForm");
    if (signupForm) {
        const email = document.getElementById("email");
        const phone = document.getElementById("phone_number");
        const password = document.getElementById("password");
        const confirmPassword = document.getElementById("confirm_password");

        signupForm.addEventListener("submit", async (e) => {
            e.preventDefault(); // stop default submit first

            const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            const phonePattern = /^\d{7,15}$/;
            const strongPassword = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

            // Email validation
            if (!emailPattern.test(email.value.trim())) {
                Swal.fire({
                    icon: "error",
                    title: "Invalid Email",
                    text: "Please enter a valid email address (e.g., name@medcare.com).",
                    confirmButtonColor: "#0b2e59"
                });
                return;
            }

            // Phone validation
            if (!phonePattern.test(phone.value.trim())) {
                Swal.fire({
                    icon: "error",
                    title: "Invalid Phone Number",
                    text: "Phone number must contain only digits (7–15 digits).",
                    confirmButtonColor: "#0b2e59"
                });
                return;
            }

            // Password match
            if (password.value !== confirmPassword.value) {
                Swal.fire({
                    icon: "error",
                    title: "Password Mismatch",
                    text: "Please make sure both passwords are the same.",
                    confirmButtonColor: "#0b2e59"
                });
                return;
            }

            // Password strength
            if (!strongPassword.test(password.value)) {
                Swal.fire({
                    icon: "warning",
                    title: "Weak Password",
                    text: "Password must include uppercase, lowercase, and at least one number (min 8 chars).",
                    confirmButtonColor: "#0b2e59"
                });
                return;
            }

            // Final confirmation before submission
            const result = await Swal.fire({
                icon: "question",
                title: "Confirm Registration",
                text: "Are you sure all details are correct?",
                showCancelButton: true,
                confirmButtonText: "Yes, Sign Up",
                cancelButtonText: "Cancel",
                confirmButtonColor: "#0b2e59",
                cancelButtonColor: "#d33"
            });

            // Only submit if user confirms
            if (result.isConfirmed) {
                signupForm.submit();
            }
        });
    }

    // ===============================
    //  Admin Dashboard (Add / Delete Doctor)
    // ===============================
    const addDoctorForm = document.getElementById("addDoctorForm");
    if (addDoctorForm) {
        addDoctorForm.addEventListener("submit", (e) => {
            e.preventDefault();

            const name = document.getElementById("name").value.trim();
            const email = document.getElementById("email").value.trim();
            const phone = document.getElementById("phone_number").value.trim();
            const specialization = document.getElementById("specialization").value.trim();
            const experience = Number(document.getElementById("experience").value);

            const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            const phonePattern = /^\d{7,15}$/;

            // Email validation
            if (!emailPattern.test(email)) {
                Swal.fire({
                    icon: "error",
                    title: "Invalid Email",
                    text: "Please enter a valid email address (e.g., name@medcare.com).",
                    confirmButtonColor: "#0b2e59"
                });
                return;
            }

            // Phone number validation
            if (!phonePattern.test(phone)) {
                Swal.fire({
                    icon: "error",
                    title: "Invalid Phone Number",
                    text: "Phone number must contain only digits (7–15 digits).",
                    confirmButtonColor: "#0b2e59"
                });
                return;
            }

            // Confirm before submission
            Swal.fire({
                title: "Confirm Add Doctor",
                text: `Are you sure you want to add ${name}?`,
                icon: "question",
                showCancelButton: true,
                confirmButtonColor: "#0b2e59",
                cancelButtonColor: "#d33",
                confirmButtonText: "Yes, Add Doctor"
            }).then((result) => {
                if (!result.isConfirmed) return;

                const doctorData = {
                    name,
                    email,
                    phone_number: phone,
                    specialization,
                    experience_years: experience
                };

                fetch("/add_doctor", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(doctorData)
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        Swal.fire({
                            icon: "success",
                            title: "Doctor Added!",
                            text: "The new doctor has been added successfully.",
                            confirmButtonColor: "#0b2e59"
                        }).then(() => location.reload());
                    } else {
                        Swal.fire({
                            icon: "error",
                            title: "Error",
                            text: data.error || "Failed to add doctor.",
                            confirmButtonColor: "#0b2e59"
                        });
                    }
                })
                .catch(err => {
                    console.error(err);
                    Swal.fire({
                        icon: "error",
                        title: "Server Error",
                        text: "Something went wrong while adding the doctor.",
                        confirmButtonColor: "#0b2e59"
                    });
                });
            });
        });

        // Delete Doctor
        document.addEventListener("click", (event) => {
            if (event.target.classList.contains("delete-btn")) {
                const doctorId = event.target.dataset.id;

                Swal.fire({
                    title: "Are you sure?",
                    text: "This will permanently delete the doctor record!",
                    icon: "warning",
                    showCancelButton: true,
                    confirmButtonColor: "#d33",
                    cancelButtonColor: "#3085d6",
                    confirmButtonText: "Yes, delete it!"
                }).then((result) => {
                    if (!result.isConfirmed) return;

                    fetch('/delete_doctor', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ doctor_id: Number(doctorId) })
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            Swal.fire({
                                icon: "success",
                                title: "Deleted!",
                                text: "Doctor record deleted successfully.",
                                confirmButtonColor: "#0b2e59"
                            }).then(() => location.reload());
                        } else {
                            Swal.fire({
                                icon: "error",
                                title: "Error",
                                text: data.error || "Failed to delete doctor.",
                                confirmButtonColor: "#0b2e59"
                            });
                        }
                    })
                    .catch(err => {
                        console.error(err);
                        Swal.fire({
                            icon: "error",
                            title: "Server Error",
                            text: "Unable to delete doctor due to a server error.",
                            confirmButtonColor: "#0b2e59"
                        });
                    });
                });
            }
        });
    }

    // ===============================
    //  Doctor Dashboard (Approve / Reject Appointment)
    // ===============================
    const approveButtons = document.querySelectorAll(".approve-btn");
    const rejectButtons = document.querySelectorAll(".reject-btn");

    if (approveButtons.length > 0 || rejectButtons.length > 0) {
        approveButtons.forEach(btn => {
            btn.addEventListener("click", () => confirmUpdate(btn.dataset.id, "approved"));
        });
        rejectButtons.forEach(btn => {
            btn.addEventListener("click", () => confirmUpdate(btn.dataset.id, "rejected"));
        });

        function confirmUpdate(id, status) {
            const actionText = status === "approved" ? "approve" : "reject";
            const actionColor = status === "approved" ? "#28a745" : "#d33";

            Swal.fire({
                title: `Are you sure you want to ${actionText} this appointment?`,
                icon: "question",
                showCancelButton: true,
                confirmButtonColor: actionColor,
                cancelButtonColor: "#3085d6",
                confirmButtonText: `Yes, ${actionText} it!`
            }).then((result) => {
                if (result.isConfirmed) updateStatus(id, status);
            });
        }

        function updateStatus(id, status) {
            fetch("/update_appointment_status", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ appointment_id: id, status: status })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    Swal.fire({
                        icon: "success",
                        title: `Appointment ${status}!`,
                        text: `The appointment has been successfully ${status}.`,
                        confirmButtonColor: "#0b2e59"
                    }).then(() => location.reload());
                } else {
                    Swal.fire({
                        icon: "error",
                        title: "Error",
                        text: data.error || "Failed to update appointment.",
                        confirmButtonColor: "#0b2e59"
                    });
                }
            })
            .catch(err => {
                console.error(err);
                Swal.fire({
                    icon: "error",
                    title: "Server Error",
                    text: "An error occurred while updating the appointment status.",
                    confirmButtonColor: "#0b2e59"
                });
            });
        }
    }

    // ===============================
    //  Patient Dashboard (Booking + Cancel Appointment)
    // ===============================
    const specializationDropdown = document.getElementById("specialization");
    const doctorDropdown = document.getElementById("doctor");
    const dateInput = document.getElementById("date");
    const timeDropdown = document.getElementById("time");

    if (specializationDropdown && doctorDropdown && dateInput && timeDropdown) {
        const today = new Date().toISOString().split("T")[0];
        dateInput.min = today;

        specializationDropdown.addEventListener("change", () => {
            const specialization = specializationDropdown.value;
            doctorDropdown.innerHTML = "<option>Loading...</option>";

            fetch(`/get_doctors/${encodeURIComponent(specialization)}`)
                .then(res => res.json())
                .then(data => {
                    doctorDropdown.innerHTML = '<option value="">Select Doctor</option>';
                    data.forEach(doc => {
                        doctorDropdown.innerHTML += `<option value="${doc.doctor_id}">${doc.name}</option>`;
                    });
                })
                .catch(() => doctorDropdown.innerHTML = '<option>Error loading doctors</option>');
        });

        function updateTimeSlots() {
            const doctorId = doctorDropdown.value;
            const date = dateInput.value;
            if (!doctorId || !date) {
                timeDropdown.innerHTML = '<option>Select doctor and date first</option>';
                return;
            }
            timeDropdown.innerHTML = '<option>Loading...</option>';

            fetch(`/get_available_slots/${doctorId}/${encodeURIComponent(date)}`)
                .then(res => res.json())
                .then(data => {
                    const allSlots = [
                        "09:00 AM","09:30 AM",
                        "10:00 AM","10:30 AM","11:00 AM",
                        "11:30 AM","12:00 PM","12:30 PM",
                        "02:00 PM","02:30 PM","03:00 PM",
                        "03:30 PM","04:00 PM","04:30 PM",
                        "05:00 PM","05:30 PM"
                    ];

                    const today = new Date();
                    const selectedDate = new Date(date); // works with input type="date"
                    timeDropdown.innerHTML = "";

                    let availableCount = 0;

                    allSlots.forEach(slot => {
                        const option = document.createElement("option");
                        option.value = slot;
                        option.textContent = slot;

                        // Convert slot time into comparable Date object
                        const slotDateTime = new Date(selectedDate);
                        const [time, period] = slot.split(" ");
                        let [hour, minute] = time.split(":").map(Number);
                        if (period === "PM" && hour !== 12) hour += 12;
                        if (period === "AM" && hour === 12) hour = 0;
                        slotDateTime.setHours(hour, minute, 0, 0);

                        // Check booked or past
                        const isBooked = data.booked.includes(slot);
                        const isPast = (
                            selectedDate.toDateString() === today.toDateString() &&
                            slotDateTime < today
                        );

                        if (isBooked || isPast) {
                            option.disabled = true;
                            option.style.color = "gray";
                            if (isPast) option.textContent += " (Past)";
                        } else {
                            availableCount++;
                        }

                        timeDropdown.appendChild(option);
                    });

                    // If all slots are past or booked
                    if (availableCount === 0) {
                        timeDropdown.innerHTML = `
                            <option selected disabled>
                                All available times have passed for this date
                            </option>`;
                    }
                })
                .catch(() => {
                    timeDropdown.innerHTML = '<option>Error loading time slots</option>';
                });
        }

        doctorDropdown.addEventListener("change", updateTimeSlots);
        dateInput.addEventListener("change", updateTimeSlots);

        const bookForm = document.getElementById("bookAppointmentForm");
        if(bookForm) {
            bookForm.addEventListener("submit", (e) => {
                e.preventDefault();

                const specialization = specializationSelect.value;
                const doctor_id = doctorSelect.value;
                const date = dateInput.value;
                const time = timeSelect.value;

                fetch("/book_appointment", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ specialization, doctor_id, date, time })
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        Swal.fire({
                            icon: "success",
                            title: "Appointment Booked!",
                            text: data.message,
                            confirmButtonColor: "#0b2e59"
                        }).then(() => location.reload());
                    } else {
                        Swal.fire({
                            icon: "error",
                            title: "Booking Failed",
                            text: data.error || "Could not book appointment.",
                            confirmButtonColor: "#0b2e59"
                        });
                    }
                })
                .catch(err => {
                    console.error(err);
                    Swal.fire({
                        icon: "error",
                        title: "Server Error",
                        text: "Something went wrong while booking.",
                        confirmButtonColor: "#0b2e59"
                    });
                });
            });
        }
        
        // Cancel appointment buttons
        document.querySelectorAll(".cancel-btn").forEach(button => {
            button.addEventListener("click", () => {
                const appointmentId = button.dataset.id;
                Swal.fire({
                    title: "Cancel this appointment?",
                    text: "Once cancelled, it cannot be rebooked automatically.",
                    icon: "warning",
                    showCancelButton: true,
                    confirmButtonColor: "#d33",
                    cancelButtonColor: "#3085d6",
                    confirmButtonText: "Yes, cancel it!"
                }).then((result) => {
                    if (result.isConfirmed) cancelAppointment(appointmentId);
                });
            });
        });

        function cancelAppointment(id) {
            fetch("/cancel_booking", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ appointment_id: id })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    Swal.fire({
                        icon: "success",
                        title: "Appointment Cancelled",
                        text: "Your appointment has been successfully cancelled.",
                        confirmButtonColor: "#0b2e59"
                    }).then(() => {
                        document.getElementById(`appointment-${id}`)?.remove();
                    });
                } else {
                    Swal.fire({
                        icon: "error",
                        title: "Unable to Cancel",
                        text: data.error || "Appointment not found or already cancelled.",
                        confirmButtonColor: "#0b2e59"
                    });
                }
            })
            .catch(err => {
                console.error(err);
                Swal.fire({
                    icon: "error",
                    title: "Server Error",
                    text: "Something went wrong while cancelling the appointment.",
                    confirmButtonColor: "#0b2e59"
                });
            });
        }
    }
    const updateProfileForm = document.getElementById("updateProfileForm");
    if (updateProfileForm) {
        document.getElementById("updateProfileForm").addEventListener("submit", (e) => {
            e.preventDefault();

            const profileData = {
                name: document.getElementById("name").value,
                email: document.getElementById("email").value,
                phone_number: document.getElementById("phone_number").value,
                new_password: document.getElementById("new_password").value,
                confirm_password: document.getElementById("confirm_password").value
            };

            fetch("/update_profile", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(profileData)
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    Swal.fire({
                        icon: "success",
                        title: "Profile Updated",
                        text: data.message,
                        confirmButtonColor: "#0b2e59"
                    }).then(() => location.reload());
                } else {
                    Swal.fire({
                        icon: "error",
                        title: "Update Failed",
                        text: data.error,
                        confirmButtonColor: "#0b2e59"
                    });
                }
            })
            .catch(err => {
                console.error(err);
                Swal.fire({
                    icon: "error",
                    title: "Server Error",
                    text: "Something went wrong while updating your profile.",
                    confirmButtonColor: "#0b2e59"
                });
            });
        });
    }
});
