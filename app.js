const express = require("express");
const router = express.Router();
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const flash = require("express-flash");
const session = require("express-session");
const cookieParser = require("cookie-parser");
require('dotenv').config();
const app = express();
const PORT = 4000;
const SECRET_KEY = "your_secret_key"; // Change this to a strong secret

// Middleware Setup
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
// app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
//  Session & Flash Setup (Place Before Using `flash`)
app.use(
  session({
    secret: SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true },
  })
);
app.use(flash());

// MySQL Connection
const db = mysql.createConnection({

  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});
app.use((req, res, next) => {
  res.locals.successMessage = req.flash("success");
  res.locals.errorMessage = req.flash("error");
  next();
});
db.connect((err) => {
  if (err) {
    console.error("Database connection failed: " + err.message);
    process.exit(1);
  }
  console.log(" MySQL Connected...");
});

//  Middleware to Verify JWT Token
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.redirect("/login");
  try {
    const verified = jwt.verify(token, SECRET_KEY);
    req.user = verified;
    next();
  } catch (err) {
    return res.redirect("/login");
  }
};

app.get("/", (req, res) => {
  res.render("home");
});

//  Login Route
app.get("/login", (req, res) => {
  res.render("login", {
    errorMessage: req.flash("error"),
    successMessage: req.flash("success"),
  });
});

//  Handle Login
app.post("/login", (req, res) => {
  const { userType, username, password } = req.body;
  let sql =
    userType === "doctor"
      ? "SELECT * FROM doctors WHERE username = ?"
      : "SELECT * FROM patients WHERE username = ?";

  db.query(sql, [username], async (err, results) => {
    if (err || results.length === 0) {
      return res.render("login", { errorMessage: " Invalid Credentials." });
    }
    const user = results[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.render("login", { errorMessage: " Invalid Credentials." });
    }
    const token = jwt.sign(
      { id: user.patient_id || user.doctor_id, role: userType },
      SECRET_KEY,
      { expiresIn: "24h" }
    );
    res.cookie("token", token, { httpOnly: true });
    res.redirect(
      userType === "doctor" ? "/doctor-dashboard" : "/patient-dashboard"
    );
  });
});

//  Logout Route
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.redirect("/login");
});

//  Patient Dashboard (Protected)
app.get("/patient-dashboard", verifyToken, (req, res) => {
  if (req.user.role !== "patient") {
    req.flash("error", " Unauthorized Access!");
    return res.redirect("/login");
  }

  const patientId = req.user.id;

  // Queries to fetch prescriptions, patient details, and appointments
  const prescriptionsQuery = `
    SELECT prescriptions.*, doctors.name AS doctor_name 
    FROM prescriptions 
    JOIN doctors ON prescriptions.doctor_id = doctors.doctor_id
    WHERE prescriptions.patient_id = ?
`;

  const patientQuery = "SELECT * FROM patients WHERE patient_id = ?";

  const appointmentsQuery = `
        SELECT a.*, d.name AS doctor_name, d.contact_no, a.status
        FROM appointments a
        JOIN doctors d ON a.doctor_id = d.doctor_id
        WHERE a.patient_id = ?
        ORDER BY a.appointment_time DESC
    `;

  // Execute all queries in parallel
  db.query(prescriptionsQuery, [patientId], (err, prescriptions) => {
    if (err) {
      req.flash("error", " Failed to fetch prescriptions.");
      return res.redirect("/login");
    }

    db.query(patientQuery, [patientId], (err, patientResults) => {
      if (err || patientResults.length === 0) {
        req.flash("error", " Patient not found.");
        return res.redirect("/");
      }

      db.query(appointmentsQuery, [patientId], (err, appointmentResults) => {
        if (err) {
          req.flash("error", " Error fetching appointments.");
          return res.redirect("/");
        }

        //  Send all data in ONE render call
        res.render("patient_dashboard", {
          prescriptions: prescriptions || [], // Ensure prescriptions is always an array
          user: patientResults[0],
          appointments: appointmentResults || [],
        });
      });
    });
  });
});

//accept appointments
app.post("/accept-appointment/:id", verifyToken, (req, res) => {
  const appointmentId = req.params.id;
  const sql =
    "UPDATE appointments SET status = 'Accepted' WHERE id = ? AND doctor_id = ?";

  db.query(sql, [appointmentId, req.user.id], (err) => {
    if (err) {
      req.flash("error", " Could not accept appointment.");
      return res.redirect("/doctor-dashboard");
    }
    req.flash("success", " Appointment accepted successfully!");
    res.redirect("/doctor-dashboard");
  });
});

app.post("/update-appointment-status", verifyToken, (req, res) => {
  console.log("Received POST request to update appointment status");
  console.log("Request Body:", req.body);

  if (req.user.role !== "doctor") {
    req.flash("error", " Unauthorized Access!");
    return res.redirect("/login");
  }

  const { appointment_id, status } = req.body;

  if (!["Accepted", "Rejected"].includes(status)) {
    req.flash("error", " Invalid status update.");
    return res.redirect("/doctor-dashboard");
  }

  const updateQuery =
    "UPDATE appointments SET status = ? WHERE id = ? AND doctor_id = ?";

  db.query(updateQuery, [status, appointment_id, req.user.id], (err) => {
    if (err) {
      console.error("DB Error:", err);
      req.flash("error", " Failed to update status.");
      return res.redirect("/doctor-dashboard");
    }
    req.flash("success", ` Appointment ${status}!`);
    res.redirect("/doctor-dashboard");
  });
});

//To give Prescription
app.get("/patient", (req, res) => {
  if (!req.user || !req.user.patient_id) {
    console.log(" Patient ID is missing!", req.user);
    req.flash("error", " Unauthorized Access!");
    return res.redirect("/login");
  }

  const patientId = req.user.patient_id;
  console.log("Patient ID:", patientId); // Debugging Log

  const query = `
        SELECT prescriptions.*, doctors.name AS doctor_name 
        FROM prescriptions 
        JOIN doctors ON prescriptions.doctor_id = doctors.doctor_id
        WHERE prescriptions.patient_id = ?
    `;

  db.query(query, [patientId], (err, results) => {
    if (err) {
      console.error(" Error fetching prescriptions:", err);
      req.flash("error", " Failed to fetch prescriptions.");
      return res.redirect("/login");
    }

    console.log("Fetched Prescriptions:", results); // Debugging log
    res.render("patient_dashboard", { prescriptions: results });
  });
});

//prescription fetch for patient

app.get("/patient", (req, res) => {
  if (!req.user || !req.user.patient_id) {
    req.flash("error", " Unauthorized Access or Missing Patient ID!");
    return res.redirect("/login");
  }

  const patientId = req.user.patient_id;
  console.log("Extracted Patient ID:", patientId);

  const query = "SELECT * FROM prescriptions WHERE patient_id = ?";

  db.query(query, [patientId], (err, results) => {
    if (err) {
      console.error(" Error fetching prescriptions:", err);
      req.flash("error", " Failed to fetch prescriptions.");
      return res.redirect("/login");
    }

    console.log("Fetched Prescriptions:", results);

    res.render("patient_dashboard", { prescriptions: results });
  });
});

//doctor dashboard

app.get("/doctor-dashboard", verifyToken, (req, res) => {
  if (req.user.role !== "doctor") {
    req.flash("error", " Unauthorized Access!");
    return res.redirect("/login");
  }

  const doctorQuery = "SELECT * FROM doctors WHERE doctor_id = ?";
  const appointmentsQuery = `
        SELECT a.*, p.name AS patient_name, p.contact_no, a.status 
        FROM appointments a
        JOIN patients p ON a.patient_id = p.patient_id
        WHERE a.doctor_id = ?
    `;
  const feedbackQuery = `
        SELECT f.rating, f.comment, f.created_at, p.name AS patient_name
        FROM feedback f
        JOIN patients p ON f.patient_id = p.patient_id
        WHERE f.doctor_id = ?
    `;

  db.query(doctorQuery, [req.user.id], (err, doctorResults) => {
    if (err || doctorResults.length === 0) {
      req.flash("error", " Doctor not found.");
      return res.redirect("/");
    }

    db.query(appointmentsQuery, [req.user.id], (err, appointmentResults) => {
      if (err) {
        req.flash("error", " Error fetching appointments.");
        return res.redirect("/");
      }

      db.query(feedbackQuery, [req.user.id], (err, feedbackResults) => {
        if (err) {
          req.flash("error", " Error fetching feedbacks.");
          return res.redirect("/");
        }

        res.render("doctor_dashboard", {
          doctor: doctorResults[0],
          appointments: appointmentResults,
          feedbacks: feedbackResults, //  Pass feedbacks to EJS
        });
      });
    });
  });
});

//edit doctor
app.get("/edit-doctor-profile", verifyToken, (req, res) => {
  if (req.user.role !== "doctor") return res.status(403).send(" Unauthorized");

  const doctorQuery =
    "SELECT doctor_id, name, contact_no, specialization, gender FROM doctors WHERE doctor_id = ?";

  db.query(doctorQuery, [req.user.id], (err, results) => {
    if (err || results.length === 0) {
      // return res.status(404).send(" Doctor not found.");
      req.flash("error", " Doctor not found.");
    }
    res.render("edit_doctor_profile", { doctor: results[0] });
  });
});

app.post("/update-doctor-profile", verifyToken, (req, res) => {
  if (req.user.role !== "doctor") return res.status(403).send(" Unauthorized");

  const { doctor_id, name, contact_no, gender, specialization } = req.body;

  const sql = `
        UPDATE doctors 
        SET name = ?, contact_no = ?, gender = ?, specialization = ? 
        WHERE doctor_id = ?
    `;

  db.query(
    sql,
    [name, contact_no, gender, specialization, doctor_id],
    (err, result) => {
      if (err) {
        console.error("Error updating doctor profile:", err);
        return res.status(500).send(" Error updating profile.");
      }
      res.redirect("/doctor-dashboard"); // Redirect to dashboard after update
    }
  );
});

app.get("/delete-doctor-account", verifyToken, (req, res) => {
  if (req.user.role !== "doctor") return res.status(403).send(" Unauthorized");

  const deleteQuery = "DELETE FROM doctors WHERE doctor_id = ?";

  db.query(deleteQuery, [req.user.id], (err) => {
    if (err) {
      console.error("Error deleting doctor account:", err);
      return res.status(500).send(" Error deleting account.");
    }
    res.redirect("/login"); // Redirect to login page after deletion
  });
});

//  Edit Patient Profile (GET - Show Form)
app.get("/edit-profile", verifyToken, (req, res) => {
  if (req.user.role !== "patient") return res.status(403).send(" Unauthorized");

  db.query(
    "SELECT * FROM patients WHERE patient_id = ?",
    [req.user.id],
    (err, results) => {
      if (err || results.length === 0) {
        return res.status(500).send(" Error fetching patient data.");
      }
      res.render("edit_profile", { user: results[0] });
    }
  );
});

app.post("/edit-profile", verifyToken, async (req, res) => {
  const userId = req.user.id; // Get logged-in patient ID
  const { name, contact_no, gender, password } = req.body;

  try {
    let sql =
      "UPDATE patients SET name = ?, contact_no = ?, gender = ? WHERE patient_id = ?";
    let values = [name, contact_no, gender, userId];

    // If password is provided, hash it before updating
    if (password && password.trim() !== "") {
      const hashedPassword = await bcrypt.hash(password, 10);
      sql =
        "UPDATE patients SET name = ?, contact_no = ?, gender = ?, password = ? WHERE patient_id = ?";
      values = [name, contact_no, gender, hashedPassword, userId];
    }

    db.query(sql, values, (err, result) => {
      if (err) {
        console.error(" Error updating profile:", err);
        return res.status(500).send(" Internal Server Error");
      }

      if (result.affectedRows === 0) {
        return res.status(404).send(" No matching patient found.");
      }

      res.redirect("/patient-dashboard"); // Redirect to dashboard after update
    });
  } catch (error) {
    console.error(" Unexpected error:", error);
    res.status(500).send(" Internal Server Error");
  }
});

//  Delete Patient Account
app.get("/delete-account", verifyToken, (req, res) => {
  if (req.user.role !== "patient") return res.status(403).send(" Unauthorized");

  db.query(
    "DELETE FROM patients WHERE patient_id = ?",
    [req.user.id],
    (err) => {
      if (err) return res.status(500).send(" Error deleting account.");
      res.clearCookie("token");
      res.redirect("/login");
    }
  );
});

// Serve Patient Registration Page
app.get("/register-patient", (req, res) => {
  res.render("patient_registration");
});

// Handle Patient Registration
app.post("/register-patient", async (req, res) => {
  const { patient_id, name, username, password, contact_no, gender } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const sql =
    "INSERT INTO patients (patient_id, name, username, password, contact_no, gender) VALUES (?, ?, ?, ?, ?, ?)";

  db.query(
    sql,
    [patient_id, name, username, hashedPassword, contact_no, gender],
    (err, result) => {
      if (err) {
        console.error(err);
        req.flash("error", " Registration failed. Try again!");
        return res.redirect("/register-patient");
      } else {
        req.flash("success", " Registration successful! Please log in.");
        return res.redirect("/login");
      }
    }
  );
});

// Serve Doctor Registration Page

app.get("/register-doctor", (req, res) => {
  res.render("doctor_registration");
});

app.post("/register-doctor", async (req, res) => {
  const {
    doctor_id,
    name,
    username,
    password,
    contact_no,
    specialization,
    gender,
  } = req.body;

  // Hash the password securely
  const hashedPassword = await bcrypt.hash(password, 10);

  // Corrected SQL query (including specialization)
  const sql =
    "INSERT INTO doctors (doctor_id, name, username, password, contact_no, specialization, gender) VALUES (?, ?, ?, ?, ?, ?, ?)";

  db.query(
    sql,
    [
      doctor_id,
      name,
      username,
      hashedPassword,
      contact_no,
      specialization,
      gender,
    ],
    (err, result) => {
      if (err) {
        console.error("Error inserting doctor:", err);
        req.flash("error", " Registration failed. Try again!");
        return res.redirect("/register-doctor");
      } else {
        req.flash("success", " Registration successful! Please log in.");
        return res.redirect("/login");
      }
    }
  );
});
//  Edit and delete appointments
app.get("/edit-appointment/:id", verifyToken, (req, res) => {
  const appointmentId = req.params.id;
  const sql = "SELECT * FROM appointments WHERE id = ? AND patient_id = ?";

  db.query(sql, [appointmentId, req.user.id], (err, results) => {
    if (err || results.length === 0) {
      req.flash("error", " Appointment not found.");
      return res.redirect("/patient-dashboard");
    }
    res.render("edit-appointment", { appointment: results[0] });
  });
});

app.post("/update-appointment/:id", verifyToken, async (req, res) => {
  try {
    let { contact_no, symptoms, appointment_time } = req.body;
    const appointmentId = req.params.id;

    //  Validate mobile number (should be exactly 10 digits)
    if (!/^\d{10}$/.test(contact_no)) {
      req.flash("error", " Invalid contact number. Must be 10 digits.");
      return res.redirect("/edit-appointment/" + appointmentId);
    }

    //  Ensure appointment date is today or in the future
    const selectedDate = new Date(appointment_time);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    if (selectedDate < today) {
      req.flash("error", " Appointment date must be today or a future date.");
      return res.redirect("/edit-appointment/" + appointmentId);
    }

    const formattedTime = selectedDate
      .toISOString()
      .slice(0, 19)
      .replace("T", " ");

    const sql =
      "UPDATE appointments SET contact_no = ?, symptoms = ?, appointment_time = ? WHERE id = ? AND patient_id = ?";
    const [result] = await db
      .promise()
      .execute(sql, [
        contact_no,
        symptoms,
        formattedTime,
        appointmentId,
        req.user.id,
      ]);

    if (result.affectedRows === 0) {
      req.flash("error", " No appointment found or unauthorized.");
      return res.redirect("/edit-appointment/" + appointmentId);
    }

    req.flash("success", " Appointment updated successfully!");
    res.redirect("/patient-dashboard");
  } catch (err) {
    console.error("MySQL Error:", err);
    req.flash("error", " Could not update appointment.");
    res.redirect("/edit-appointment/" + req.params.id);
  }
});

app.get("/delete-appointment/:id", verifyToken, (req, res) => {
  const appointmentId = req.params.id;
  const sql = "DELETE FROM appointments WHERE id = ? AND patient_id = ?";

  db.query(sql, [appointmentId, req.user.id], (err) => {
    if (err) {
      req.flash("error", " Could not delete appointment.");
      return res.redirect("/patient-dashboard");
    }
    req.flash("success", " Appointment deleted successfully!");
    res.redirect("/patient-dashboard");
  });
});

//  Book Appointment (GET Form)
app.get("/book-appointment", verifyToken, (req, res) => {
  db.query("SELECT doctor_id, name FROM doctors", (err, doctors) => {
    if (err) return res.status(500).send(" Error fetching doctors.");
    res.render("book_appointment", { doctors, user: req.user });
  });
});

//  Handle Appointment Booking (POST)
app.post("/book-appointment", verifyToken, (req, res) => {
  let { doctor_id, contact_no, symptoms, appointment_time } = req.body;

  //  Validate mobile number (should be exactly 10 digits)
  if (!/^\d{10}$/.test(contact_no)) {
    req.flash("error", " Invalid contact number. Must be 10 digits.");
    return res.redirect("/book-appointment");
  }

  //  Ensure appointment date is today or in the future
  const selectedDate = new Date(appointment_time);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  if (selectedDate < today) {
    req.flash("error", " Appointment date must be today or a future date.");
    return res.redirect("/book-appointment");
  }

  db.query(
    "INSERT INTO appointments (patient_id, doctor_id, contact_no, symptoms, appointment_time) VALUES (?, ?, ?, ?, ?)",
    [req.user.id, doctor_id, contact_no, symptoms, appointment_time],
    (err) => {
      if (err) {
        console.error(" Error booking appointment:", err);
        req.flash("error", " Could not book appointment. Try again.");
        return res.redirect("/book-appointment");
      }
      req.flash("success", " Appointment Booked Successfully!");
      res.redirect("/patient-dashboard");
    }
  );
});

//  Edit and delete appointments (Duplicate cleaned up)
router.get("/edit-appointment/:id", async (req, res) => {
  const appointmentId = req.params.id;
  try {
    const [appointment] = await db.query(
      "SELECT * FROM appointments WHERE id = ?",
      [appointmentId]
    );

    if (!appointment) {
      return res.status(404).send("Appointment not found");
    }

    // Ensure correct datetime format
    appointment.appointment_time = new Date(appointment.appointment_time)
      .toISOString()
      .slice(0, 16);

    res.render("edit-appointment", { appointment });
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.post("/update-appointment/:id", verifyToken, (req, res) => {
  let { contact_no, symptoms, appointment_time } = req.body;
  const appointmentId = req.params.id;

  //  Validate mobile number (should be exactly 10 digits)
  if (!/^\d{10}$/.test(contact_no)) {
    req.flash("error", " Invalid contact number. Must be 10 digits.");
    return res.redirect("/edit-appointment/" + appointmentId);
  }

  //  Ensure appointment date is today or in the future
  const selectedDate = new Date(appointment_time);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  if (selectedDate < today) {
    req.flash("error", " Appointment date must be today or a future date.");
    return res.redirect("/edit-appointment/" + appointmentId);
  }

  db.query(
    "UPDATE appointments SET contact_no = ?, symptoms = ?, appointment_time = ? WHERE id = ? AND patient_id = ?",
    [contact_no, symptoms, appointment_time, appointmentId, req.user.id],
    (err) => {
      if (err) {
        req.flash("error", " Could not update appointment.");
        return res.redirect("/edit-appointment/" + appointmentId);
      }
      req.flash("success", " Appointment updated successfully!");
      res.redirect("/patient-dashboard");
    }
  );
});

app.get("/delete-appointment/:id", verifyToken, (req, res) => {
  const appointmentId = req.params.id;
  const sql = "DELETE FROM appointments WHERE id = ? AND patient_id = ?";

  db.query(sql, [appointmentId, req.user.id], (err) => {
    if (err) {
      req.flash("error", " Could not delete appointment.");
      return res.redirect("/patient-dashboard");
    }
    req.flash("success", " Appointment deleted successfully!");
    res.redirect("/patient-dashboard");
  });
});

// Render Feedback Form with Doctors List
//  Render Feedback Page (GET)
app.get("/feedback", verifyToken, (req, res) => {
  db.query("SELECT doctor_id, name FROM doctors", (err, doctors) => {
    if (err) {
      console.error(" Error fetching doctors:", err);
      return res.status(500).send(" Error fetching doctors.");
    }
    res.render("feedback", { doctors, user: req.user });
  });
});

//  Handle Feedback Submission (POST)
app.post("/submit-feedback", verifyToken, (req, res) => {
  const { doctor_id, rating, comment } = req.body;
  const patient_id = req.user ? req.user.id : null;

  if (!patient_id) {
    req.flash("error", " Unauthorized. Please log in.");
    return res.redirect("/login");
  }

  // Check if doctor exists
  db.query(
    "SELECT doctor_id FROM doctors WHERE doctor_id = ?",
    [doctor_id],
    (err, doctorResults) => {
      if (err || doctorResults.length === 0) {
        req.flash("error", "Selected doctor does not exist.");
        return res.redirect("/submit-feedback");
      }

      // Insert Feedback
      db.query(
        "INSERT INTO feedback (patient_id, doctor_id, rating, comment) VALUES (?, ?, ?, ?)",
        [patient_id, doctor_id, rating, comment],
        (err) => {
          if (err) {
            console.error("Error submitting feedback:", err);
            req.flash("error", "Could not submit feedback. Try again.");
            return res.redirect("/submit-feedback");
          }
          req.flash("success", "Feedback submitted successfully!");
          res.redirect("/patient-dashboard");
        }
      );
    }
  );
});

app.get("/feedback/:doctor_id", verifyToken, async (req, res) => {
  const doctor_id = req.params.doctor_id;

  try {
    const [doctor] = await db.execute(
      "SELECT doctor_id, name FROM doctors WHERE doctor_id = ?",
      [doctor_id]
    );

    if (doctor.length === 0) {
      return res.status(404).send("Doctor not found.");
    }

    res.render("feedback", {
      doctor_id,
      patient_id: req.user.id, // Get patient ID from logged-in user
      doctor: doctor[0],
    });
  } catch (error) {
    console.error("Error fetching doctor:", error);
    res.status(500).send("Internal Server Error.");
  }
});
app.get("/doctor-feedback/:doctor_id", async (req, res) => {
  const doctor_id = req.params.doctor_id;

  try {
    const [feedback] = await db.execute(
      "SELECT f.rating, f.comment, p.name AS patient_name FROM feedback f JOIN patients p ON f.patient_id = p.id WHERE f.doctor_id = ?",
      [doctor_id]
    );

    res.render("doctor-feedback", { feedback });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).send("Database error.");
  }
});

//submit prescription

app.post("/submit-prescription", verifyToken, async (req, res) => {
  const { appointment_id, prescription_text } = req.body;
  const doctor_id = req.user.id; // Get logged-in doctor's ID

  try {
    // Get patient_id from appointment
    const [rows] = await db
      .promise()
      .query("SELECT patient_id FROM appointments WHERE id = ?", [
        appointment_id,
      ]);

    console.log("Appointment Query Result:", rows);

    if (!rows || rows.length === 0) {
      req.flash("error", "Appointment not found.");
      return res.redirect("/doctor-dashboard");
    }

    const patient_id = rows[0].patient_id; // Corrected extraction
    console.log("Patient ID Retrieved:", patient_id);

    // Insert prescription into database
    await db
      .promise()
      .query(
        "INSERT INTO prescriptions (appointment_id, doctor_id, patient_id, prescription_text) VALUES (?, ?, ?, ?)",
        [appointment_id, doctor_id, patient_id, prescription_text]
      );

    req.flash("success", "Prescription saved successfully!");
    res.redirect("/doctor-dashboard");
  } catch (error) {
    console.error("Database Error:", error);
    req.flash("error", "Error saving prescription.");
    res.redirect("/doctor-dashboard");
  }
});

//  Start Server
app.listen(4000, () => console.log("Server running on http://localhost:4000"));
