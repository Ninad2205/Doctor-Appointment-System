const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../models/db");

const router = express.Router();

// User Login Route
router.post("/login", (req, res) => {
    const { username, password, userType } = req.body;
    
    const table = userType === "doctor" ? "doctors" : "patients";
    
    db.query(`SELECT * FROM ${table} WHERE username = ?`, [username], async (err, results) => {
        if (err) return res.status(500).send("Server Error");
        if (results.length === 0) return res.status(401).render("login", { errorMessage: "Invalid Username or Password" });

        const user = results[0];

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).render("login", { errorMessage: "Invalid Password" });

        // Generate JWT token
        const token = jwt.sign({ id: user.id, role: userType }, process.env.JWT_SECRET, { expiresIn: "1h" });

        // Set token in cookies
        res.cookie("token", token, { httpOnly: true });

        // Redirect based on role
        if (userType === "doctor") {
            res.redirect("/doctor-dashboard");
        } else {
            res.redirect("/patient-dashboard");
        }
    });
});

// Logout Route
router.get("/logout", (req, res) => {
    res.clearCookie("token");
    res.redirect("/login");
});

module.exports = router;
