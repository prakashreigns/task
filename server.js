require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(cors());

const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/userDB";
const JWT_SECRET = process.env.JWT_SECRET || "default_secret_key";

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log(" MongoDB Connected"))
    .catch(err => console.error(" MongoDB Connection Error:", err));


const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    gender: { type: String, required: true }
});

const User = mongoose.model("User", userSchema, "users");

const generateToken = (user) => jwt.sign(
    { id: user._id, username: user.username }, 
    JWT_SECRET, 
    { expiresIn: "1h" }
);

app.post('/register', async (req, res) => {
    try {
        const { username, password, email, gender } = req.body;

        if (!username || !password || !email || !gender) {
            return res.status(400).json({ message: "All fields are required!" });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: "Username already exists!" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, email, gender });
        await newUser.save();

        res.status(201).json({ message: "User registered successfully!" });
    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: "Both fields are required!" });
        }

        const user = await User.findOne({ username });
        if (!user) {
            console.log(" User not found in database:", username);
            return res.status(401).json({ message: "Invalid username or password" });
        }

        console.log(" User found:", user);

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log(" Password mismatch. Entered:", password, "Stored:", user.password);
            return res.status(401).json({ message: "Invalid username or password" });
        }

        const token = generateToken(user);
        console.log(" Login successful:", username);

        res.status(200).json({ 
            message: "Login successful!", 
            token, 
            user: { id: user._id, username: user.username, email: user.email, gender: user.gender }
        });
    } catch (error) {
        console.error(" Login Error:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(` Server running at http://localhost:${PORT}`));
