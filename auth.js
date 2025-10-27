const express = require("express");
const bcrypt = require("bcrypt");
const db = require("./db");
const jwt = require("jsonwebtoken");
require('dotenv').config();

app.use(express.json());

// Register
app.post("/v1/API/auth/register", async (req, res) => {
    const { fname, lname, email, phone, address, password, dob } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const query = 'INSERT INTO user(`first_name`, `last_name`, `email`, `phone`, `address`, `password`, `dob`) VALUES (?,?,?,?,?,?,?)';
        db.query(query, [fname, lname, email, phone, address, hashedPassword, dob], (err, result) => {
            res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
        });
    } catch (error) {
        console.error('Hashing error:', error);
        sendError(res, 500, "Error registering user");
    }
});

// Login 
app.post('/v1/API/auth/login', (req, res) => {
    const body = req.body || {};
    const { email, password } = body;

    const query = 'SELECT * FROM user WHERE email = ?';
    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error('DB error on login:', err);
            return sendError(res, 500, 'Database error');
        }

        if (results.length > 0) {
            const user = results[0];

            const isMatch = await bcrypt.compare(password, user.password);

            if (isMatch) {
                const payload = { id: user.id, email: user.email };
                const secret = process.env.JWT_SECRET;
                const token = jwt.sign(payload, secret, { expiresIn: '1h' });

                const { password: _, ...userSafe } = user;

                return res.status(200).json({ message: 'Login successful', token, user: userSafe });
            } else {
                return sendError(res, 401, 'Invalid credentials');
            }
        } else {
            return sendError(res, 404, 'User not found');
        }
    });
});

//verify JWT
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    if (!authHeader) return sendError(res, 401, 'Missing Authorization header');

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') return sendError(res, 401, 'Invalid Authorization format');

    const token = parts[1];
    const secret = process.env.JWT_SECRET;

    jwt.verify(token, secret, (err, decoded) => {
        if (err) {
            console.error('JWT verify error:', err);
            return sendError(res, 401, 'Invalid or expired token');
        }
        req.user = decoded;
        next();
    });
}

app.get('/', (req, res) => {
    res.send('server is running');
});

// User route
app.get('/v1/API/users', verifyToken, (req, res) => {
    const userId = req.user && req.user.id;
    if (!userId) return sendError(res, 400, 'Invalid token payload');

    const query = 'SELECT id, first_name, last_name, email, phone, address, dob FROM user WHERE id = ?';
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('DB error on profile:', err);
            return sendError(res, 500, 'Database error');
        }
        if (results.length === 0) return sendError(res, 404, 'User not found');
        res.json({ user: results[0] });
    });
});


const PORT = 3001;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

