const express = require("express");
const bcrypt = require("bcrypt");
const db = require("./db");

const app = express();

app.use(express.json());

app.post("/v1/API/auth/register", async (req, res) => {
    const { fname,lname,email,phone,address,password,dob } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const query = 'INSERT INTO user(`first_name`, `last_name`, `email`, `phone`, `address`, `password`, `dob`) VALUES (?,?,?,?,?,?,?)';
        db.query(query, [fname,lname, email,phone,address,hashedPassword,dob], (err, result) => {
            if (err) throw err;
            res.status(201).send('User registered successfully');
        });
    }  catch (error) {
        res.status(500).send("Error registering user");
    }
});

// login
app.post('/v1/API/auth/login', (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM user WHERE email = ?';
    db.query(query, [email], async (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            const user = results[0];

            const isMatch = await bcrypt.compare(password, user.password);

            if (isMatch) {
                res.status(200).send('Login successful');
            } else {
                res.status(401).send('Invalid credentials');
            }
        } else {
            res.status(404).send('User not found');
        }
    });
});

app.get('/', (req, res) => {
    res.send('server is running on port 3000');
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost3000`);
});

