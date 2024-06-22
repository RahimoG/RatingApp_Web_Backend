import express from 'express';
import mysql from 'mysql'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import cookieParser from 'cookie-parser';
import { config } from 'dotenv';

// dotenv setup
config({ path: '../.env' });

const app = express();
app.use(express.json());
app.use(cors({
    origin: ["http://localhost:5173", "http://localhost:8081"],
    methods: ["POST", "GET"],
    credentials: true,
}));
app.use(cookieParser());

// connection db
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "rating"
})

const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if(!token){
        return res.json({ Error: "You are not authenticated!"});
    }else{
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if(err) {
                return res.json({ Error: "TOKEN is not correct !"});
            }else{
                req.username = decoded.username;
                next();
            }
        })
    }
}

app.get('/', verifyUser , (req, res) => {
    // change
    const SQL = "SELECT id, first_name, last_name, email, type FROM Users  WHERE email = ?";
    console.log(req.body.email)
    db.query(SQL , req.body.email, (errQuery, data) => { 
        if(errQuery) return res.json({Error: "Error for FETCHING data into database.", err: errQuery})
        if (data.length > 0){
            return res.json({Status: "Success", data: data[0]});
        }
    });
    
})

app.post('/register', (req, res) => {
    // we hash password with bcrypt
    bcrypt.hash(req.body.password.toString(), parseInt(process.env.BCRYPT_SALT), (err, hash) => {
        if(err) return res.json({ Error: "Error for hashing password."});
        // we get data from frontend
        const values = [
            req.body.first_name,
            req.body.last_name,
            req.body.email,
            req.body.type,
            hash,
        ];
        db.query("SELECT * FROM Users  WHERE email = ?", req.body.email, (errQuery, result) => {
            if(errQuery) return res.json({Error: "Error for fetching data from database.", err: errQuery})
            if(result.length > 0){
                return res.json({Error: "email exsist!", errID: '1'}); // errID = 1 means that the email exists so we control the error output on frontend
            }else{
                // change
                const sql = "INSERT INTO Users  (`first_name`, `last_name`, `email`, `type`, `password`) VALUES (?)";
                db.query(sql, [values], (errQuery, result) => { 
                    if(errQuery) return res.json({Error: "Error for inserting data into database.", values: values, err: errQuery})
                    const token = jwt.sign({ email: req.body.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
                    res.cookie('token', token);  
                    // return res.redirect('/'); old 
                    return res.json({Status: "Success"});
                });
            }
        })
    });
});

app.post('/login', (req, res) => {
    // change
    const sql = "SELECT * FROM Users  WHERE email = ?";
    db.query(sql, [req.body.email], (errQuery, data) => { 
        if(errQuery) return res.json({Error: "Error for fetching data from database.", err: errQuery})
        if(data.length > 0) {
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if(err) return res.json({Error: "Password compare error"})
                if(response){
                    const email = data[0].email;
                    const token = jwt.sign({ email: email }, process.env.JWT_SECRET, { expiresIn: '1d' });
                    res.cookie('token', token);  
                    return res.json({Status: "Success"});
                }else{
                    return res.json({Error: "Password is incorrect!", errID: '2'});
                }
            });
        }
        else {
            return res.json({Error: "no email existed!", err: errQuery, errID : '1'})
        }
    }); 
});
// Update Points function 


/* # Task Model:
    Create Task:
    Assign Task:
    Submit Task:
    Evaluate Task:
*/

app.listen(8081, () => {
    console.log("Running ...");
})



