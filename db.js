const {createPool} = require("mysql")

 const pool = createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "test-auth",
    connectionLimit: 2 
 })

 pool.query(`select * from user`, (err, res)=>{
    return console.log(res)
 })