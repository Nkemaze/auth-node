let mysql = require('mysql');

let conn = mysql.createConnection({
    host:"localhost",
    user:"root",
    password:"",
    database:"test-auth"
})

conn.connect(function(err){
    if(err) throw err;
    console.log("connected");
})

module.exports = conn;
