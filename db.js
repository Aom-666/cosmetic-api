const mysql = require('mysql2');
require('dotenv').config(); // โหลดค่าจากไฟล์ .env

// สร้าง Connection Pool เพื่อประสิทธิภาพที่ดีกว่า
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// ส่งออก pool ในรูปแบบ promise เพื่อให้ใช้งานกับ async/await ได้ง่าย
module.exports = pool.promise();