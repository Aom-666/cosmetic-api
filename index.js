const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db'); // Import connection pool ที่เราสร้างไว้
require('dotenv').config();

const app = express();

// --- Middleware ---
app.use(cors()); // อนุญาตให้ Frontend (React) เรียกใช้ API นี้ได้
app.use(express.json()); // ทำให้ Server อ่านข้อมูลแบบ JSON ที่ส่งมาได้

// === API Endpoint สำหรับ Login (เวอร์ชันตรวจสอบ Role) ===
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน' });
        }

        // ✨ 1. แก้ไข SQL Query ให้ JOIN ตาราง Role เพื่อดึงชื่อ Role มาด้วย
        // (สมมติว่าตาราง Role ของคุณชื่อ Roles และมีคอลัมน์ Role_ID, Type_Name)
        const [rows] = await db.query(
            `SELECT u.Users_ID, u.username, u.password, r.Type_Name as role
             FROM Users u
             JOIN role r ON u.Role_ID = r.Role_ID
             WHERE u.username = ?`,
            [username]
        );
        
        if (rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบผู้ใช้นี้ในระบบ' });
        }

        const user = rows[0];

        const isPasswordMatch = await bcrypt.compare(password, user.password);

        if (!isPasswordMatch) {
            return res.status(401).json({ message: 'รหัสผ่านไม่ถูกต้อง' });
        }

        // ✨ 2. เพิ่มด่านตรวจ Role ตรงนี้!
        // หลังจากเช็ครหัสผ่านผ่านแล้ว ให้เช็ค Role ต่อ
        if (user.role !== 'admin') {
            // ถ้า Role ไม่ใช่ 'admin' ให้ส่งข้อความแจ้งเตือนและไม่อนุญาตให้เข้า
            return res.status(403).json({ message: 'คุณไม่มีสิทธิ์เข้าถึงส่วนนี้' });
        }

        // --- ถ้าผ่านทุกอย่าง (เป็น admin และรหัสถูก) ---
        // 3. สร้าง Token ที่มีข้อมูล Role ติดไปด้วย (สำคัญมาก)
        const payload = {
            userId: user.Users_ID,
            username: user.username,
            role: user.role // ใส่ role เข้าไปใน Token
        };

        const token = jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({
            message: 'เข้าสู่ระบบสำเร็จ',
            token: token
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดใน Server' });
    }
});

// === API Endpoint สำหรับข้อมูลกราฟวงกลม 'สัดส่วนโทนสีผิว' ===
app.get('/api/skintone-summary', async (req, res) => {
    try {
        // 1. ดึงข้อมูลจาก Database โดยนับจำนวนผู้ใช้ในแต่ละโทนสีผิว
        const [rows] = await db.query(
            `SELECT SkinTone, COUNT(*) as count 
             FROM skintoneanalysis 
             GROUP BY SkinTone 
             ORDER BY count DESC`
        );

        // 2. ส่งข้อมูลกลับไปให้ Frontend ในรูปแบบ JSON
        res.status(200).json(rows);

    } catch (error) {
        console.error('Error fetching skintone summary:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดใน Server' });
    }
});


// --- รัน Server ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});