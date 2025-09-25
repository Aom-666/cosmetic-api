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

// --- Middleware สำหรับตรวจสอบ Token (ด่านตรวจ) ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // รูปแบบ "Bearer TOKEN"

    if (!token) {
        return res.status(403).json({ message: "A token is required for authentication" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // แนบข้อมูล user ที่ถอดรหัสได้ ไปกับ request
    } catch (err) {
        return res.status(401).json({ message: "Invalid Token" });
    }
    return next();
};


// === API Endpoint สำหรับ Login (แก้ไขลำดับการทำงาน) ===
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน' });
        }

        const [rows] = await db.query(
            `SELECT u.Users_ID, u.username, u.password, r.Type_Name as role
             FROM Users u
             JOIN role r ON u.Role_ID = r.Role_ID
             WHERE u.username = ?`,
            [username]
        );
        
        if (rows.length === 0) {
            // ✨ 1. บันทึก Log ก่อน แล้วค่อย return ✨
            const description = `พยายามเข้าสู่ระบบด้วยชื่อผู้ใช้ที่ไม่มีในระบบ: '${username}'`;
            await db.query(
                `INSERT INTO Activity_Log (operator_id, action_type, description, status) 
                 VALUES (?, ?, ?, ?)`,
                [null, 'LOGIN_FAIL', description, 'ไม่สำเร็จ']
            );
            return res.status(404).json({ message: 'ไม่พบผู้ใช้นี้ในระบบ' });
        }

        const user = rows[0];
        const isPasswordMatch = await bcrypt.compare(password, user.password);

        if (!isPasswordMatch) {
            // ✨ 2. บันทึก Log ก่อน แล้วค่อย return ✨
            const description = `พยายามเข้าสู่ระบบด้วยชื่อผู้ใช้ '${username}' แต่รหัสผ่านไม่ถูกต้อง`;
            await db.query(
                `INSERT INTO Activity_Log (operator_id, action_type, description, status) VALUES (?, ?, ?, ?)`,
                [user.Users_ID, 'LOGIN_FAIL', description, 'ไม่สำเร็จ']
            );
            return res.status(401).json({ message: 'รหัสผ่านไม่ถูกต้อง' });
        }

        if (user.role !== 'admin') {
            // (Optional) บันทึก Log กรณีพยายาม Login แต่ไม่มีสิทธิ์
            const description = `ผู้ใช้ '${username}' พยายามเข้าสู่ระบบ แต่ไม่มีสิทธิ์ (Role: ${user.role})`;
            await db.query(
                `INSERT INTO Activity_Log (operator_id, action_type, description, status) VALUES (?, ?, ?, ?)`,
                [user.Users_ID, 'LOGIN_NO_AUTH', description, 'ไม่สำเร็จ']
            );
            return res.status(403).json({ message: 'คุณไม่มีสิทธิ์เข้าถึงส่วนนี้' });
        }

        const payload = {
            userId: user.Users_ID,
            username: user.username,
            role: user.role
        };

        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

        const description = `Admin '${user.username}' เข้าสู่ระบบ`;
        await db.query(
            `INSERT INTO Activity_Log (operator_id, action_type, description, status) VALUES (?, ?, ?, ?)`,
            [user.Users_ID, 'LOGIN_SUCCESS', description, 'สำเร็จ']
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

// 1. API สำหรับดึงข้อมูลสถิติภาพรวม (Stat Cards)
app.get('/api/stats/summary', async (req, res) => {
    try {
        // ใช้ Promise.all เพื่อให้ query ทำงานพร้อมกันทั้งหมด
        const [
            [[{ count: usersCount }]],
            [[{ count: cosmeticsCount }]],
            [[{ count: looksCount }]],
            [[{ count: feedbackCount }]]
        ] = await Promise.all([
            db.query("SELECT COUNT(*) as count FROM Users"),
            db.query("SELECT COUNT(*) as count FROM Cosmetics"),
            db.query("SELECT COUNT(*) as count FROM MakeupLook"),
            db.query("SELECT COUNT(*) as count FROM Feedback")
        ]);

        // ส่งข้อมูลทั้งหมดกลับไปใน JSON เดียว
        res.status(200).json({
            users: usersCount,
            cosmetics: cosmeticsCount,
            looks: looksCount,
            feedbacks: feedbackCount,
        });
    } catch (error) {
        console.error("Error fetching stats summary:", error);
        res.status(500).json({ message: "Server error while fetching stats summary." });
    }
});

// === API สำหรับกราฟ "สัดส่วนโทนสีผิว" ===
app.get('/api/skintone-summary', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT 
                SkinTone, 
                COUNT(*) as count 
            FROM 
                SkinToneAnalysis  -- <<-- ใช้ตารางที่คุณส่งมา
            GROUP BY 
                SkinTone
            ORDER BY
                count DESC
        `);
        res.status(200).json(rows);
    } catch (error){
        console.error("Error fetching skintone summary:", error);
        res.status(500).json({ message: "Server error while fetching skintone summary." });
    }
});

// === API สำหรับกราฟ "5 อันดับดาราที่ถูกเปรียบเทียบมากที่สุด" ===
app.get('/api/popular-celebrities', async (req, res) => {
    try {
        // ✨ ใช้ชื่อคอลัมน์จากรูปภาพที่คุณส่งมา: ThaiCelebrities_name และ ThaiCelebrities_ID ✨
        const [rows] = await db.query(`
            SELECT 
                tc.ThaiCelebrities_name AS celebrityName,
                COUNT(s.Similarity_ID) AS comparison_count
            FROM 
                Similarity s
            JOIN 
                ThaiCelebrities tc ON s.ThaiCelebrities_ID = tc.ThaiCelebrities_ID
            GROUP BY 
                tc.ThaiCelebrities_name
            ORDER BY 
                comparison_count DESC
            LIMIT 5
        `);
        res.status(200).json(rows);
    } catch (error) {
        console.error("Error fetching popular celebrities:", error);
        res.status(500).json({ message: "Server error while fetching popular celebrities." });
    }
});

// === API Endpoint สำหรับดึงข้อมูล Feedback (เวอร์ชันไม่มี status) ===
app.get('/api/feedback', async (req, res) => {
    try {
        // นำ filterStatus ออกจากตัวแปร เพราะไม่ได้ใช้แล้ว
        const { sortBy, searchTerm, filterRating } = req.query;

        console.log("--- Backend ได้รับคำขอ ---");
        console.log("Filters ที่ได้รับ:", req.query);

        let sql = `
            SELECT 
                f.FeedbackID, f.CommentText, f.Rating, f.Date, u.username as userName
            FROM Feedback f
            JOIN Users u ON f.Users_ID = u.Users_ID
            WHERE 1=1 
        `;
        const params = [];

        if (searchTerm) {
            sql += ` AND (u.username LIKE ? OR f.CommentText LIKE ?)`;
            params.push(`%${searchTerm}%`, `%${searchTerm}%`);
        }

        if (filterRating && filterRating !== 'ทั้งหมด') {
            sql += ` AND f.Rating = ?`;
            params.push(parseInt(filterRating, 10)); 
        }

        switch (sortBy) {
            case 'dateAsc': sql += ' ORDER BY f.Date ASC'; break;
            case 'ratingDesc': sql += ' ORDER BY f.Rating DESC'; break;
            case 'ratingAsc': sql += ' ORDER BY f.Rating ASC'; break;
            default: sql += ' ORDER BY f.Date DESC';
        }

        const [rows] = await db.query(sql, params);
        res.status(200).json(rows);
    } catch (error) {
        console.error('Error fetching feedback:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดใน Server' });
    }
});

// === API Endpoint สำหรับดึงข้อมูล Activity Log (สำหรับหน้า Dashboard) ===
app.get('/api/activity-log', async (req, res) => {
    try {
        const { page = 1, limit = 10, filterByAdmin } = req.query;
        const offset = (page - 1) * limit;

        let sql = `
            SELECT a.log_id, a.timestamp, a.description, a.status, u.username as operator_name
            FROM Activity_Log a
            JOIN Users u ON a.operator_id = u.Users_ID
        `;
        const params = [];

        if (filterByAdmin === 'true') {
            sql += ` WHERE u.Role_ID = ?`; // กรองจาก Role ID ของ Admin (สมมติว่าเป็น 2)
            params.push(2);
        }

        sql += ` ORDER BY a.timestamp DESC LIMIT ? OFFSET ?`;
        params.push(parseInt(limit), parseInt(offset));
        
        let countSql = `SELECT COUNT(*) as total FROM Activity_Log`;
        if (filterByAdmin === 'true') {
            countSql += ` WHERE operator_id IN (SELECT Users_ID FROM Users WHERE Role_ID = 2)`;
        }

        const [logs] = await db.query(sql, params);
        const [[{ total }]] = await db.query(countSql);
        
        res.status(200).json({
            logs: logs,
            totalPages: Math.ceil(total / limit)
        });
    } catch (error) {
        console.error('Error fetching activity log:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดใน Server' });
    }
});

// === API Endpoint สำหรับสร้างรายงานผลการเปรียบเทียบ (ทำ JOIN ที่นี่) ===
app.get('/api/similarity-report', async (req, res) => {
    try {
        // ✨ นี่คือคำสั่ง SQL หัวใจสำคัญ ✨
        // เรา JOIN 3 ตารางเข้าด้วยกัน: similarity, Users, และ ThaiCelebrities
        // เพื่อแปลง ID ทั้งหมดให้เป็นชื่อที่อ่านได้
        const sql = `
            SELECT 
                s.similarity_ID,
                u.username,
                tc.ThaiCelebrities_name AS celebrityName, -- ใช้ AS เพื่อตั้งชื่อ Key ใน JSON ให้นำไปใช้ง่าย
                s.similarityDetail_Percent AS similarityPercent,
                s.similarity_Date AS similarityDate
            FROM 
                similarity s
            JOIN 
                Users u ON s.Users_ID = u.Users_ID
            JOIN 
                ThaiCelebrities tc ON s.ThaiCelebrities_ID = tc.ThaiCelebrities_ID
            ORDER BY 
                s.similarityDetail_Percent DESC;
        `;

        // สั่งให้ฐานข้อมูลทำงานตามคำสั่ง SQL
        const [rows] = await db.query(sql);
        
        // ส่งข้อมูลที่ JOIN แล้ว (มีชื่อเรียบร้อย) กลับไปให้ Frontend ในรูปแบบ JSON
        res.status(200).json(rows);

    } catch (error) {
        // หากเกิดข้อผิดพลาด ให้แสดง log ในฝั่ง server และส่งข้อความ error กลับไป
        console.error('Error fetching similarity report:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลรายงาน' });
    }
});

// === API Endpoints สำหรับจัดการ Makeup Looks ===

// 1. ดึงข้อมูลลุคทั้งหมด (GET)
app.get('/api/looks', async (req, res) => {
    try {
        const [looks] = await db.query("SELECT LookID, lookName, lookCategory, description FROM MakeupLook ORDER BY LookID ASC");
        res.status(200).json(looks);
    } catch (error) {
        console.error("Error fetching makeup looks:", error);
        res.status(500).json({ message: "Server error while fetching looks." });
    }
});

// เพิ่มลุคใหม่ (POST)
app.post('/api/looks', async (req, res) => {
    try {
        const { lookName, lookCategory, description } = req.body;
        // ✨ สมมติว่ามี req.user.userId จาก Middleware
        const adminUserId = 1; // <<-- ในระบบจริง ให้ใช้ ID ของ Admin ที่ login อยู่

        const [result] = await db.query(
            "INSERT INTO MakeupLook (lookName, lookCategory, description) VALUES (?, ?, ?)",
            [lookName, lookCategory, description]
        );
        
        // ✨ บันทึก Log หลังเพิ่มข้อมูลสำเร็จ ✨
        const logDescription = `เพิ่มลุคใหม่: '${lookName}'`;
        await db.query(
            `INSERT INTO Activity_Log (operator_id, action_type, description, status) VALUES (?, ?, ?, ?)`,
            [adminUserId, 'LOOK_CREATE', logDescription, 'เพิ่ม']
        );

        res.status(201).json({ LookID: result.insertId, lookName, lookCategory, description });
    } catch (error) {
        console.error("Error adding new look:", error);
        res.status(500).json({ message: "Server error." });
    }
});

// แก้ไขลุค (PUT)
app.put('/api/looks/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { lookName, lookCategory, description } = req.body;
        const adminUserId = 1; // <<-- ในระบบจริง ให้ใช้ ID ของ Admin ที่ login อยู่

        await db.query(
            "UPDATE MakeupLook SET lookName = ?, lookCategory = ?, description = ? WHERE LookID = ?",
            [lookName, lookCategory, description, id]
        );
        
        // ✨ บันทึก Log หลังแก้ไขข้อมูลสำเร็จ ✨
        const logDescription = `แก้ไขข้อมูลลุค ID #${id}: '${lookName}'`;
        await db.query(
            `INSERT INTO Activity_Log (operator_id, action_type, description, status) VALUES (?, ?, ?, ?)`,
            [adminUserId, 'LOOK_UPDATE', logDescription, 'แก้ไข']
        );

        res.status(200).json({ message: "Look updated successfully." });
    } catch (error) {
        console.error("Error updating look:", error);
        res.status(500).json({ message: "Server error." });
    }
});

// ลบลุค (DELETE)
app.delete('/api/looks/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const adminUserId = 1; // <<-- ในระบบจริง ให้ใช้ ID ของ Admin ที่ login อยู่

        // ✨ ดึงชื่อลุคมาก่อนที่จะลบ เพื่อใช้ในการบันทึก Log ✨
        const [looks] = await db.query("SELECT lookName FROM MakeupLook WHERE LookID = ?", [id]);
        const lookName = looks.length > 0 ? looks[0].lookName : `ID #${id}`;

        await db.query("DELETE FROM MakeupLook WHERE LookID = ?", [id]);

        // ✨ บันทึก Log หลังลบข้อมูลสำเร็จ ✨
        const logDescription = `ลบลุค: '${lookName}'`;
        await db.query(
            `INSERT INTO Activity_Log (operator_id, action_type, description, status) VALUES (?, ?, ?, ?)`,
            [adminUserId, 'LOOK_DELETE', logDescription, 'ลบ']
        );

        res.status(200).json({ message: "Look deleted successfully." });
    } catch (error) {
        console.error("Error deleting look:", error);
        res.status(500).json({ message: "Server error." });
    }
});

// --- รัน Server ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
