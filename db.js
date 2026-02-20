const mysql = require('mysql2');

// ⚠️ IMPORTANT: Change 'YOUR_PASSWORD' to your actual MySQL password
const pool = mysql.createPool({
  host: '127.0.0.1',
  user: 'root',
  password: 'Harshit12@3',  // 👈 CHANGE THIS!
  database: 'feedb',
  port: 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Error handler
pool.on('error', (err) => {
  console.error('MySQL Pool Error:', err);
  if (err.code === 'PROTOCOL_CONNECTION_LOST') {
    console.error('Database connection lost. Pool will reconnect automatically.');
  }
});

// Test connection
pool.getConnection((err, connection) => {
  if (err) {
    console.error('❌ MySQL connection error:', err);
    console.error('Please check:');
    console.error('1. MySQL is running');
    console.error('2. Database "feedback_ju" exists');
    console.error('3. Username and password are correct');
    return;
  }
  console.log('✅ MySQL Connected Successfully');
  connection.release();
});

module.exports = pool;