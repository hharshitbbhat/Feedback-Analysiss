// ─── 1. ALL REQUIRES FIRST ───
const express    = require('express');
const path       = require('path');
const bcrypt     = require('bcrypt');
const session    = require('express-session');
const multer     = require('multer');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const csrf       = require('csrf');
require('dotenv').config();

const db = require('./db');

function ensureStudentStatusColumn() {
  db.query(
    `
      SELECT 1
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'students'
        AND COLUMN_NAME = 'status'
      LIMIT 1
    `,
    (err, rows) => {
      if (err) {
        console.error('Student status column check failed:', err);
        return;
      }

      if (rows.length > 0) {
        db.query(
          "ALTER TABLE students MODIFY COLUMN status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'approved'",
          (modifyErr) => {
            if (modifyErr) {
              console.error('Failed to update students.status column:', modifyErr);
            }
          }
        );
        return;
      }

      db.query(
        "ALTER TABLE students ADD COLUMN status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'approved' AFTER password",
        (alterErr) => {
          if (alterErr) {
            console.error('Failed to add students.status column:', alterErr);
            return;
          }
          console.log('Added students.status column with default approved');
        }
      );
    }
  );
}

function runQuery(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

async function ensureCourseUniqueness() {
  try {
    const duplicateGroups = await runQuery(
      `
        SELECT
          course_name,
          programme,
          semester,
          COUNT(*) AS duplicate_count,
          MAX(course_id) AS keep_id,
          GROUP_CONCAT(course_id ORDER BY course_id) AS all_ids
        FROM courses
        GROUP BY course_name, programme, semester
        HAVING COUNT(*) > 1
      `
    );

    for (const group of duplicateGroups) {
      const allIds = String(group.all_ids || '')
        .split(',')
        .map((id) => Number.parseInt(id, 10))
        .filter(Number.isInteger);
      const keepId = Number.parseInt(group.keep_id, 10);
      const duplicateIds = allIds.filter((id) => id !== keepId);

      if (!keepId || !duplicateIds.length) continue;

      await runQuery('START TRANSACTION');

      try {
        const feedbackRows = await runQuery(
          `
            SELECT feedback_id, student_id, course_id
            FROM feedback
            WHERE course_id IN (${allIds.map(() => '?').join(',')})
            ORDER BY student_id ASC, feedback_id DESC
          `,
          allIds
        );

        const feedbackToDelete = [];
        const feedbackToMove = [];
        const seenStudents = new Set();

        feedbackRows.forEach((row) => {
          const studentKey = Number(row.student_id);
          if (seenStudents.has(studentKey)) {
            feedbackToDelete.push(Number(row.feedback_id));
            return;
          }

          seenStudents.add(studentKey);
          if (Number(row.course_id) !== keepId) {
            feedbackToMove.push(Number(row.feedback_id));
          }
        });

        if (feedbackToDelete.length) {
          await runQuery(
            `DELETE FROM feedback WHERE feedback_id IN (${feedbackToDelete.map(() => '?').join(',')})`,
            feedbackToDelete
          );
        }

        if (feedbackToMove.length) {
          await runQuery(
            `
              UPDATE feedback
              SET course_id = ?, faculty_id = (SELECT faculty_id FROM courses WHERE course_id = ?)
              WHERE feedback_id IN (${feedbackToMove.map(() => '?').join(',')})
            `,
            [keepId, keepId, ...feedbackToMove]
          );
        }

        await runQuery(
          `DELETE FROM courses WHERE course_id IN (${duplicateIds.map(() => '?').join(',')})`,
          duplicateIds
        );

        await runQuery('COMMIT');
        console.log(
          `Merged duplicate course entries for "${group.course_name}" (${group.programme}, semester ${group.semester}); kept course ${keepId}`
        );
      } catch (groupErr) {
        await runQuery('ROLLBACK');
        console.error(
          `Failed merging duplicate course entries for "${group.course_name}" (${group.programme}, semester ${group.semester}):`,
          groupErr
        );
      }
    }

    const existingIndex = await runQuery(
      `
        SELECT 1
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'courses'
          AND INDEX_NAME = 'uniq_courses_name_programme_semester'
        LIMIT 1
      `
    );

    if (existingIndex.length === 0) {
      await runQuery(
        'ALTER TABLE courses ADD UNIQUE KEY uniq_courses_name_programme_semester (course_name, programme, semester)'
      );
      console.log('Added unique index on courses(course_name, programme, semester)');
    }
  } catch (err) {
    console.error('Course uniqueness check failed:', err);
  }
}

// ─── 2. CREATE APP ───
const app = express();
ensureStudentStatusColumn();
ensureCourseUniqueness();

// ─── 3. CONSTANTS ───
const upload     = multer();
const tokens     = new csrf();
const CSRF_SECRET = process.env.CSRF_SECRET || 'your-csrf-secret';

if (!process.env.SESSION_SECRET) {
  console.warn('⚠️  WARNING: SESSION_SECRET not set in .env');
}

// ─── 4. RATE LIMITERS ───
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: '❌ Too many registration attempts. Try again in 15 minutes.'
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: '❌ Too many login attempts. Try again in 15 minutes.' }
});

// ─── 5. GLOBAL MIDDLEWARE ───
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com"],
      styleSrc:  ["'self'", "'unsafe-inline'"],
      imgSrc:    ["'self'", "data:"],
      connectSrc:["'self'"],
      fontSrc:   ["'self'"],
    }
  }
}));
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret123',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production'
  }
}));

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

/* ===================== AUTH HELPERS ===================== */
function denyForbidden(req, res) {
  if (
    req.path.startsWith('/api/') ||
    req.xhr ||
    (req.headers.accept && req.headers.accept.includes('application/json')) ||
    req.method !== 'GET'
  ) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  return res.status(403).send('Forbidden');
}

function isStudentAuth(req, res, next) {
  if (!req.session || !req.session.studentId) {
    return denyForbidden(req, res);
  }
  next();
}

function isAdminAuth(req, res, next) {
  if (!req.session || !req.session.isAdmin) {
    return denyForbidden(req, res);
  }
  next();
}

function verifyCsrfToken(req, res, next) {
  const sessionToken = req.session?.csrfToken;
  const headerToken = req.get('x-csrf-token');
  const bodyToken = req.body?.csrfToken;
  const token = headerToken || bodyToken;

  if (!sessionToken || !token || token !== sessionToken || !tokens.verify(CSRF_SECRET, token)) {
    if (
      req.path.startsWith('/api/') ||
      req.xhr ||
      (req.headers.accept && req.headers.accept.includes('application/json')) ||
      req.method !== 'GET'
    ) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    return res.status(403).send('❌ Invalid request');
  }
  next();
}

/* ===================== PAGES ===================== */
// Landing page - accessible to everyone
app.get('/', (_req, res) =>
  res.sendFile(path.join(__dirname, 'public/landing.html'))
);

app.get('/student-login', (_req, res) =>
  res.sendFile(path.join(__dirname, 'public/student-login.html'))
);

app.get('/admin-login', (_req, res) =>
  res.sendFile(path.join(__dirname, 'public/admin-login.html'))
);

app.get('/register', (req, res) => {
  const token = tokens.create(CSRF_SECRET);
  req.session.csrfToken = token;
  res.sendFile(path.join(__dirname, 'public/register.html'));
});

// CSRF token endpoint
app.get('/api/csrf-token', (req, res) => {
  if (!req.session.csrfToken) {
    const token = tokens.create(CSRF_SECRET);
    req.session.csrfToken = token;
  }
  res.json({ token: req.session.csrfToken });
});

// Protected student routes
app.get('/feedback', isStudentAuth, (_req, res) =>
  res.sendFile(path.join(__dirname, 'public/index.html'))
);

app.get('/thank-you', isStudentAuth, (_req, res) =>
  res.sendFile(path.join(__dirname, 'public/thankyou.html'))
);

// Protected admin route
app.get('/admin', isAdminAuth, (_req, res) =>
  res.sendFile(path.join(__dirname, 'public/admin.html'))
);

app.get('/logout', (req, res) => {
  const type = req.query.type;
  if (!req.session) {
    return res.redirect(type === 'admin' ? '/admin-login' : '/student-login');
  }

  if (type === 'admin') {
    delete req.session.isAdmin;
    delete req.session.adminId;
    if (!req.session.studentId) {
      delete req.session.role;
    }
  } else {
    delete req.session.studentId;
    if (!req.session.isAdmin) {
      delete req.session.role;
    }
  }

  const hasAuth = req.session.isAdmin || req.session.studentId;
  if (!hasAuth) {
    return req.session.destroy((err) => {
      if (err) console.error('Logout error:', err);
      res.clearCookie('connect.sid');
      res.redirect(type === 'admin' ? '/admin-login' : '/student-login');
    });
  }

  req.session.save((err) => {
    if (err) console.error('Logout save error:', err);
    res.redirect(type === 'admin' ? '/admin-login' : '/student-login');
  });
});

/* ===================== ADMIN LOGIN ===================== */
app.post('/admin/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  db.query(
    'SELECT * FROM admins WHERE username = ?',
    [username],
    async (err, rows) => {
      if (err) {
        console.error('Admin login DB error:', err);
        return res.status(500).json({ error: 'Server error' });
      }

      if (rows.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const admin = rows[0];

      const match = await bcrypt.compare(password, admin.password);
      if (!match) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Regenerate session ID before setting values (prevents session fixation)
      req.session.regenerate((err) => {
        if (err) {
          console.error('Admin session regenerate error:', err);
          return res.status(500).json({ error: 'Session error' });
        }

        req.session.isAdmin = true;
        req.session.adminId = admin.id;
        req.session.role = 'admin';

        req.session.save((err) => {
          if (err) {
            console.error('Admin session save error:', err);
            return res.status(500).json({ error: 'Session error' });
          }
          res.json({ success: true, redirect: '/admin' });
        });
      });
    }
  );
});

/* ===================== STUDENT LOGIN ===================== */
app.post('/student/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const existingAdminId = req.session?.isAdmin ? req.session.adminId : null;
  const existingCsrfToken = req.session?.csrfToken || null;

  db.query(
    'SELECT * FROM students WHERE username = ?',
    [username.toLowerCase()],
    async (err, rows) => {
      if (err) {
        console.error('Student login DB error:', err);
        return res.status(500).json({ error: 'Server error, please try again' });
      }

      if (rows.length === 0) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      if (rows[0].status && rows[0].status !== 'approved') {
        const error = rows[0].status === 'rejected'
          ? 'Your account has been rejected by admin'
          : 'Your account is pending admin approval';
        return res.status(403).json({ error });
      }

      const match = await bcrypt.compare(password, rows[0].password);
      if (!match) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      // Regenerate session ID before setting values (prevents session fixation)
      req.session.regenerate((err) => {
        if (err) {
          console.error('Student session regenerate error:', err);
          return res.status(500).json({ error: 'Session error' });
        }

        if (existingAdminId) {
          req.session.isAdmin = true;
          req.session.adminId = existingAdminId;
        }
        req.session.studentId = rows[0].id;
        req.session.role = 'student';
        if (existingCsrfToken) {
          req.session.csrfToken = existingCsrfToken;
        }

        req.session.save((err) => {
          if (err) {
            console.error('Student session save error:', err);
            return res.status(500).json({ error: 'Session error' });
          }
          res.json({ success: true, redirect: '/feedback' });
        });
      });
    }
  );
});

/* ===================== REGISTRATION ===================== */
const REGISTRATION_CODE = 'JU.FEEDBACK';

app.post('/register', registerLimiter, upload.none(), [
  body('code').trim().notEmpty().isLength({ max: 20 }),

  body('name').trim().notEmpty().isLength({ max: 100 }),
  body('password').isLength({ min: 6 }),
  body('sem').isInt({ min: 1, max: 8 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return res.status(400).send('❌ Invalid input data');

  const { csrfToken } = req.body;
  if (!tokens.verify(CSRF_SECRET, csrfToken))
    return res.status(403).send('❌ Invalid request');

  const { code, name, dept, sem, password, registerationCode } = req.body;

  if (registerationCode !== REGISTRATION_CODE)
    return res.status(400).send('❌ Invalid registration code');

  if (!code || !name || !dept || !sem || !password)
    return res.status(400).send('❌ All fields are required');

  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
  if (!passwordRegex.test(password))
    return res.status(400).send('❌ Password must be 8+ characters with uppercase, lowercase and a number');

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query(
      `INSERT INTO students (student_code, student_name, department, semester, username, password, status)
       VALUES (?,?,?,?,?,?,?)`,
      [code, name, dept, sem, code.toLowerCase(), hashedPassword, 'pending'],
      (err) => {
        if (err) {
          console.error('Registration DB error:', err);
          return res.status(500).send('❌ Registration failed. Student code may already exist.');
        }
        res.send('Registration successful. Wait for admin approval.');
      }
    );
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).send('❌ Server error during registration');
  }
});

/* ===================== CURRENT STUDENT ===================== */
app.get('/api/current-student', isStudentAuth, (req, res) => {
  db.query(
    `SELECT student_name, student_code, department, semester
     FROM students WHERE id = ?`,
    [req.session.studentId],
    (err, rows) => {
      if (err || rows.length === 0)
        return res.status(500).json({ error: 'Student not found' });
      res.json(rows[0]);
    }
  );
});

/* ===================== API ENDPOINTS ===================== */
app.get('/api/courses', isAdminAuth, (req, res) => {
  db.query(
    `SELECT c.course_id as id, c.course_name,
            c.programme, c.semester, c.faculty_id
     FROM courses c ORDER BY c.course_name`,
    (err, rows) => {
      if (err) {
        console.error('Get courses error:', err);
        return res.status(500).json({ error: 'Failed to fetch courses' });
      }
      res.json(rows);
    }
  );
});

app.get('/api/faculties', isAdminAuth, (req, res) => {
  db.query(
    `SELECT faculty_id as id, name as faculty_name, 
            designation, department
     FROM faculties ORDER BY name`,
    (err, rows) => {
      if (err) {
        console.error('Get faculties error:', err);
        return res.status(500).json({ error: 'Failed to fetch faculties' });
      }
      res.json(rows);
    }
  );
});

app.get('/api/students', isAdminAuth, (req, res) => {
  db.query('SELECT * FROM students ORDER BY student_name', (err, results) => {
    if (err) {
      console.error('Get students error:', err);
      return res.status(500).json({ error: 'Failed to fetch students' });
    }
    res.json(results);
  });
});

app.get('/api/students/pending', isAdminAuth, (req, res) => {
  db.query(
    `
      SELECT id, student_name AS name, username
      FROM students
      WHERE status = 'pending'
      ORDER BY student_name
    `,
    (err, results) => {
      if (err) {
        console.error('Get pending students error:', err);
        return res.status(500).json({ error: 'Failed to fetch pending students' });
      }
      res.json(results);
    }
  );
});

app.put('/api/students/:id/approve', isAdminAuth, verifyCsrfToken, (req, res) => {
  db.query(
    "UPDATE students SET status = 'approved' WHERE id = ?",
    [req.params.id],
    (err, result) => {
      if (err) {
        console.error('Approve student error:', err);
        return res.status(500).json({ error: 'Failed to approve student' });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Student not found' });
      }
      res.json({ success: true });
    }
  );
});

app.put('/api/students/:id/reject', isAdminAuth, verifyCsrfToken, (req, res) => {
  db.query(
    "UPDATE students SET status = 'rejected' WHERE id = ?",
    [req.params.id],
    (err, result) => {
      if (err) {
        console.error('Reject student error:', err);
        return res.status(500).json({ error: 'Failed to reject student' });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Student not found' });
      }
      res.json({ success: true });
    }
  );
});

/* ===================== COURSES BY SEMESTER ===================== */
app.get('/courses/:semester', isStudentAuth, (req, res) => {
  db.query(
    `SELECT c.course_id, c.course_name,
            f.faculty_id, f.name AS faculty_name
     FROM courses c
     JOIN faculties f ON c.faculty_id = f.faculty_id
     WHERE c.semester = ?`,
    [req.params.semester],
    (err, rows) => {
      if (err) return res.status(500).json([]);
      res.json(rows);
    }
  );
});

/* ===================== QUESTIONS API WITH AUTO-REORDERING ===================== */

// Get all questions (for admin)
app.get('/api/questions', isAdminAuth, (req, res) => {
  db.query(
    `SELECT id, question_text, question_type, display_order, is_required, is_active, created_at
     FROM feedback_questions 
     ORDER BY display_order ASC`,
    (err, rows) => {
      if (err) {
        console.error('Get questions error:', err);
        return res.status(500).json({ error: 'Failed to fetch questions' });
      }
      res.json(rows);
    }
  );
});

// Get active questions (for students - feedback form)
app.get('/api/questions/active', isStudentAuth, (req, res) => {
  db.query(
    `SELECT id, question_text, question_type, display_order, is_required
     FROM feedback_questions 
     WHERE is_active = TRUE
     ORDER BY display_order ASC`,
    (err, rows) => {
      if (err) {
        console.error('Get active questions error:', err);
        return res.status(500).json({ error: 'Failed to fetch questions' });
      }
      res.json(rows);
    }
  );
});

// Add new question with automatic reordering
app.post('/api/questions', isAdminAuth, verifyCsrfToken, (req, res) => {
  const { question_text, question_type, display_order, is_required } = req.body;
  
  if (!question_text || !question_type || !display_order) {
    return res.status(400).json({ error: 'Question text, type, and order are required' });
  }
  
  const targetOrder = parseInt(display_order);
  
  db.query('START TRANSACTION', (err) => {
    if (err) {
      console.error('Transaction start error:', err);
      return res.status(500).json({ error: 'Failed to start transaction' });
    }
    
    db.query(
      'UPDATE feedback_questions SET display_order = display_order + 1 WHERE display_order >= ?',
      [targetOrder],
      (err) => {
        if (err) {
          console.error('Shift questions error:', err);
          db.query('ROLLBACK');
          return res.status(500).json({ error: 'Failed to reorder questions' });
        }
        
        db.query(
          'INSERT INTO feedback_questions (question_text, question_type, display_order, is_required, is_active) VALUES (?, ?, ?, ?, 1)',
          [question_text, question_type, targetOrder, is_required !== undefined ? is_required : 1],
          (err, result) => {
            if (err) {
              console.error('Add question error:', err);
              db.query('ROLLBACK');
              return res.status(500).json({ error: 'Failed to add question' });
            }
            
            db.query('COMMIT', (err) => {
              if (err) {
                console.error('Commit error:', err);
                db.query('ROLLBACK');
                return res.status(500).json({ error: 'Failed to commit changes' });
              }
              
              console.log(`✅ Question added at position ${targetOrder}, existing questions shifted down`);
              res.json({ 
                success: true, 
                id: result.insertId,
                message: `Question added at position ${targetOrder}. Existing questions have been shifted down.`
              });
            });
          }
        );
      }
    );
  });
});

// Update question with position change handling
app.put('/api/questions/:id', isAdminAuth, verifyCsrfToken, (req, res) => {
  const { question_text, question_type, display_order, is_required, is_active, old_order } = req.body;
  
  if (!question_text || !question_type || display_order === undefined) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  const newOrder = parseInt(display_order);
  const questionId = parseInt(req.params.id);
  
  db.query('START TRANSACTION', (err) => {
    if (err) {
      console.error('Transaction start error:', err);
      return res.status(500).json({ error: 'Failed to start transaction' });
    }
    
    if (old_order !== undefined && old_order !== newOrder) {
      const oldPos = parseInt(old_order);
      
      if (newOrder > oldPos) {
        db.query(
          'UPDATE feedback_questions SET display_order = display_order - 1 WHERE display_order > ? AND display_order <= ? AND id != ?',
          [oldPos, newOrder, questionId],
          (err) => {
            if (err) {
              console.error('Reorder down error:', err);
              db.query('ROLLBACK');
              return res.status(500).json({ error: 'Failed to reorder questions' });
            }
            updateQuestion();
          }
        );
      } else if (newOrder < oldPos) {
        db.query(
          'UPDATE feedback_questions SET display_order = display_order + 1 WHERE display_order >= ? AND display_order < ? AND id != ?',
          [newOrder, oldPos, questionId],
          (err) => {
            if (err) {
              console.error('Reorder up error:', err);
              db.query('ROLLBACK');
              return res.status(500).json({ error: 'Failed to reorder questions' });
            }
            updateQuestion();
          }
        );
      }
    } else {
      updateQuestion();
    }
    
    function updateQuestion() {
      db.query(
        'UPDATE feedback_questions SET question_text = ?, question_type = ?, display_order = ?, is_required = ?, is_active = ? WHERE id = ?',
        [question_text, question_type, newOrder, is_required, is_active, questionId],
        (err, result) => {
          if (err) {
            console.error('Update question error:', err);
            db.query('ROLLBACK');
            return res.status(500).json({ error: 'Failed to update question' });
          }
          if (result.affectedRows === 0) {
            db.query('ROLLBACK');
            return res.status(404).json({ error: 'Question not found' });
          }
          
          db.query('COMMIT', (err) => {
            if (err) {
              console.error('Commit error:', err);
              db.query('ROLLBACK');
              return res.status(500).json({ error: 'Failed to commit changes' });
            }
            console.log(`✅ Question ${questionId} updated successfully`);
            res.json({ success: true, message: 'Question updated successfully' });
          });
        }
      );
    }
  });
});

// Delete question with automatic reordering
app.delete('/api/questions/:id', isAdminAuth, verifyCsrfToken, (req, res) => {
  db.query('SELECT display_order FROM feedback_questions WHERE id = ?', [req.params.id], (err, rows) => {
    if (err) {
      console.error('Delete question error:', err);
      return res.status(500).json({ error: 'Failed to delete question' });
    }
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Question not found' });
    }
    
    const deletedOrder = rows[0].display_order;
    
    db.query('START TRANSACTION', (err) => {
      if (err) {
        console.error('Transaction start error:', err);
        return res.status(500).json({ error: 'Failed to start transaction' });
      }
      
      db.query('DELETE FROM feedback_questions WHERE id = ?', [req.params.id], (err) => {
        if (err) {
          console.error('Delete question error:', err);
          db.query('ROLLBACK');
          return res.status(500).json({ error: 'Failed to delete question' });
        }
        
        db.query(
          'UPDATE feedback_questions SET display_order = display_order - 1 WHERE display_order > ?',
          [deletedOrder],
          (err) => {
            if (err) {
              console.error('Shift after delete error:', err);
              db.query('ROLLBACK');
              return res.status(500).json({ error: 'Failed to reorder questions after deletion' });
            }
            
            db.query('COMMIT', (err) => {
              if (err) {
                console.error('Commit error:', err);
                db.query('ROLLBACK');
                return res.status(500).json({ error: 'Failed to commit changes' });
              }
              
              console.log(`✅ Question at position ${deletedOrder} deleted, remaining questions shifted up`);
              res.json({ success: true, message: 'Question deleted and remaining questions reordered' });
            });
          }
        );
      });
    });
  });
});

// Reorder questions (drag and drop)
app.post('/api/questions/reorder', isAdminAuth, verifyCsrfToken, (req, res) => {
  const { questions } = req.body;
  
  if (!questions || !Array.isArray(questions) || questions.length === 0) {
    return res.status(400).json({ error: 'Questions array is required' });
  }
  
  for (const q of questions) {
    if (!q.id || q.display_order === undefined) {
      return res.status(400).json({ error: 'Each question must have id and display_order' });
    }
  }
  
  const ids = questions.map(q => q.id).join(',');
  
  db.query('START TRANSACTION', (err) => {
    if (err) {
      console.error('Transaction start error:', err);
      return res.status(500).json({ error: 'Failed to start transaction' });
    }
    
    const offsetSql = `UPDATE feedback_questions SET display_order = display_order + 10000 WHERE id IN (${ids})`;
    
    db.query(offsetSql, (err) => {
      if (err) {
        console.error('Reorder questions offset error:', err);
        db.query('ROLLBACK');
        return res.status(500).json({ error: 'Failed to reorder questions' });
      }
      
      const whenClauses = questions.map(q => `WHEN ${q.id} THEN ${q.display_order}`).join(' ');
      
      const finalSql = `
        UPDATE feedback_questions 
        SET display_order = CASE id 
          ${whenClauses}
        END
        WHERE id IN (${ids})
      `;
      
      db.query(finalSql, (err, result) => {
        if (err) {
          console.error('Reorder questions final error:', err);
          db.query('ROLLBACK');
          return res.status(500).json({ error: 'Failed to reorder questions' });
        }
        
        db.query('COMMIT', (err) => {
          if (err) {
            console.error('Commit error:', err);
            db.query('ROLLBACK');
            return res.status(500).json({ error: 'Failed to commit changes' });
          }
          
          console.log('✅ Questions reordered via drag and drop');
          res.json({ success: true, message: 'Questions reordered successfully' });
        });
      });
    });
  });
});


/* ===================== ADMIN: VIEW ALL FEEDBACK ===================== */
app.get('/admin/feedback', isAdminAuth, (_req, res) => {
  db.query(
    `SELECT
      f.feedback_id AS id,
      f.created_at,
      f.q1_regularity,
      f.q2_syllabus,
      f.q3_conceptual,
      f.q4_practical,
      f.q5_communication,
      f.q6_teaching,
      f.q7_contribution,
      f.comment,
      s.student_name,
      s.student_code,
      s.department,
      s.semester,
      c.course_name,
      c.programme,
      fac.name AS faculty_name
    FROM feedback f
    JOIN students s ON f.student_id = s.id
    JOIN courses c ON f.course_id = c.course_id
    JOIN faculties fac ON f.faculty_id = fac.faculty_id
    ORDER BY f.created_at DESC`,
    (err, rows) => {
      if (err) {
        console.error('Admin feedback error:', err);
        return res.status(500).json([]);
      }
      res.json(rows);
    }
  );
});

/* ===================== ADMIN: ADD OPERATIONS ===================== */
app.post('/add-faculty', isAdminAuth, upload.none(), verifyCsrfToken, (req, res) => {
  const name = String(req.body?.name || '').trim();
  const designation = String(req.body?.designation || '').trim();
  const dept = String(req.body?.dept || req.body?.department || '').trim();

  if (!name || name.length > 100) {
    return res.status(400).json({ error: 'Invalid faculty name' });
  }
  if (!designation || designation.length > 100) {
    return res.status(400).json({ error: 'Invalid designation' });
  }
  if (!dept || dept.length > 100) {
    return res.status(400).json({ error: 'Invalid department' });
  }
  
  db.query(
    'INSERT INTO faculties (name, designation, department) VALUES (?, ?, ?)',
    [name, designation, dept],
    (err, result) => {
      if (err) {
        console.error('Add faculty error:', err);
        return res.status(500).json({ error: 'Failed to add faculty member' });
      }
      res.json({ success: true, id: result.insertId });
    }
  );
});

app.post('/add-course', isAdminAuth, upload.none(), verifyCsrfToken, (req, res) => {
  const course = String(req.body?.course || '').trim();
  const programme = String(req.body?.programme || '').trim();
  const semester = Number.parseInt(req.body?.semester, 10);
  const faculty = Number.parseInt(req.body?.faculty, 10);

  if (!course || course.length > 120) {
    return res.status(400).json({ error: 'Invalid course name' });
  }
  if (!programme || programme.length > 50) {
    return res.status(400).json({ error: 'Invalid programme' });
  }
  if (!Number.isInteger(semester) || semester < 1 || semester > 8) {
    return res.status(400).json({ error: 'Invalid semester' });
  }
  if (!Number.isInteger(faculty) || faculty <= 0) {
    return res.status(400).json({ error: 'Invalid faculty ID' });
  }

  db.query(
    `
      SELECT course_id
      FROM courses
      WHERE course_name = ? AND programme = ? AND semester = ?
      ORDER BY course_id DESC
      LIMIT 1
    `,
    [course, programme, semester],
    (findErr, rows) => {
      if (findErr) {
        console.error('Find existing course error:', findErr);
        return res.status(500).json({ error: 'Failed to add course' });
      }

      if (rows.length > 0) {
        const existingCourseId = Number(rows[0].course_id);
        db.query(
          'UPDATE courses SET faculty_id = ? WHERE course_id = ?',
          [faculty, existingCourseId],
          (updateErr) => {
            if (updateErr) {
              console.error('Replace existing course error:', updateErr);
              return res.status(500).json({ error: 'Failed to update existing course' });
            }
            res.json({ success: true, id: existingCourseId, replaced: true });
          }
        );
        return;
      }

      db.query(
        'INSERT INTO courses (course_name, programme, semester, faculty_id) VALUES (?, ?, ?, ?)',
        [course, programme, semester, faculty],
        (err, result) => {
          if (err) {
            console.error('Add course error:', err);
            return res.status(500).json({ error: 'Failed to add course' });
          }
          res.json({ success: true, id: result.insertId });
        }
      );
    }
  );
});

app.post('/add-student', isAdminAuth, upload.none(), verifyCsrfToken, async (req, res) => {
  const code = String(req.body?.code || '').trim();
  const name = String(req.body?.name || '').trim();
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  const dept = String(req.body?.dept || '').trim();
  const sem = Number.parseInt(req.body?.sem, 10);

  if (!code || code.length > 20) {
    return res.status(400).json({ error: 'Invalid student code' });
  }
  if (!name || name.length > 100) {
    return res.status(400).json({ error: 'Invalid student name' });
  }
  if (!username || username.length > 50) {
    return res.status(400).json({ error: 'Invalid username' });
  }
  if (!dept || dept.length > 100) {
    return res.status(400).json({ error: 'Invalid department' });
  }
  if (!Number.isInteger(sem) || sem < 1 || sem > 8) {
    return res.status(400).json({ error: 'Invalid semester' });
  }
  if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/.test(password)) {
    return res.status(400).json({ error: 'Invalid password format' });
  }
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query(
      `INSERT INTO students (student_code, student_name, username, password, department, semester)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [code, name, username.toLowerCase(), hashedPassword, dept, sem],
      (err, result) => {
        if (err) {
          console.error('Add student error:', err);
          return res.status(500).json({ error: 'Failed to add student' });
        }
        res.json({ success: true, id: result.insertId });
      }
    );
  } catch (err) {
    console.error('Password hashing error:', err);
    res.status(500).json({ error: 'Failed to process request' });
  }
});

/* ===================== ADMIN: DELETE OPERATIONS ===================== */

// FIX #1: Faculty delete now cascades — removes feedback and courses first
app.delete('/api/faculty/:id', isAdminAuth, verifyCsrfToken, (req, res) => {
  const id = req.params.id;

  db.query('START TRANSACTION', (err) => {
    if (err) {
      console.error('Transaction start error:', err);
      return res.status(500).json({ error: 'Failed to start transaction' });
    }

    // Step 1: Delete all feedback referencing courses of this faculty
    db.query('DELETE FROM feedback WHERE course_id IN (SELECT course_id FROM courses WHERE faculty_id = ?)', [id], (err) => {
      if (err) {
        console.error('Delete feedback for faculty error:', err);
        db.query('ROLLBACK');
        return res.status(500).json({ error: 'Failed to remove related feedback' });
      }

      // Step 2: Delete all courses referencing this faculty
      db.query('DELETE FROM courses WHERE faculty_id = ?', [id], (err) => {
        if (err) {
          console.error('Delete courses for faculty error:', err);
          db.query('ROLLBACK');
          return res.status(500).json({ error: 'Failed to remove related courses' });
        }

        // Step 3: Delete the faculty
        db.query('DELETE FROM faculties WHERE faculty_id = ?', [id], (err, result) => {
          if (err) {
            console.error('Delete faculty error:', err);
            db.query('ROLLBACK');
            return res.status(500).json({ error: 'Failed to delete faculty' });
          }
          if (result.affectedRows === 0) {
            db.query('ROLLBACK');
            return res.status(404).json({ error: 'Faculty not found' });
          }

          db.query('COMMIT', (err) => {
            if (err) {
              console.error('Commit error:', err);
              db.query('ROLLBACK');
              return res.status(500).json({ error: 'Failed to commit changes' });
            }
            console.log(`✅ Faculty ${id} and all related data deleted`);
            res.json({ success: true, message: 'Faculty and all related data deleted successfully' });
          });
        });
      });
    });
  });
});

// FIX #1: Course delete now cascades — removes related feedback first
app.delete('/api/course/:id', isAdminAuth, verifyCsrfToken, (req, res) => {
  const id = req.params.id;

  db.query('START TRANSACTION', (err) => {
    if (err) {
      console.error('Transaction start error:', err);
      return res.status(500).json({ error: 'Failed to start transaction' });
    }

    // Step 1: Delete all feedback referencing this course
    db.query('DELETE FROM feedback WHERE course_id = ?', [id], (err) => {
      if (err) {
        console.error('Delete feedback for course error:', err);
        db.query('ROLLBACK');
        return res.status(500).json({ error: 'Failed to remove related feedback' });
      }

      // Step 2: Delete the course
      db.query('DELETE FROM courses WHERE course_id = ?', [id], (err, result) => {
        if (err) {
          console.error('Delete course error:', err);
          db.query('ROLLBACK');
          return res.status(500).json({ error: 'Failed to delete course' });
        }
        if (result.affectedRows === 0) {
          db.query('ROLLBACK');
          return res.status(404).json({ error: 'Course not found' });
        }

        db.query('COMMIT', (err) => {
          if (err) {
            console.error('Commit error:', err);
            db.query('ROLLBACK');
            return res.status(500).json({ error: 'Failed to commit changes' });
          }
          console.log(`✅ Course ${id} and all related feedback deleted`);
          res.json({ success: true, message: 'Course and related feedback deleted successfully' });
        });
      });
    });
  });
});

app.delete('/api/student/:id', isAdminAuth, verifyCsrfToken, (req, res) => {
  const studentId = req.params.id;
  db.query('START TRANSACTION', (err) => {
    if (err) {
      console.error('Transaction start error:', err);
      return res.status(500).json({ error: 'Failed to start transaction' });
    }
    
    // First delete all feedback from this student
    db.query('DELETE FROM feedback WHERE student_id = ?', [studentId], (err) => {
      if (err) {
        console.error('Delete feedback error:', err);
        db.query('ROLLBACK');
        return res.status(500).json({ error: 'Failed to delete feedback' });
      }
      
      // Then delete the student
      db.query('DELETE FROM students WHERE id = ?', [studentId], (err, result) => {
        if (err) {
          console.error('Delete student error:', err);
          db.query('ROLLBACK');
          return res.status(500).json({ error: 'Failed to delete student' });
        }
        if (result.affectedRows === 0) {
          db.query('ROLLBACK');
          return res.status(404).json({ error: 'Student not found' });
        }
        
        db.query('COMMIT', (err) => {
          if (err) {
            console.error('Commit error:', err);
            db.query('ROLLBACK');
            return res.status(500).json({ error: 'Failed to commit changes' });
          }
          res.json({ success: true, message: 'Student and their feedback deleted successfully' });
        });
      });
    });
  });
});

app.delete('/api/feedback/:id', isAdminAuth, verifyCsrfToken, (req, res) => {
  db.query('DELETE FROM feedback WHERE feedback_id = ?', [req.params.id], (err, result) => {
    if (err) {
      console.error('Delete feedback error:', err);
      return res.status(500).json({ error: 'Failed to delete feedback' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Feedback not found' });
    }
    res.json({ success: true });
  });
});

/* ===================== ADMIN: UPDATE OPERATIONS ===================== */
app.put('/api/faculty/:id', isAdminAuth, verifyCsrfToken, (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  const name = String(req.body?.name || '').trim();
  const designation = String(req.body?.designation || '').trim();
  const department = String(req.body?.department || '').trim();

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid faculty ID' });
  }
  if (!name || name.length > 100) {
    return res.status(400).json({ error: 'Invalid faculty name' });
  }
  if (!designation || designation.length > 100) {
    return res.status(400).json({ error: 'Invalid designation' });
  }
  if (!department || department.length > 100) {
    return res.status(400).json({ error: 'Invalid department' });
  }
  
  db.query(
    'UPDATE faculties SET name = ?, designation = ?, department = ? WHERE faculty_id = ?',
    [name, designation, department, id],
    (err, result) => {
      if (err) {
        console.error('Update faculty error:', err);
        return res.status(500).json({ error: 'Failed to update faculty' });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Faculty not found' });
      }
      res.json({ success: true });
    }
  );
});

app.put('/api/student/:id', isAdminAuth, verifyCsrfToken, (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  const student_code = String(req.body?.student_code || '').trim();
  const student_name = String(req.body?.student_name || '').trim();
  const username = String(req.body?.username || '').trim();
  const department = String(req.body?.department || '').trim();
  const semester = Number.parseInt(req.body?.semester, 10);
  const status = String(req.body?.status || '').trim().toLowerCase();

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid student ID' });
  }
  if (!student_code || student_code.length > 20) {
    return res.status(400).json({ error: 'Invalid student code' });
  }
  if (!student_name || student_name.length > 100) {
    return res.status(400).json({ error: 'Invalid student name' });
  }
  if (!username || username.length > 50) {
    return res.status(400).json({ error: 'Invalid username' });
  }
  if (!department || department.length > 100) {
    return res.status(400).json({ error: 'Invalid department' });
  }
  if (!Number.isInteger(semester) || semester < 1 || semester > 8) {
    return res.status(400).json({ error: 'Invalid semester' });
  }
  if (!['pending', 'approved', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Invalid student status' });
  }
  
  db.query(
    'UPDATE students SET student_code = ?, student_name = ?, username = ?, department = ?, semester = ?, status = ? WHERE id = ?',
    [student_code, student_name, username.toLowerCase(), department, semester, status, id],
    (err, result) => {
      if (err) {
        console.error('Update student error:', err);
        return res.status(500).json({ error: 'Failed to update student' });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Student not found' });
      }
      res.json({ success: true });
    }
  );
});

app.put('/api/course/:id', isAdminAuth, verifyCsrfToken, (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  const course_name = String(req.body?.course_name || '').trim();
  const programme = String(req.body?.programme || '').trim();
  const semester = Number.parseInt(req.body?.semester, 10);
  const faculty_id = Number.parseInt(req.body?.faculty_id, 10);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid course ID' });
  }
  if (!course_name || course_name.length > 120) {
    return res.status(400).json({ error: 'Invalid course name' });
  }
  if (!programme || programme.length > 50) {
    return res.status(400).json({ error: 'Invalid programme' });
  }
  if (!Number.isInteger(semester) || semester < 1 || semester > 8) {
    return res.status(400).json({ error: 'Invalid semester' });
  }
  if (!Number.isInteger(faculty_id) || faculty_id <= 0) {
    return res.status(400).json({ error: 'Invalid faculty ID' });
  }
  
  db.query(
    'UPDATE courses SET course_name = ?, programme = ?, semester = ?, faculty_id = ? WHERE course_id = ?',
    [course_name, programme, semester, faculty_id, id],
    (err, result) => {
      if (err) {
        console.error('Update course error:', err);
        return res.status(500).json({ error: 'Failed to update course' });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Course not found' });
      }
      res.json({ success: true });
    }
  );
});

app.get('/api/course/:id/faculty', isStudentAuth, (req, res) => {
  const courseId = Number.parseInt(req.params.id, 10);

  if (!Number.isInteger(courseId) || courseId <= 0) {
    return res.status(400).json({ error: 'Invalid course ID' });
  }

  db.query(
    `SELECT c.course_id, c.course_name, c.semester,
            f.faculty_id, f.name AS faculty_name
     FROM courses c
     JOIN faculties f ON c.faculty_id = f.faculty_id
     WHERE c.course_id = ?`,
    [courseId],
    (err, rows) => {
      if (err) {
        console.error('Get course faculty error:', err);
        return res.status(500).json({ error: 'Failed to fetch faculty for course' });
      }
      if (rows.length === 0) {
        return res.status(404).json({ error: 'Course faculty mapping not found' });
      }
      res.json(rows[0]);
    }
  );
});

app.put('/api/course/:id/faculty', isAdminAuth, verifyCsrfToken, (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  const faculty_id = Number.parseInt(req.body?.faculty_id, 10);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid course ID' });
  }
  if (!Number.isInteger(faculty_id) || faculty_id <= 0) {
    return res.status(400).json({ error: 'Invalid faculty ID' });
  }

  db.query(
    'SELECT faculty_id FROM faculties WHERE faculty_id = ?',
    [faculty_id],
    (facultyErr, facultyRows) => {
      if (facultyErr) {
        console.error('Validate faculty link error:', facultyErr);
        return res.status(500).json({ error: 'Failed to validate faculty' });
      }
      if (facultyRows.length === 0) {
        return res.status(404).json({ error: 'Faculty not found' });
      }

      db.query(
        'UPDATE courses SET faculty_id = ? WHERE course_id = ?',
        [faculty_id, id],
        (err, result) => {
          if (err) {
            console.error('Update course faculty link error:', err);
            return res.status(500).json({ error: 'Failed to update faculty-course link' });
          }
          if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Course not found' });
          }
          res.json({ success: true });
        }
      );
    }
  );
});

/* ===================== SUBMIT FEEDBACK (DYNAMIC QUESTIONS) ===================== */
app.post('/add-feedback', isStudentAuth, upload.none(), verifyCsrfToken, (req, res) => {
  const {
    course,
    faculty,
    comments,
    question_responses
  } = req.body;

  if (!course || !faculty) {
    return res.status(400).json({ error: 'Course and faculty are required' });
  }

  let responses = {};
  try {
    responses = JSON.parse(question_responses || '{}');
  } catch (err) {
    return res.status(400).json({ error: 'Invalid question responses format' });
  }

  db.query(
    `SELECT c.course_id, c.faculty_id, f.name AS faculty_name
     FROM courses c
     JOIN faculties f ON c.faculty_id = f.faculty_id
     WHERE c.course_id = ?`,
    [course],
    (courseErr, courseRows) => {
      if (courseErr) {
        console.error('Validate course-faculty link error:', courseErr);
        return res.status(500).json({ error: 'Failed to validate course and faculty' });
      }
      if (courseRows.length === 0) {
        return res.status(400).json({ error: 'Selected course is not linked to any faculty' });
      }

      const currentFacultyId = Number(courseRows[0].faculty_id);
      if (!currentFacultyId) {
        return res.status(400).json({ error: 'Selected course has no faculty assigned' });
      }

      db.query(
    `SELECT feedback_id FROM feedback WHERE student_id = ? AND course_id = ?`,
    [req.session.studentId, course],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (rows.length > 0) {
        return res.status(400).json({ error: 'Feedback already submitted for this course' });
      }

      const q1 = responses['1'] || 3;
      const q2 = responses['2'] || 3;
      const q3 = responses['3'] || 3;
      const q4 = responses['4'] || 3;
      const q5 = responses['5'] || 3;
      const q6 = responses['6'] || 3;
      const q7 = responses['7'] || 3;

      db.query(
        `INSERT INTO feedback
        (
          student_id, faculty_id, course_id,
          q1_regularity, q2_syllabus, q3_conceptual,
          q4_practical, q5_communication,
          q6_teaching, q7_contribution,
          comment
        )
        VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        [
          req.session.studentId,
          currentFacultyId,
          course,
          q1, q2, q3, q4, q5, q6, q7,
          comments || null
        ],
        (err) => {
          if (err) {
            console.error('Feedback submission error:', err);
            return res.status(500).json({ error: 'Failed to submit feedback' });
          }
          res.json({ success: true });
        }
      );
    }
      );
    }
  );
});

/* ===================== CHECK SESSION (role-aware) ===================== */
app.get('/api/check-session', (req, res) => {
  if (!req.session) return res.json({ authenticated: false, role: null });

  const isAdmin = Boolean(req.session.isAdmin);
  const isStudent = Boolean(req.session.studentId);
  const role = isStudent ? 'student' : (isAdmin ? 'admin' : null);

  res.json({
    authenticated: isAdmin || isStudent,
    role,
    isAdmin,
    isStudent
  });
});

// STATIC FILES - MUST COME AFTER ALL ROUTES
app.use(express.static('public'));

/* ===================== 404 ===================== */
app.use((_req, res) => {
  res.status(404).send('Page not found');
});

/* ===================== SERVER ===================== */
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log('====================================');
  console.log('🚀 Faculty Feedback System Running');
  console.log(`🏠 Landing Page: http://localhost:${PORT}/`);
  console.log(`👨‍💼 Admin Login: http://localhost:${PORT}/admin-login`);
  console.log(`🎓 Student Login: http://localhost:${PORT}/student-login`);
  console.log(`📝 Student Register: http://localhost:${PORT}/register`);
  console.log(`📋 Feedback Form: http://localhost:${PORT}/feedback`);
  console.log(`⚙️  Admin Panel: http://localhost:${PORT}/admin`);
  console.log('====================================');
  console.log('✨ Auto-reordering enabled for questions!');
  console.log('✨ Cascade deletes enabled for faculty & courses!');
  console.log('====================================');
});



