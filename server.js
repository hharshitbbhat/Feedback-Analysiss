const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const multer = require('multer');
const upload = multer();
require('dotenv').config();

const db = require('./db');

const app = express();

/* ===================== MIDDLEWARE ===================== */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// SESSION MIDDLEWARE - MUST COME BEFORE ROUTES
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'secret123',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production'
    }
  })
);

/* ===================== AUTH HELPERS ===================== */
function isStudentAuth(req, res, next) {
  if (!req.session.studentId) return res.redirect('/student-login');
  next();
}

function isAdminAuth(req, res, next) {
  if (!req.session.isAdmin) return res.status(401).send('Unauthorized');
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

app.get('/register', (_req, res) =>
  res.sendFile(path.join(__dirname, 'public/register.html'))
);

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
  req.session.destroy(() => {
    if (req.query.type === 'admin') {
      res.redirect('/admin-login');
    } else {
      res.redirect('/student-login');
    }
  });
});

/* ===================== ADMIN LOGIN ===================== */
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  db.query(
    'SELECT * FROM admins WHERE username = ?',
    [username],
    async (err, rows) => {
      if (err) {
        console.error('Admin login error:', err);
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

      req.session.isAdmin = true;
      req.session.adminId = admin.id;
      
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
          return res.status(500).json({ error: 'Session error' });
        }
        res.json({ success: true, redirect: '/admin' });
      });
    }
  );
});

/* ===================== STUDENT LOGIN ===================== */
app.post('/student/login', async (req, res) => {
  const { username, password } = req.body;

  db.query(
    'SELECT * FROM students WHERE username = ?',
    [username.toLowerCase()],
    async (err, rows) => {
      if (err || rows.length === 0) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      const match = await bcrypt.compare(password, rows[0].password);
      if (!match) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      req.session.studentId = rows[0].id;

      req.session.save((err) => {
        if (err) {
          return res.status(500).json({ error: 'Session error' });
        }
        res.json({ success: true, redirect: '/feedback' });
      });
    }
  );
});

/* ===================== REGISTRATION ===================== */
const REGISTRATION_CODE = 'JU.FEEDBACK';

app.post('/register', async (req, res) => {
  const { code, name, dept, sem, password, registerationCode } = req.body;

  if (registerationCode !== REGISTRATION_CODE)
    return res.send('❌ Invalid registration code');

  const hashed = await bcrypt.hash(password, 10);

  db.query(
    `INSERT INTO students
     (student_code, student_name, department, semester, username, password)
     VALUES (?,?,?,?,?,?)`,
    [code, name, dept, sem, code.toLowerCase(), hashed],
    (err) => {
      if (err) return res.send('❌ Registration failed');
      res.send('✅ Registered successfully! <a href="/student-login">Login</a>');
    }
  );
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

app.get('/api/faculties', (req, res) => {
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

// ⭐ UPDATED: Add new question with automatic reordering
app.post('/api/questions', isAdminAuth, (req, res) => {
  const { question_text, question_type, display_order, is_required } = req.body;
  
  if (!question_text || !question_type || !display_order) {
    return res.status(400).json({ error: 'Question text, type, and order are required' });
  }
  
  const targetOrder = parseInt(display_order);
  
  // Start transaction
  db.query('START TRANSACTION', (err) => {
    if (err) {
      console.error('Transaction start error:', err);
      return res.status(500).json({ error: 'Failed to start transaction' });
    }
    
    // STEP 1: Shift all questions at or after target position DOWN by 1
    db.query(
      'UPDATE feedback_questions SET display_order = display_order + 1 WHERE display_order >= ?',
      [targetOrder],
      (err) => {
        if (err) {
          console.error('Shift questions error:', err);
          db.query('ROLLBACK');
          return res.status(500).json({ error: 'Failed to reorder questions' });
        }
        
        // STEP 2: Insert the new question at the target position
        db.query(
          'INSERT INTO feedback_questions (question_text, question_type, display_order, is_required, is_active) VALUES (?, ?, ?, ?, 1)',
          [question_text, question_type, targetOrder, is_required !== undefined ? is_required : 1],
          (err, result) => {
            if (err) {
              console.error('Add question error:', err);
              db.query('ROLLBACK');
              return res.status(500).json({ error: 'Failed to add question' });
            }
            
            // STEP 3: Commit the transaction
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

// ⭐ UPDATED: Update question with position change handling
app.put('/api/questions/:id', isAdminAuth, (req, res) => {
  const { question_text, question_type, display_order, is_required, is_active, old_order } = req.body;
  
  if (!question_text || !question_type || display_order === undefined) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  const newOrder = parseInt(display_order);
  const questionId = parseInt(req.params.id);
  
  // Start transaction
  db.query('START TRANSACTION', (err) => {
    if (err) {
      console.error('Transaction start error:', err);
      return res.status(500).json({ error: 'Failed to start transaction' });
    }
    
    // If old_order is provided and position changed, reorder other questions
    if (old_order !== undefined && old_order !== newOrder) {
      const oldPos = parseInt(old_order);
      
      if (newOrder > oldPos) {
        // Moving DOWN: decrement questions between old and new position
        console.log(`Moving question ${questionId} DOWN from ${oldPos} to ${newOrder}`);
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
        // Moving UP: increment questions between new and old position
        console.log(`Moving question ${questionId} UP from ${oldPos} to ${newOrder}`);
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
      // No position change, just update
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

// ⭐ ALREADY GOOD: Delete question with automatic reordering
app.delete('/api/questions/:id', isAdminAuth, (req, res) => {
  // First, get the display_order of the question being deleted
  db.query('SELECT display_order FROM feedback_questions WHERE id = ?', [req.params.id], (err, rows) => {
    if (err) {
      console.error('Delete question error:', err);
      return res.status(500).json({ error: 'Failed to delete question' });
    }
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Question not found' });
    }
    
    const deletedOrder = rows[0].display_order;
    
    // Start transaction
    db.query('START TRANSACTION', (err) => {
      if (err) {
        console.error('Transaction start error:', err);
        return res.status(500).json({ error: 'Failed to start transaction' });
      }
      
      // STEP 1: Delete the question
      db.query('DELETE FROM feedback_questions WHERE id = ?', [req.params.id], (err) => {
        if (err) {
          console.error('Delete question error:', err);
          db.query('ROLLBACK');
          return res.status(500).json({ error: 'Failed to delete question' });
        }
        
        // STEP 2: Shift all questions after deleted position UP by 1
        db.query(
          'UPDATE feedback_questions SET display_order = display_order - 1 WHERE display_order > ?',
          [deletedOrder],
          (err) => {
            if (err) {
              console.error('Shift after delete error:', err);
              db.query('ROLLBACK');
              return res.status(500).json({ error: 'Failed to reorder questions after deletion' });
            }
            
            // STEP 3: Commit the transaction
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

// ⭐ ALREADY GOOD: Reorder questions (drag and drop)
app.post('/api/questions/reorder', isAdminAuth, (req, res) => {
  const { questions } = req.body;
  
  if (!questions || !Array.isArray(questions) || questions.length === 0) {
    return res.status(400).json({ error: 'Questions array is required' });
  }
  
  // Validate each question has id and display_order
  for (const q of questions) {
    if (!q.id || q.display_order === undefined) {
      return res.status(400).json({ error: 'Each question must have id and display_order' });
    }
  }
  
  const ids = questions.map(q => q.id).join(',');
  
  // Use transaction for atomic operation
  db.query('START TRANSACTION', (err) => {
    if (err) {
      console.error('Transaction start error:', err);
      return res.status(500).json({ error: 'Failed to start transaction' });
    }
    
    // Step 1: Offset all values by adding 10000 to avoid unique constraint conflicts
    const offsetSql = `UPDATE feedback_questions SET display_order = display_order + 10000 WHERE id IN (${ids})`;
    
    db.query(offsetSql, (err) => {
      if (err) {
        console.error('Reorder questions offset error:', err);
        db.query('ROLLBACK');
        return res.status(500).json({ error: 'Failed to reorder questions' });
      }
      
      // Step 2: Set final values using CASE
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
        
        // Commit the transaction
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
      fd.feedback_id AS id,
      s.student_name,
      s.student_code,
      c.course_name,
      f.name AS faculty_name,
      fd.q1_regularity,
      fd.q2_syllabus,
      fd.q3_conceptual,
      fd.q4_practical,
      fd.q5_communication,
      fd.q6_teaching,
      fd.q7_contribution,
      fd.comment,
      fd.created_at
    FROM feedback fd
    JOIN students s ON fd.student_id = s.id
    JOIN courses c ON fd.course_id = c.course_id
    JOIN faculties f ON fd.faculty_id = f.faculty_id
    ORDER BY fd.created_at DESC`,
    (err, rows) => {
      if (err) return res.status(500).json([]);
      res.json(rows);
    }
  );
});

/* ===================== ADMIN: ADD OPERATIONS ===================== */
app.post('/add-faculty', isAdminAuth, upload.none(), (req, res) => {
  const name = req.body?.name;
  const designation = req.body?.designation;
  const dept = req.body?.dept || req.body?.department;
  
  if (!name || !designation || !dept) {
    return res.status(400).json({ error: 'All fields are required' });
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

app.post('/add-course', isAdminAuth, upload.none(), (req, res) => {
  const course = req.body?.course;
  const programme = req.body?.programme;
  const semester = req.body?.semester;
  const faculty = req.body?.faculty;
  
  if (!course || !programme || !semester || !faculty) {
    return res.status(400).json({ error: 'All fields are required' });
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
});

app.post('/add-student', isAdminAuth, upload.none(), async (req, res) => {
  const code = req.body?.code;
  const name = req.body?.name;
  const username = req.body?.username;
  const password = req.body?.password;
  const dept = req.body?.dept;
  const sem = req.body?.sem;
  
  if (!code || !name || !username || !password || !dept || !sem) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  try {
    const hashed = await bcrypt.hash(password, 10);
    db.query(
      `INSERT INTO students (student_code, student_name, username, password, department, semester)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [code, name, username, hashed, dept, sem],
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
app.delete('/api/faculty/:id', isAdminAuth, (req, res) => {
  db.query('DELETE FROM faculties WHERE faculty_id = ?', [req.params.id], (err) => {
    if (err) {
      console.error('Delete faculty error:', err);
      return res.status(500).json({ error: 'Failed to delete faculty' });
    }
    res.json({ success: true });
  });
});

app.delete('/api/course/:id', isAdminAuth, (req, res) => {
  db.query('DELETE FROM courses WHERE course_id = ?', [req.params.id], (err) => {
    if (err) {
      console.error('Delete course error:', err);
      return res.status(500).json({ error: 'Failed to delete course' });
    }
    res.json({ success: true });
  });
});

app.delete('/api/student/:id', isAdminAuth, (req, res) => {
  db.query('DELETE FROM students WHERE id = ?', [req.params.id], (err) => {
    if (err) {
      console.error('Delete student error:', err);
      return res.status(500).json({ error: 'Failed to delete student' });
    }
    res.json({ success: true });
  });
});

app.delete('/api/feedback/:id', isAdminAuth, (req, res) => {
  db.query('DELETE FROM feedback WHERE feedback_id = ?', [req.params.id], (err) => {
    if (err) {
      console.error('Delete feedback error:', err);
      return res.status(500).json({ error: 'Failed to delete feedback' });
    }
    res.json({ success: true });
  });
});

/* ===================== ADMIN: UPDATE OPERATIONS ===================== */
app.put('/api/faculty/:id', isAdminAuth, (req, res) => {
  const { name, designation, department } = req.body;
  
  if (!name || !designation || !department) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  db.query(
    'UPDATE faculties SET name = ?, designation = ?, department = ? WHERE faculty_id = ?',
    [name, designation, department, req.params.id],
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

app.put('/api/student/:id', isAdminAuth, (req, res) => {
  const { student_code, student_name, username, department, semester } = req.body;
  
  if (!student_code || !student_name || !username || !department || !semester) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  db.query(
    'UPDATE students SET student_code = ?, student_name = ?, username = ?, department = ?, semester = ? WHERE id = ?',
    [student_code, student_name, username, department, semester, req.params.id],
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

app.put('/api/course/:id', isAdminAuth, (req, res) => {
  const { course_name, programme, semester, faculty_id } = req.body;
  
  if (!course_name || !programme || !semester || !faculty_id) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  db.query(
    'UPDATE courses SET course_name = ?, programme = ?, semester = ?, faculty_id = ? WHERE course_id = ?',
    [course_name, programme, semester, faculty_id, req.params.id],
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

/* ===================== SUBMIT FEEDBACK (DYNAMIC QUESTIONS) ===================== */
app.post('/add-feedback', isStudentAuth, upload.none(), (req, res) => {
  const {
    course,
    faculty,
    comments,
    question_responses // JSON string: {question_id: answer}
  } = req.body;

  if (!course || !faculty) {
    return res.status(400).json({ error: 'Course and faculty are required' });
  }

  // Parse question responses
  let responses = {};
  try {
    responses = JSON.parse(question_responses || '{}');
  } catch (err) {
    return res.status(400).json({ error: 'Invalid question responses format' });
  }

  // Check if feedback already exists
  db.query(
    `SELECT feedback_id FROM feedback WHERE student_id = ? AND course_id = ?`,
    [req.session.studentId, course],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (rows.length > 0) {
        return res.status(400).json({ error: 'Feedback already submitted for this course' });
      }

      // Map dynamic responses to existing table columns (for backward compatibility)
      // This assumes questions 1-7 still exist and map to the original columns
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
          faculty,
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
  console.log('====================================');
});