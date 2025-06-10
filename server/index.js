//server/index.js
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import { createServer } from 'http';
import { Server } from 'socket.io';
import dotenv from 'dotenv';
import pkg from 'pg';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { body, validationResult } from 'express-validator';
import { createClient } from '@supabase/supabase-js';
import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import ffmpeg from 'fluent-ffmpeg';
import { getClientIp } from 'request-ip'; 
import { promisify } from 'util';
import multer from 'multer';
import AdmZip from 'adm-zip';
import mime from 'mime-types';
import githubRouter from './routes/github.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const { Pool } = pkg;
dotenv.config();

const PRIVATE_KEY = fs.readFileSync(
  path.resolve(process.env.PRIVATE_KEY_PATH),
  'utf8'
);

// If you also verify tokens elsewhere using the public key, do the same:
const PUBLIC_KEY = fs.readFileSync(
  path.resolve(process.env.PUBLIC_KEY_PATH),
  'utf8'
);

// Database connection
const pool = new Pool({
  connectionString: 'postgresql://securedrive_user:4YToNdsiPz68V6dv4pYWIrOTLDoK4a1T@dpg-d0o5obali9vc73fn60lg-a.oregon-postgres.render.com/securedrive_6chh?ssl=true',
  ssl: { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Supabase client for file storage
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const FFMPEG_BIN  = process.env.FFMPEG_PATH  || 'ffmpeg';
const FFPROBE_BIN = process.env.FFPROBE_PATH || 'ffprobe';

// resolve relative paths
const ffmpegPath  = path.resolve(__dirname, FFMPEG_BIN);
const ffprobePath = path.resolve(__dirname, FFPROBE_BIN);

ffmpeg.setFfmpegPath(ffmpegPath);
ffmpeg.setFfprobePath(ffprobePath);

console.log('Using ffmpeg:', ffmpegPath);
console.log('Using ffprobe:', ffprobePath);

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // In production, use a strong secret key

const JWT_EXPIRES_IN = '7d';
const JWT_EXPIRES_IN_MS = 7 * 24 * 60 * 60 * 1000;

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:5173",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
  }
});

const PORT = process.env.PORT || 7001;

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/zip' || file.mimetype === 'application/x-zip-compressed') {
      cb(null, true);
    } else {
      cb(new Error('Only ZIP files are allowed'));
    }
  }
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});

// Middleware
app.use(helmet());
app.use(compression());
app.use(morgan('combined'));
app.use(limiter);
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Auth middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    // verify RS256 token against your RSA public key
    const decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });

    // stash the token's JWT ID onto req so logout can see it
    req.jwtId = decoded.jti;
    const result = await pool.query(
      'SELECT id, email, name FROM users WHERE id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

const generateToken = (userId) => {
  return jwt.sign(
    { userId },
    process.env.ENCRYPTION_KEY,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
};

// Code execution function
const spawnAsync = (cmd, args, opts) => new Promise((res, rej) => {
  const c = spawn(cmd, args, opts);
  let stdout = '', stderr = '';
  c.stdout.on('data', d => stdout += d);
  c.stderr.on('data', d => stderr += d);
  c.on('error', rej);
  c.on('close', code => res({ code, stdout, stderr }));
});

async function executeCode(code, language, input = '') {
  const tempDir = path.join(__dirname, 'temp');
  if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

  const fileName = `code_${Date.now()}`;
  let command, args;

  switch (language) {
    case 'javascript':
      command = 'node'; args = ['-e', code]; break;
    case 'python':
      command = 'python3'; args = ['-c', code]; break;

    case 'java': {
      const classMatch = code.match(/public\s+class\s+(\w+)/);
      const className = classMatch ? classMatch[1] : 'Main';
      const javaFile = path.join(tempDir, `${className}.java`);
      await fs.promises.writeFile(javaFile, code);

      const { code: jc, stderr: jErr } = await spawnAsync('javac', [javaFile], { cwd: tempDir });
      if (jc !== 0) return { error: jErr || 'Java compilation failed' };

      command = 'java'; args = ['-cp', tempDir, className];
      break;
    }

    case 'cpp': {
      const src = path.join(tempDir, `${fileName}.cpp`);
      const bin = path.join(tempDir, fileName);
      await fs.promises.writeFile(src, code);

      const { code: cc, stderr: cErr } = await spawnAsync('g++', [src, '-o', bin], { cwd: tempDir });
      if (cc !== 0) return { error: cErr || 'C++ compilation failed' };

      command = bin; args = []; break;
    }

    case 'c': {
      const src = path.join(tempDir, `${fileName}.c`);
      const bin = path.join(tempDir, fileName);
      await fs.promises.writeFile(src, code);

      const { code: gc, stderr: gErr } = await spawnAsync('gcc', [src, '-o', bin], { cwd: tempDir });
      if (gc !== 0) return { error: gErr || 'C compilation failed' };

      command = bin; args = []; break;
    }

    case 'typescript': {
      const tsf = path.join(tempDir, `${fileName}.ts`);
      const jsf = path.join(tempDir, `${fileName}.js`);
      await fs.promises.writeFile(tsf, code);

      const { code: tc, stderr: tErr } = await spawnAsync('npx', ['tsc', tsf, '--outDir', tempDir], { cwd: tempDir });
      if (tc !== 0) return { error: tErr || 'TypeScript compilation failed' };

      command = 'node'; args = [jsf]; break;
    }

    default:
      return { error: 'Unsupported language' };
  }

  // execute compiled or interpreted code
  const proc = spawn(command, args, { cwd: tempDir, stdio: ['pipe','pipe','pipe'], timeout: 10000 });
  let out = '', err = '';
  proc.stdout.on('data', d => out += d);
  proc.stderr.on('data', d => err += d);
  if (input) { proc.stdin.write(input); proc.stdin.end(); }

  return new Promise(res => {
    proc.on('close', code => {
      res(code === 0 ? { output: out } : { error: err || `Exited ${code}` });
    });
    proc.on('error', e => res({ error: e.message }));
  });
}

// Error handler
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);

  let error = {
    message: err.message || 'Internal Server Error',
    status: err.status || 500
  };

  if (err.name === 'ValidationError') {
    error.message = Object.values(err.errors).map(val => val.message).join(', ');
    error.status = 400;
  }

  if (err.name === 'JsonWebTokenError') {
    error.message = 'Invalid token';
    error.status = 401;
  }

  if (err.name === 'TokenExpiredError') {
    error.message = 'Token expired';
    error.status = 401;
  }

  if (err.code === '23505') {
    error.message = 'Duplicate entry';
    error.status = 409;
  }

  if (err.code === '23503') {
    error.message = 'Referenced record not found';
    error.status = 400;
  }

  if (process.env.NODE_ENV === 'production' && error.status === 500) {
    error.message = 'Internal Server Error';
  }

  res.status(error.status).json({
    error: error.message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};

// Initialize database tables
async function initializeDatabase() {
  const client = await pool.connect();
  
  try {
    // Create version history table for documents
    await client.query(`
      CREATE TABLE IF NOT EXISTS document_versions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        version_number INTEGER NOT NULL,
        created_by UUID NOT NULL REFERENCES users(id),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create projects table for ZIP uploads
    await client.query(`
      CREATE TABLE IF NOT EXISTS projects (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        description TEXT,
        zip_path TEXT NOT NULL,
        extract_path TEXT,
        status TEXT NOT NULL DEFAULT 'uploaded',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Create project_files table
    await client.query(`
      CREATE TABLE IF NOT EXISTS project_files (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        relative_path TEXT NOT NULL,
        is_directory BOOLEAN NOT NULL DEFAULT FALSE,
        size INTEGER,
        mime_type TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Create indexes for better performance
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_files_owner_id ON files(owner_id);
      CREATE INDEX IF NOT EXISTS idx_files_updated_at ON files(updated_at);
      CREATE INDEX IF NOT EXISTS idx_user_files_user_id ON user_files(user_id);
      CREATE INDEX IF NOT EXISTS idx_user_files_file_id ON user_files(file_id);
      CREATE INDEX IF NOT EXISTS idx_versions_file_id ON document_versions(file_id);
      CREATE INDEX IF NOT EXISTS idx_projects_owner_id ON projects(owner_id);
      CREATE INDEX IF NOT EXISTS idx_project_files_project_id ON project_files(project_id);
      CREATE INDEX IF NOT EXISTS idx_project_files_path ON project_files(relative_path);
    `);

    // Create codespace_share table for sharing files/projects via tokens
    await client.query(`
      CREATE TABLE IF NOT EXISTS codespace_share (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
        owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token TEXT UNIQUE NOT NULL,
        permission TEXT NOT NULL DEFAULT 'read', -- 'read', 'write'
        expires_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create indexes for new tables
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_codespace_share_file_id ON codespace_share(file_id);
      CREATE INDEX IF NOT EXISTS idx_codespace_share_token ON codespace_share(token);
    `);



    console.log('Database tables initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
    throw error;
  } finally {
    client.release();
  }
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV 
  });
});

// AUTH ROUTES
// Register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  
  try {
    // Check if user already exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'User with this email already exists' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create new user
    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, hashedPassword]
    );
    
    const user = result.rows[0];
    
    // Generate JWT token
     const jti     = uuidv4();
     const token = jwt.sign(
       { id: user.id, name: user.name, email: user.email, jti },
      PRIVATE_KEY,
      { algorithm: 'RS256', expiresIn: JWT_EXPIRES_IN }
    );
    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password, deviceId } = req.body; // Ensure frontend sends deviceId

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate JWT ID and token
    const jwtId = uuidv4();
    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email, jti: jwtId },
      PRIVATE_KEY,
      { algorithm: 'RS256', expiresIn: JWT_EXPIRES_IN }
    );
// Calculate expiry timestamp
    const now = new Date();
    const expiresAt = new Date(now.getTime() + JWT_EXPIRES_IN_MS); // define JWT_EXPIRES_IN_MS = 1000 * 60 * 60 * 24 etc.

    // Get IP Address
    const ipAddress = getClientIp(req) || req.ip || 'unknown';

    // Insert into sessions table
    await pool.query(
      `INSERT INTO sessions (user_id, ip_address, device_id, jwt_id, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [user.id, ipAddress, deviceId, jwtId, expiresAt]
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

/**
 * POST /api/auth/logout
 * - Requires: Authorization: Bearer <token>
 * - Action: Mark the matching session row as revoked = true
 */
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    console.log('→ [/api/auth/logout] handler invoked');

    // 1) Ensure authenticateToken populated req.user:
    console.log('→ [/api/auth/logout] req.user payload:', req.user);
    const jwtId = req.jwtId;
    if (!jwtId) {
      console.warn('→ [/api/auth/logout] no jti found on req.user');
      return res.status(400).json({ message: 'Invalid token: missing jti' });
    }

    // 2) Before flipping anything, check whether that jwt_id even exists in sessions:
    const { rows: existingRows } = await pool.query(
      `SELECT id, jwt_id, revoked, created_at 
         FROM sessions 
        WHERE jwt_id = $1`,
      [jwtId]
    );
    console.log('→ [/api/auth/logout] lookup sessions by jwt_id:', existingRows);
    if (existingRows.length === 0) {
      console.warn(`→ [/api/auth/logout] no session row found for jwt_id = ${jwtId}`);
      return res.status(404).json({ message: 'Session not found (already revoked or invalid)' });
    }

   // 3) Flip revoked = true on that exact row:
    const updateResult = await pool.query(
      `UPDATE sessions
         SET revoked = true
       WHERE jwt_id = $1`,
      [jwtId]
    );
    console.log(`→ [/api/auth/logout] sessions rows updated:`, updateResult.rowCount);

    // 4) Success
    return res.json({ message: 'Logout successful' });
  } catch (err) {
    console.error('Logout error:', err);
    return res.status(500).json({ message: 'Server error during logout' });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
    },
  });
});

// PROJECT ROUTES (ZIP Upload)
// Upload ZIP file
app.post('/api/projects/upload', authenticateToken, upload.single('zipFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No ZIP file uploaded' });
    }

    const { name, description } = req.body;
    const zipPath = req.file.path;
    const projectName = name || path.basename(req.file.originalname, '.zip');

    // Create project record
    const result = await pool.query(
       `INSERT INTO projects
          (owner_id, name, description, zip_path, status, project_type)
        VALUES ($1, $2, $3, $4, $5, 'zip')
        RETURNING *`,
      [req.user.id, projectName, description || '', zipPath, 'uploaded']
    );

    const project = result.rows[0];

    // Process ZIP file asynchronously
    processZipFile(project.id, zipPath);

    res.status(201).json({
      message: 'Project uploaded successfully',
      project: {
        id: project.id,
        name: project.name,
        description: project.description,
        status: project.status,
        created_at: project.created_at
      }
    });
  } catch (error) {
    console.error('Error uploading project:', error);
    res.status(500).json({ error: 'Failed to upload project' });
  }
});

// Get all projects for user
app.get('/api/projects', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '' } = req.query;
    const offset = (page - 1) * limit;

    let query = `
      SELECT p.*, COUNT(pf.id) as file_count
      FROM projects p
      LEFT JOIN project_files pf ON p.id = pf.project_id
      WHERE p.owner_id = $1 AND p.project_type = 'zip'
    `;
    
    const params = [req.user.id];

    if (search) {
      query += ` AND p.name ILIKE $${params.length + 1}`;
      params.push(`%${search}%`);
    }

    query += ` GROUP BY p.id ORDER BY p.updated_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    // Compute total count of ZIP projects (with optional search filter)
    const countParams = [req.user.id];
    let countQuery = `
      SELECT COUNT(*) 
        FROM projects 
       WHERE owner_id = $1 
         AND project_type = 'zip'
    `;
    if (search) {
      countQuery += ` AND name ILIKE $2`;
      countParams.push(`%${search}%`);
    }
    const countRes = await pool.query(countQuery, countParams);

    res.json({
      projects: result.rows,
      pagination: {
        page: parseInt(page, 10),
        limit: parseInt(limit, 10),
        total: parseInt(countRes.rows[0].count, 10)
      }
    });
  } catch (error) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

// Get single project with file structure
app.get('/api/projects/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const projectResult = await pool.query(
      'SELECT * FROM projects WHERE id = $1 AND owner_id = $2',
      [id, req.user.id]
    );

    if (projectResult.rows.length === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const project = projectResult.rows[0];

    // Get file structure
    const filesResult = await pool.query(
      'SELECT * FROM project_files WHERE project_id = $1 ORDER BY relative_path',
      [id]
    );

    res.json({
      ...project,
      files: filesResult.rows
    });
  } catch (error) {
    console.error('Error fetching project:', error);
    res.status(500).json({ error: 'Failed to fetch project' });
  }
});

// Get file content
app.get('/api/projects/:id/files/*', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const filePath = req.params[0]; // Everything after /files/

    // Verify project ownership
    const projectResult = await pool.query(
      'SELECT extract_path FROM projects WHERE id = $1 AND owner_id = $2',
      [id, req.user.id]
    );

    if (projectResult.rows.length === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const project = projectResult.rows[0];
    console.log('Project extract_path:', project.extract_path);
    console.log('Requested filePath:', filePath);
    const fullPath = path.join(project.extract_path, filePath);
    
    // Security check: ensure file is within project directory
    if (!fullPath.startsWith(project.extract_path)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Check if file exists and is not a directory
    console.log('Constructed fullPath to check:', fullPath);
    if (!fs.existsSync(fullPath) || fs.statSync(fullPath).isDirectory()) {
      console.error(`File not found or is a directory: ${fullPath}`);
      return res.status(404).json({ error: 'File not found' });
    }

    // Read file content
    const content = fs.readFileSync(fullPath, 'utf8');
    const mimeType = mime.lookup(fullPath) || 'text/plain';

    res.json({
      content,
      mimeType,
      path: filePath
    });
  } catch (error) {
    console.error('Error reading file:', error);
    res.status(500).json({ error: 'Failed to read file' });
  }
});

// Update file content
app.put('/api/projects/:id/files/*', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const filePath = req.params[0];
    const { content } = req.body;

    // Verify project ownership
    const projectResult = await pool.query(
      'SELECT extract_path FROM projects WHERE id = $1 AND owner_id = $2',
      [id, req.user.id]
    );

    if (projectResult.rows.length === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const project = projectResult.rows[0];
    const fullPath = path.join(project.extract_path, filePath);

    // Security check
    if (!fullPath.startsWith(project.extract_path)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Write file content
    fs.writeFileSync(fullPath, content, 'utf8');

    // Update project timestamp
    await pool.query(
      'UPDATE projects SET updated_at = NOW() WHERE id = $1',
      [id]
    );

    res.json({ message: 'File updated successfully' });
  } catch (error) {
    console.error('Error updating file:', error);
    res.status(500).json({ error: 'Failed to update file' });
  }
});

// Delete project
app.delete('/api/projects/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Get project info
    const projectResult = await pool.query(
      'SELECT extract_path, zip_path FROM projects WHERE id = $1 AND owner_id = $2',
      [id, req.user.id]
    );

    if (projectResult.rows.length === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const project = projectResult.rows[0];

    // Delete files from filesystem
    if (project.extract_path && fs.existsSync(project.extract_path)) {
      fs.rmSync(project.extract_path, { recursive: true, force: true });
    }
    if (project.zip_path && fs.existsSync(project.zip_path)) {
      fs.unlinkSync(project.zip_path);
    }

    // Delete from database (cascades to project_files)
    await pool.query('DELETE FROM projects WHERE id = $1', [id]);

    res.json({ message: 'Project deleted successfully' });
  } catch (error) {
    console.error('Error deleting project:', error);
    res.status(500).json({ error: 'Failed to delete project' });
  }
});








// Delete project
app.delete('/api/projects/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Get project info and check ownership
    const projectResult = await pool.query(
      'SELECT owner_id, extract_path, zip_path FROM projects WHERE id = $1',
      [id]
    );

    if (projectResult.rows.length === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const project = projectResult.rows[0];

    if (project.owner_id !== req.user.id) {
      // If not owner, check if user has access via codespace_user_access or user_files
      const userAccessCheck = await pool.query(
        'SELECT 1 FROM user_files WHERE user_id = $1 AND file_id = $2',
        [req.user.id, id]
      );
      if (userAccessCheck.rows.length === 0) {
        return res.status(403).json({ error: 'Insufficient permissions to delete this project' });
      }
      // If user has access but is not owner, only remove their access
      await pool.query('DELETE FROM user_files WHERE user_id = $1 AND file_id = $2', [req.user.id, id]);
      return res.json({ message: 'Access to project removed successfully' });
    }

    // If owner, proceed with full deletion
    // Delete files from filesystem
    if (project.extract_path && fs.existsSync(project.extract_path)) {
      fs.rmSync(project.extract_path, { recursive: true, force: true });
    }
    if (project.zip_path && fs.existsSync(project.zip_path)) {
      fs.unlinkSync(project.zip_path);
    }

    // Delete from database (cascades to project_files, codespace_share, user_files)
    await pool.query('DELETE FROM projects WHERE id = $1', [id]);

    res.json({ message: 'Project deleted successfully' });
  } catch (error) {
    console.error('Error deleting project:', error);
    res.status(500).json({ error: 'Failed to delete project' });
  }
});














// Process ZIP file function
async function processZipFile(projectId, zipPath) {
  try {
    // Update status to unzipping
    await pool.query(
      'UPDATE projects SET status = $1 WHERE id = $2',
      ['unzipping', projectId]
    );

    const zip = new AdmZip(zipPath);
    const extractPath = path.join(__dirname, 'projects', projectId);

    // Create extract directory
    if (!fs.existsSync(extractPath)) {
      fs.mkdirSync(extractPath, { recursive: true });
    }

    // Extract ZIP
    zip.extractAllTo(extractPath, true);

    // Update project with extract path
    await pool.query(
      'UPDATE projects SET extract_path = $1, status = $2 WHERE id = $3',
      [extractPath, 'ready', projectId]
    );

    // Scan and catalog files
    await catalogFiles(projectId, extractPath);

    console.log(`Project ${projectId} processed successfully`);
  } catch (error) {
    console.error(`Error processing project ${projectId}:`, error);
    
    // Update status to error
    await pool.query(
      'UPDATE projects SET status = $1 WHERE id = $2',
      ['error', projectId]
    );
  }
}

// Catalog files function
async function catalogFiles(projectId, extractPath) {
  const files = [];

  function scanDirectory(dirPath, relativePath = '') {
    const items = fs.readdirSync(dirPath);

    for (const item of items) {
      const fullPath = path.join(dirPath, item);
      const itemRelativePath = path.join(relativePath, item).replace(/\\/g, '/');
      const stats = fs.statSync(fullPath);

      if (stats.isDirectory()) {
        console.log(`Cataloging directory: ${itemRelativePath} (Full path: ${fullPath})`);
        files.push({
          project_id: projectId,
          relative_path: itemRelativePath,
          is_directory: true,
          size: null,
          mime_type: null
        });
        
        // Recursively scan subdirectory
        scanDirectory(fullPath, itemRelativePath);
      } else {
        console.log(`Cataloging file: ${itemRelativePath} (Full path: ${fullPath})`);
        const mimeType = mime.lookup(fullPath) || 'application/octet-stream';
        files.push({
          project_id: projectId,
          relative_path: itemRelativePath,
          is_directory: false,
          size: stats.size,
          mime_type: mimeType
        });
      }
    }
  }

  scanDirectory(extractPath);

  // Insert all files into database
  for (const file of files) {
    await pool.query(
      'INSERT INTO project_files (project_id, relative_path, is_directory, size, mime_type) VALUES ($1, $2, $3, $4, $5)',
      [file.project_id, file.relative_path, file.is_directory, file.size, file.mime_type]
    );
  }
}

// CODE EXECUTION ROUTE
app.post('/api/code/run', [
  body('code').notEmpty(),
  body('language').isIn(['javascript', 'python', 'java', 'cpp', 'c', 'typescript'])
], authenticateToken, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { code, language, input } = req.body;
    
    const result = await executeCode(code, language, input);
    res.json(result);
  } catch (error) {
    console.error('Code execution error:', error);
    res.status(500).json({ error: 'Failed to execute code' });
  }
});


// SHARE ROUTES
// Generate Share Token
app.post('/api/share/generate', [
  body('fileId').isUUID().withMessage('Invalid file ID'),
  body('permission').isIn(['read', 'write']).withMessage('Invalid permission'),
  body('expiresIn').optional().isString().withMessage('ExpiresIn must be a string (e.g., "1h", "7d")')
], authenticateToken, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { fileId, permission, expiresIn } = req.body;

    // Verify user owns the file
    const fileCheck = await pool.query(
      'SELECT id, owner_id FROM files WHERE id = $1 AND owner_id = $2',
      [fileId, req.user.id]
    );

    if (fileCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied or file not found' });
    }

    // Generate a unique 64-character hex token (32 bytes)
    const shareToken = crypto.randomBytes(32).toString('hex');

    let expiresAt = null;
    if (expiresIn) {
      // Basic parsing for expiresIn (e.g., "1h", "7d")
      const duration = parseInt(expiresIn);
      const unit = expiresIn.slice(-1);
      let ms = 0;
      if (unit === 'h') ms = duration * 60 * 60 * 1000;
      else if (unit === 'd') ms = duration * 24 * 60 * 60 * 1000;
      else if (unit === 'm') ms = duration * 60 * 1000; // minutes
      else if (unit === 's') ms = duration * 1000; // seconds
      
      if (ms > 0) {
        expiresAt = new Date(Date.now() + ms);
      }
    }

    const result = await pool.query(
      'INSERT INTO codespace_share (file_id, owner_id, token, permission, expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING token',
      [fileId, req.user.id, shareToken, permission, expiresAt]
    );

      // use your FRONTEND_URL env var so the link is valid
    const fullShareUrl = `${process.env.FRONTEND_URL}/share?token=${result.rows[0].token}`;

   // return both token and shareUrl
   res.status(201).json({
     token: result.rows[0].token,
     shareUrl: fullShareUrl
   });
  } catch (error) {
    console.error('Error generating share token:', error);
    res.status(500).json({ error: 'Failed to generate share token' });
  }
});

// Access Share Token
app.post('/api/share/access', [
  body('token').notEmpty().withMessage('Share token is required')
], authenticateToken, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { token } = req.body;

    const shareRecord = await pool.query(
      'SELECT file_id, permission, expires_at FROM codespace_share WHERE token = $1',
      [token]
    );

    if (shareRecord.rows.length === 0) {
      return res.status(404).json({ error: 'Invalid or expired share token' });
    }

    const { file_id, permission, expires_at } = shareRecord.rows[0];

    if (expires_at && new Date() > new Date(expires_at)) {
      return res.status(403).json({ error: 'Share token has expired' });
    }

    // Grant access to the user in the user_files table
    await pool.query(
      'INSERT INTO user_files (user_id, file_id, permission) VALUES ($1, $2, $3) ON CONFLICT (user_id, file_id) DO UPDATE SET permission = $3',
      [req.user.id, file_id, permission]
    );

    res.json({ message: 'Access granted', fileId: file_id, permission });
  } catch (error) {
    console.error('Error accessing share token:', error);
    res.status(500).json({ error: 'Failed to access share token' });
  }
});


// DOCUMENT ROUTES (Projects)
// Get all documents for user
app.get('/api/documents', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '' } = req.query;
    const offset = (page - 1) * limit;

    let query = `
      SELECT f.*, u.name as owner_name, uf.permission
      FROM files f
      LEFT JOIN users u ON f.owner_id = u.id
      LEFT JOIN user_files uf ON f.id = uf.file_id AND uf.user_id = $1 -- Existing user_files for direct collaboration
      WHERE (f.owner_id = $1 OR uf.user_id = $1) AND f.type = 'document'
    `;
    
    const params = [req.user.id];

    if (search) {
      query += ` AND f.name ILIKE $${params.length + 1}`;
      params.push(`%${search}%`);
    }

    query += ` ORDER BY f.updated_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    // Transform files to document format
    const documents = result.rows.map(row => ({
      id: row.id,
      title: row.name,
      content: '', // Content will be loaded separately
      created_at: row.created_at,
      updated_at: row.updated_at,
      owner_name: row.owner_name,
      permission: row.permission || 'admin'
    }));

    res.json({
      documents,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: result.rows.length
      }
    });
  } catch (error) {
    console.error('Error fetching documents:', error);
    res.status(500).json({ error: 'Failed to fetch documents' });
  }
});

// Get single document
app.get('/api/documents/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(`
      SELECT f.*, u.name as owner_name,
             CASE 
               WHEN f.owner_id = $2 THEN 'admin'
               ELSE COALESCE(uf.permission, 'none') -- Existing user_files for direct collaboration
             END as permission
      FROM files f
      LEFT JOIN users u ON f.owner_id = u.id
      LEFT JOIN user_files uf ON f.id = uf.file_id AND uf.user_id = $2
      WHERE f.id = $1 AND (
        f.owner_id = $2 OR 
        uf.user_id = $2
      )
    `, [id, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const file = result.rows[0];

    // Get document content from Supabase
    let content = '';
    try {
      const { data, error } = await supabase.storage
        .from(process.env.SUPABASE_BUCKET)
        .download(file.storage_path);

      if (!error && data) {
        content = await data.text();
      }
    } catch (storageError) {
      console.error('Error fetching content:', storageError);
    }

    // Get collaborators
    const collaborators = await pool.query(`
      SELECT u.id, u.email, u.name, uf.permission
      FROM user_files uf
      JOIN users u ON uf.user_id = u.id
      WHERE uf.file_id = $1 AND uf.user_id != $2
    `, [id, file.owner_id]);

    const document = {
      id: file.id,
      title: file.name,
      content,
      created_at: file.created_at,
      updated_at: file.updated_at,
      owner_name: file.owner_name,
      permission: file.permission,
      collaborators: collaborators.rows
    };

    res.json(document);
  } catch (error) {
    console.error('Error fetching document:', error);
    res.status(500).json({ error: 'Failed to fetch document' });
  }
});

// Create new document
app.post('/api/documents', [
  body('title').optional().trim(),
  body('content').optional()
], authenticateToken, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { title = 'Untitled Project', content = '' } = req.body;
    const fileName = `${title.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.js`;
    const storagePath = `projects/${req.user.id}/${fileName}`;

    // Upload content to Supabase
    const { error: uploadError } = await supabase.storage
      .from(process.env.SUPABASE_BUCKET)
      .upload(storagePath, content, {
        contentType: 'text/plain'
      });

    if (uploadError) {
      throw uploadError;
    }

    // Create file record
    const result = await pool.query(
      'INSERT INTO files (name, type, size, storage_path, owner_id, encrypted) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [title, 'document', content.length, storagePath, req.user.id, false]
    );

    const file = result.rows[0];

    // Create initial version
    await pool.query(
      'INSERT INTO document_versions (file_id, content, version_number, created_by) VALUES ($1, $2, $3, $4)',
      [file.id, content, 1, req.user.id]
    );

    const document = {
      id: file.id,
      title: file.name,
      content,
      created_at: file.created_at,
      updated_at: file.updated_at
    };

    res.status(201).json(document);
  } catch (error) {
    console.error('Error creating document:', error);
    res.status(500).json({ error: 'Failed to create document' });
  }
});

// Update document
app.put('/api/documents/:id', [
  body('title').optional().trim(),
  body('content').optional()
], authenticateToken, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { id } = req.params;
    const { title, content } = req.body;

    // Check permissions
    const permissionCheck = await pool.query(`
      SELECT f.owner_id, f.storage_path, uf.permission
      FROM files f
      LEFT JOIN user_files uf ON f.id = uf.file_id AND uf.user_id = $2
      WHERE f.id = $1
    `, [id, req.user.id]);

    if (permissionCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const file = permissionCheck.rows[0];
    const isOwner = file.owner_id === req.user.id;
    const hasWritePermission = file.permission === 'write';

    if (!isOwner && !hasWritePermission) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    // Update file record
    const updateFields = [];
    const updateValues = [];
    let paramCount = 1;

    if (title !== undefined) {
      updateFields.push(`name = $${paramCount++}`);
      updateValues.push(title);
    }

    if (content !== undefined) {
      updateFields.push(`size = $${paramCount++}`);
      updateValues.push(content.length);
    }

    updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
    updateValues.push(id);

    const result = await pool.query(
      `UPDATE files SET ${updateFields.join(', ')} WHERE id = $${paramCount} RETURNING *`,
      updateValues
    );

    // Update content in Supabase if provided
    if (content !== undefined) {
      const { error: updateError } = await supabase.storage
        .from(process.env.SUPABASE_BUCKET)
        .update(file.storage_path, content, {
          contentType: 'text/plain'
        });

      if (updateError) {
        throw updateError;
      }

      // Create new version
      const versionResult = await pool.query(
        'SELECT COALESCE(MAX(version_number), 0) + 1 as next_version FROM document_versions WHERE file_id = $1',
        [id]
      );

      await pool.query(
        'INSERT INTO document_versions (file_id, content, version_number, created_by) VALUES ($1, $2, $3, $4)',
        [id, content, versionResult.rows[0].next_version, req.user.id]
      );
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating document:', error);
    res.status(500).json({ error: 'Failed to update document' });
  }
});

// Delete document
app.delete('/api/documents/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Get file info and check ownership/access
    const fileResult = await pool.query(
      'SELECT f.owner_id, f.storage_path FROM files f WHERE f.id = $1',
      [id]
    );

    if (fileResult.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const file = fileResult.rows[0];


    if (file.owner_id !== req.user.id) {
      // If not owner, check if user has access via user_files
      const userAccessCheck = await pool.query(
        'SELECT 1 FROM user_files WHERE user_id = $1 AND file_id = $2',
        [req.user.id, id]
      );
      if (userAccessCheck.rows.length === 0) {
        return res.status(403).json({ error: 'Insufficient permissions to delete this document' });
      }
      // If user has access but is not owner, only remove their access
      await pool.query('DELETE FROM user_files WHERE user_id = $1 AND file_id = $2', [req.user.id, id]);
      return res.json({ message: 'Access to document removed successfully' });
    }

    // If owner, proceed with full deletion
    // Delete associated share tokens
    await pool.query('DELETE FROM codespace_share WHERE file_id = $1', [id]);

    // Delete user_files entries for this document
    await pool.query('DELETE FROM user_files WHERE file_id = $1', [id]);

  
    // Delete from Supabase storage
    await supabase.storage
      .from(process.env.SUPABASE_BUCKET)
      .remove([file.storage_path]);

    // Delete file record (cascades to user_files and document_versions)
    await pool.query('DELETE FROM files WHERE id = $1', [id]);

    res.json({ message: 'Document deleted successfully' });
  } catch (error) {
    console.error('Error deleting document:', error);
    res.status(500).json({ error: 'Failed to delete document' });
  }
});

// Share document
app.post('/api/documents/:id/share', [
  body('email').isEmail().normalizeEmail(),
  body('permission').isIn(['read', 'write'])
], authenticateToken, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { id } = req.params;
    const { email, permission } = req.body;

    // Check if user owns the document
    const docResult = await pool.query(
      'SELECT * FROM files WHERE id = $1 AND owner_id = $2',
      [id, req.user.id]
    );

    if (docResult.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found or insufficient permissions' });
    }

    // Find user to share with
    const userResult = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const collaboratorId = userResult.rows[0].id;

    // Add or update collaborator
    await pool.query(`
      INSERT INTO user_files (user_id, file_id, permission)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id, file_id)
      DO UPDATE SET permission = $3, created_at = CURRENT_TIMESTAMP
    `, [collaboratorId, id, permission]);

    res.json({ message: 'Document shared successfully' });
  } catch (error) {
    console.error('Error sharing document:', error);
    res.status(500).json({ error: 'Failed to share document' });
  }
});

// Get document versions
app.get('/api/documents/:id/versions', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Check permissions
    const permissionCheck = await pool.query(`
      SELECT f.owner_id, uf.permission
      FROM files f
      LEFT JOIN user_files uf ON f.id = uf.file_id AND uf.user_id = $2
      WHERE f.id = $1
    `, [id, req.user.id]);

    if (permissionCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const result = await pool.query(`
      SELECT dv.*, u.name as created_by_name
      FROM document_versions dv
      JOIN users u ON dv.created_by = u.id
      WHERE dv.file_id = $1
      ORDER BY dv.version_number DESC
    `, [id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching document versions:', error);
    res.status(500).json({ error: 'Failed to fetch document versions' });
  }
});

// SOCKET.IO SETUP
const activeUsers = new Map();
const documentRooms = new Map();

 io.use(async (socket, next) => {
   try {
     const token = socket.handshake.auth.token;
     if (!token) {
       return next(new Error('Authentication error: Token not provided'));
     }

     const decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
     // payload might have "id" (from login) or "userId" (if you ever switch)
     const userId = decoded.id || decoded.userId;

     const result = await pool.query(
       'SELECT id, email, name FROM users WHERE id = $1',
       [userId]
     );

    if (result.rows.length === 0) {
      return next(new Error('User not found'));
    }

    socket.user = result.rows[0];
    next();
  } catch (err) {
    console.error('Socket authentication error:', err);
    next(new Error('Authentication error: Invalid or expired token'));
  }
});

io.on('connection', (socket) => {
  console.log(`User ${socket.user.email} connected`);

  socket.on('join-document', async (documentId) => {
    try {
      // Verify user has access to document
      const accessCheck = await pool.query(`
        SELECT f.id
        FROM files f
        LEFT JOIN user_files uf ON f.id = uf.file_id AND uf.user_id = $2
        WHERE f.id = $1 AND (f.owner_id = $2 OR uf.user_id = $2)
      `, [documentId, socket.user.id]);

      if (accessCheck.rows.length === 0) {
        socket.emit('error', { message: 'Access denied to document' });
        return;
      }

      const previousRoom = documentRooms.get(socket.id);
      if (previousRoom) {
        socket.leave(previousRoom);
        removeUserFromDocument(previousRoom, socket.user.id);
      }

      socket.join(documentId);
      documentRooms.set(socket.id, documentId);

      if (!activeUsers.has(documentId)) {
        activeUsers.set(documentId, new Set());
      }
      activeUsers.get(documentId).add({
        id: socket.user.id,
        email: socket.user.email,
        fullName: socket.user.name,
        socketId: socket.id
      });

      socket.to(documentId).emit('user-joined', {
        user: {
          id: socket.user.id,
          email: socket.user.email,
          fullName: socket.user.name
        }
      });

      const currentUsers = Array.from(activeUsers.get(documentId) || [])
        .filter(user => user.id !== socket.user.id);
      socket.emit('active-users', currentUsers);

      console.log(`User ${socket.user.email} joined document ${documentId}`);
    } catch (error) {
      console.error('Error joining document:', error);
      socket.emit('error', { message: 'Failed to join document' });
    }
  });

  socket.on('document-change', async (data) => {
    const documentId = documentRooms.get(socket.id);
    if (!documentId) return;

    try {
      const permissionCheck = await pool.query(`
        SELECT f.owner_id, uf.permission
        FROM files f
        LEFT JOIN user_files uf ON f.id = uf.file_id AND uf.user_id = $2
        WHERE f.id = $1
      `, [documentId, socket.user.id]);

      if (permissionCheck.rows.length === 0) {
        socket.emit('error', { message: 'Document not found' });
        return;
      }

      const file = permissionCheck.rows[0];
      const isOwner = file.owner_id === socket.user.id;
      const hasWritePermission = file.permission === 'write';

      if (!isOwner && !hasWritePermission) {
        socket.emit('error', { message: 'Insufficient permissions to edit' });
        return;
      }

      socket.to(documentId).emit('document-change', {
        ...data,
        userId: socket.user.id,
        timestamp: new Date().toISOString()
      });

      if (data.autoSave) {
        // Get storage path
        const fileResult = await pool.query(
          'SELECT storage_path FROM files WHERE id = $1',
          [documentId]
        );

        if (fileResult.rows.length > 0) {
          const storagePath = fileResult.rows[0].storage_path;
          
          // Update content in Supabase
          await supabase.storage
            .from(process.env.SUPABASE_BUCKET)
            .update(storagePath, data.content, {
              contentType: 'text/plain'
            });

          // Update file record
          await pool.query(
            'UPDATE files SET size = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
            [data.content.length, documentId]
          );
        }
      }
    } catch (error) {
      console.error('Error handling document change:', error);
      socket.emit('error', { message: 'Failed to process document change' });
    }
  });

  socket.on('cursor-position', (data) => {
    const documentId = documentRooms.get(socket.id);
    if (!documentId) return;

    socket.to(documentId).emit('cursor-position', {
      ...data,
      userId: socket.user.id,
      user: {
        id: socket.user.id,
        fullName: socket.user.name
      }
    });
  });

  socket.on('selection-change', (data) => {
    const documentId = documentRooms.get(socket.id);
    if (!documentId) return;

    socket.to(documentId).emit('selection-change', {
      ...data,
      userId: socket.user.id,
      user: {
        id: socket.user.id,
        fullName: socket.user.name
      }
    });
  });

  socket.on('disconnect', () => {
    const documentId = documentRooms.get(socket.id);
    if (documentId) {
      removeUserFromDocument(documentId, socket.user.id);
      socket.to(documentId).emit('user-left', {
        userId: socket.user.id
      });
      documentRooms.delete(socket.id);
    }
    console.log(`User ${socket.user.email} disconnected`);
  });
});

function removeUserFromDocument(documentId, userId) {
  const users = activeUsers.get(documentId);
  if (users) {
    const userArray = Array.from(users);
    const updatedUsers = userArray.filter(user => user.id !== userId);
    
    if (updatedUsers.length === 0) {
      activeUsers.delete(documentId);
    } else {
      activeUsers.set(documentId, new Set(updatedUsers));
    }
  }
}

// Error handling middleware
app.use(errorHandler);

app.use('/api/github', githubRouter);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Initialize database and start server
async function startServer() {
  try {
    await initializeDatabase();
    console.log('Database initialized successfully');
    
    server.listen(PORT, () => {
      console.log(`CodeSpace server running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// make your auth middleware available to other modules:
export { authenticateToken, pool };

startServer();
