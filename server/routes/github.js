//server/routes/github.js
import express from 'express';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import fsPromises from 'fs/promises';
import path from 'path';
import { execSync } from 'child_process';
import axios from 'axios';
import { authenticateToken as auth } from '../middleware/auth.js';
import { pool } from '../utils/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const router = express.Router();
// GET /api/github/repositories
// Fetch list of user repos from GitHub
router.get('/repositories', auth, async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) {
      return res.status(400).json({ error: 'GitHub token is required' });
    }

    const response = await axios.get('https://api.github.com/user/repos', {
      headers: {
        Authorization: `token ${token}`,
        Accept: 'application/vnd.github.v3+json'
      },
      params: { sort: 'updated', per_page: 100 }
    });

    res.json(response.data);
  } catch (err) {
    console.error('Error fetching GitHub repositories:', err);
    res.status(500).json({ error: 'Failed to fetch repositories' });
  }
});

// POST /api/github/import
// Create a project record and kick off cloning
router.post('/import', auth, async (req, res) => {
  try {
    const { repoUrl, repoName, description, githubToken, defaultBranch } = req.body;
    const userId = req.user.id;

    if (!repoUrl || !repoName || !githubToken) {
      return res.status(400).json({ error: 'repoUrl, repoName and githubToken are required' });
    }

    // Insert into your real projects table
    const { rows } = await pool.query(
      `INSERT INTO projects
         (owner_id, name, description, github_url, default_branch, github_token, status, project_type)
       VALUES ($1,$2,$3,$4,$5,$6,'cloning','github')
       RETURNING *`,
      [userId, repoName, description||'', repoUrl, defaultBranch||'main', githubToken]
    );
    const project = rows[0];

    // Clone in background (simple inline implementation)
    (async () => {
      // 1) Ensure base "projects" dir exists
      const projectsBase = path.join(__dirname, '..', 'projects');
      await fsPromises.mkdir(projectsBase, { recursive: true });

      // 2) Create this repo's extract folder
      const extractPath = path.join(projectsBase, project.id);
      await fsPromises.mkdir(extractPath, { recursive: true });

      try {
        // 3) Token‑injected clone URL
        const cloneUrl = repoUrl.replace(
          'https://github.com/',
          `https://${githubToken}@github.com/`
        );

        // 4) Perform the clone
        execSync(
          `git clone --branch ${project.default_branch || 'main'} "${cloneUrl}" "${extractPath}"`,
          { stdio: 'ignore' }
        );

        // 5) Mark project as ready
        await pool.query(
          'UPDATE projects SET extract_path=$1, status=$2 WHERE id=$3',
          [extractPath, 'ready', project.id]
        );
      } catch (err) {
        console.error('Error cloning:', err);
        await pool.query(
          'UPDATE projects SET status=$1 WHERE id=$2',
          ['error', project.id]
        );
      }
    })();

    res.json({ success: true, project: { id: project.id, name: project.name, status: project.status } });
  } catch (err) {
    console.error('Import error:', err);
    res.status(500).json({ 
      error: 'Failed to import repository',
      message: err.message,
      details: err.stack 
    });
  }
});

// GET /api/github/projects
router.get('/projects', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const page    = parseInt(req.query.page) || 1;
    const limit   = parseInt(req.query.limit) || 20;
    const offset  = (page - 1) * limit;

    const result = await pool.query(
      `SELECT p.*, COUNT(pf.id) AS file_count
         FROM projects p
         LEFT JOIN project_files pf ON p.id = pf.project_id
        WHERE p.owner_id = $1 AND p.project_type = 'github'
        GROUP BY p.id
        ORDER BY p.updated_at DESC
        LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );
    const count = await pool.query(
      'SELECT COUNT(*) FROM projects WHERE owner_id=$1 AND project_type=$2',
      [userId, 'github']
    );

    res.json({
      projects: result.rows,
      total: parseInt(count.rows[0].count,10),
      page, limit
    });
  } catch (err) {
    console.error('Error fetching projects:', err);
    res.status(500).json({ error: 'Failed to fetch GitHub projects' });
  }
});

// GET /api/github/projects/:id
router.get('/projects/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    const projRes = await pool.query(
      'SELECT * FROM projects WHERE id=$1 AND owner_id=$2',
      [id, userId]
    );
    if (projRes.rows.length === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }
    const project = projRes.rows[0];

    const filesRes = await pool.query(
      'SELECT * FROM project_files WHERE project_id=$1 ORDER BY relative_path',
      [id]
    );
    project.files = filesRes.rows;

    res.json(project);
  } catch (err) {
    console.error('Error fetching project:', err);
    res.status(500).json({ error: 'Failed to fetch GitHub project' });
  }
});

// GET /api/github/projects/:id/files/*
// Read a file from the cloned repo
router.get('/projects/:id/files/*', auth, async (req, res) => {
  try {
    const projectId = req.params.id;
    const filePath  = req.params[0];
    const userId    = req.user.id;

    // verify ownership
    const pr = await pool.query(
      'SELECT extract_path FROM projects WHERE id=$1 AND owner_id=$2',
      [projectId, userId]
    );
    if (!pr.rows.length) {
      return res.status(404).json({ error: 'Project not found' });
    }
    const extractPath = pr.rows[0].extract_path;
    const fullPath = path.join(extractPath, filePath);

    // security: path must start with extractPath
    if (!fullPath.startsWith(extractPath)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    try {
      const content = await fsPromises.readFile(fullPath, 'utf8');
      res.json({ content });
    } catch (fileErr) {
      console.error('File read error:', fileErr);
      res.status(404).json({ error: 'File not found' });
    }
  } catch (err) {
    console.error('Error getting file content:', err);
    res.status(500).json({ error: 'Failed to get file content' });
  }
});

// PUT /api/github/projects/:id/files/*
// Update a file in the cloned repo
router.put('/projects/:id/files/*', auth, async (req, res) => {
  try {
    const projectId = req.params.id;
    const filePath  = req.params[0];
    const { content } = req.body;
    const userId    = req.user.id;

    const pr = await pool.query(
      'SELECT extract_path FROM projects WHERE id=$1 AND owner_id=$2',
      [projectId, userId]
    );
    if (!pr.rows.length) {
      return res.status(404).json({ error: 'Project not found' });
    }
    const extractPath = pr.rows[0].extract_path;
    const fullPath = path.join(extractPath, filePath);

    if (!fullPath.startsWith(extractPath)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    await fsPromises.writeFile(fullPath, content, 'utf8');
    await pool.query(
      'UPDATE projects SET updated_at=CURRENT_TIMESTAMP WHERE id=$1',
      [projectId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Error updating file:', err);
    res.status(500).json({ error: 'Failed to update file' });
  }
});

// POST /api/github/projects/:id/commit
router.post('/projects/:id/commit', auth, async (req, res) => {
  try {
    const projectId = req.params.id;
    const { commitMessage, commitDescription, changedFiles } = req.body;
    const userId = req.user.id;

    // verify exists
    const pr = await pool.query(
      'SELECT extract_path, github_url, default_branch, github_token FROM projects WHERE id=$1 AND owner_id=$2',
      [projectId, userId]
    );
    if (!pr.rows.length) {
      return res.status(404).json({ error: 'Project not found' });
    }
    const project = pr.rows[0];
    const repoPath = project.extract_path;

    // write each changed file
    for (const f of changedFiles) {
      const full = path.join(repoPath, f.filePath);
      await fsPromises.writeFile(full, f.content, 'utf8');
      execSync(`git add "${f.filePath}"`, { cwd: repoPath });
    }

    // commit
    const msg = commitDescription
      ? `${commitMessage}\n\n${commitDescription}`
      : commitMessage;
    execSync(`git commit -m "${msg.replace(/"/g,'\\"')}"`, { cwd: repoPath });

    // push
    const tokenUrl = project.github_url.replace(
      'https://github.com/',
      `https://${project.github_token}@github.com/`
    );
    execSync(`git push "${tokenUrl}" ${project.default_branch}`, { cwd: repoPath });

    res.json({ success: true });
  } catch (err) {
    console.error('Error committing:', err);
    res.status(500).json({ error: 'Failed to commit changes' });
  }
});

// DELETE /api/github/projects/:id
router.delete('/projects/:id', auth, async (req, res) => {
  try {
    const projectId = req.params.id;
    const userId = req.user.id;

    const pr = await pool.query(
      'SELECT extract_path FROM projects WHERE id=$1 AND owner_id=$2',
      [projectId, userId]
    );
    if (!pr.rows.length) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const extractPath = pr.rows[0].extract_path;
    // remove files
    await fsPromises.rm(extractPath, { recursive: true, force: true });

    // delete DB record (cascades to project_files)
    await pool.query('DELETE FROM projects WHERE id=$1', [projectId]);

    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting project:', err);
    res.status(500).json({ error: 'Failed to delete project' });
  }
});

export default router;
