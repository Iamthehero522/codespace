// server/routes/codespaceShare.js
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { pool } = require('../utils/db.js');
const { authenticateToken: auth } = require('../middleware/auth.js');
const emailService = require('../emailService');

// Generate share token
router.post('/generate', auth, async (req, res) => {
  try {
    const { resourceId, resourceType, permission = 'read', expiresIn } = req.body;
    const userId = req.user.id;

    // Verify user owns the resource or has access to it
    let resourceCheck;
    if (resourceType === 'file') {
      resourceCheck = await pool.query(
        'SELECT id, name, type FROM files WHERE id = $1 AND owner_id = $2',
        [resourceId, userId]
      );
    } else if (resourceType === 'project') {
      resourceCheck = await pool.query(
        'SELECT id, name, project_type FROM projects WHERE id = $1 AND owner_id = $2',
        [resourceId, userId]
      );
    } else {
      return res.status(400).json({ error: 'Invalid resource type' });
    }

    if (resourceCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Resource not found or access denied' });
    }

    const resourceName = resourceCheck.rows[0].name;

    // Generate unique token
    const token = uuidv4();
    
    // Calculate expiration date
    let expiresAt = null;
    if (expiresIn) {
      const now = new Date();
      switch (expiresIn) {
        case '1h':
          expiresAt = new Date(now.getTime() + 60 * 60 * 1000);
          break;
        case '24h':
          expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000);
          break;
        case '7d':
          expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
          break;
        case '30d':
          expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
          break;
        default:
          // Custom format like "2h", "5d", etc.
          const match = expiresIn.match(/^(\d+)([hd])$/);
          if (match) {
            const value = parseInt(match[1]);
            const unit = match[2];
            if (unit === 'h') {
              expiresAt = new Date(now.getTime() + value * 60 * 60 * 1000);
            } else if (unit === 'd') {
              expiresAt = new Date(now.getTime() + value * 24 * 60 * 60 * 1000);
            }
          }
      }
    }

    // Store share token in database
    const shareResult = await pool.query(
      `INSERT INTO codespace_share (resource_id, resource_type, owner_id, token, permission, expires_at) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING *`,
      [resourceId, resourceType, userId, token, permission, expiresAt]
    );

    res.json({
      success: true,
      token: token,
      shareUrl: `${process.env.FRONTEND_URL}/share?token=${token}`,
      permission: permission,
      expiresAt: expiresAt,
      resourceName: resourceName
    });

  } catch (error) {
    console.error('Error generating share token:', error);
    res.status(500).json({ error: 'Failed to generate share token' });
  }
});

// Access shared file via token
router.post('/access', auth, async (req, res) => {
  try {
    const { token } = req.body;
    const userId = req.user.id;

    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }

    // Find share record
    const shareResult = await pool.query(
      `SELECT cs.*, u.name as owner_name
       FROM codespace_share cs
       JOIN users u ON cs.owner_id = u.id
       WHERE cs.token = $1`,
      [token]
    );

    if (shareResult.rows.length === 0) {
      return res.status(404).json({ error: 'Invalid or expired share token' });
    }

    const share = shareResult.rows[0];

    // Check if token has expired
    if (share.expires_at && new Date() > new Date(share.expires_at)) {
      return res.status(410).json({ error: 'Share token has expired' });
    }

    let resourceDetails;
    if (share.resource_type === 'file') {
      resourceDetails = await pool.query(
        'SELECT id, name, type FROM files WHERE id = $1',
        [share.resource_id]
      );
      if (resourceDetails.rows.length === 0) {
        return res.status(404).json({ error: 'Shared file not found' });
      }
      // Grant access to the user (add to user_files if not already present)
      await pool.query(
        `INSERT INTO user_files (user_id, file_id, permission) 
         VALUES ($1, $2, $3) 
         ON CONFLICT (user_id, file_id) 
         DO UPDATE SET permission = EXCLUDED.permission`,
        [userId, share.resource_id, share.permission]
      );
    } else if (share.resource_type === 'project') {
      resourceDetails = await pool.query(
        'SELECT id, name, project_type FROM projects WHERE id = $1',
        [share.resource_id]
      );
      if (resourceDetails.rows.length === 0) {
        return res.status(404).json({ error: 'Shared project not found' });
      }
    } else {
      return res.status(400).json({ error: 'Unknown resource type in share record' });
    }

    res.json({
      success: true,
      resourceId: share.resource_id,
      resourceType: share.resource_type,
      resourceName: resourceDetails.rows[0].name,
      fileType: resourceDetails.rows[0].type, // Only for files
      projectType: resourceDetails.rows[0].project_type, // Only for projects
      permission: share.permission,
      ownerName: share.owner_name
    });

  } catch (error) {
    console.error('Error accessing share token:', error);
    res.status(500).json({ error: 'Failed to access shared file' });
  }
});

// Send share email
router.post('/send-email', auth, async (req, res) => {
  try {
    const { recipientEmail, shareToken, message, expiresIn } = req.body;
    const userId = req.user.id;

    // Get sender information
    const userResult = await pool.query(
      'SELECT name, email FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const sender = userResult.rows[0];

    // Retrieve share details from the token to get resource name and URL
    const shareDetailsResult = await pool.query(
      `SELECT cs.resource_id, cs.resource_type, cs.permission, cs.expires_at
       FROM codespace_share cs
       WHERE cs.token = $1`,
      [shareToken]
    );

    if (shareDetailsResult.rows.length === 0) {
      return res.status(404).json({ error: 'Share token not found' });
    }
    const shareDetails = shareDetailsResult.rows[0];

    let resourceName;
    if (shareDetails.resource_type === 'file') {
      const fileResult = await pool.query('SELECT name FROM files WHERE id = $1', [shareDetails.resource_id]);
      resourceName = fileResult.rows[0]?.name;
    } else if (shareDetails.resource_type === 'project') {
      const projectResult = await pool.query('SELECT name FROM projects WHERE id = $1', [shareDetails.resource_id]);
      resourceName = projectResult.rows[0]?.name;
    }

    if (!resourceName) {
      return res.status(404).json({ error: 'Shared resource name not found' });
    }

    const shareUrl = `${process.env.FRONTEND_URL}/share?token=${shareToken}`;

    // Send email
    await emailService.sendShareEmail({
      recipientEmail,
      shareUrl,
      fileName: resourceName,
      permission: shareDetails.permission,
      senderName: sender.name,
      message,
      expiresIn
    });

    res.json({
      success: true,
      message: 'Email sent successfully'
    });

  } catch (error) {
    console.error('Error sending share email:', error);
    res.status(500).json({ error: error.message || 'Failed to send email' });
  }
});

// List user's shared files
router.get('/my-shares', auth, async (req, res) => {
  try {
    const userId = req.user.id;

    // Fetch shares for files
    const fileSharesResult = await pool.query(
      `SELECT cs.*, f.name as resource_name, f.type as resource_type_detail
       FROM codespace_share cs
       JOIN files f ON cs.resource_id = f.id
       WHERE cs.owner_id = $1 AND cs.resource_type = 'file'
       ORDER BY cs.created_at DESC`,
      [userId]
    );

    // Fetch shares for projects
    const projectSharesResult = await pool.query(
      `SELECT cs.*, p.name as resource_name, p.project_type as resource_type_detail
       FROM codespace_share cs
       JOIN projects p ON cs.resource_id = p.id
       WHERE cs.owner_id = $1 AND cs.resource_type = 'project'
       ORDER BY cs.created_at DESC`,
      [userId]
    );

    res.json({
      success: true,
      shares: [...fileSharesResult.rows, ...projectSharesResult.rows]
    });

  } catch (error) {
    console.error('Error fetching user shares:', error);
    res.status(500).json({ error: 'Failed to fetch shares' });
  }
});

// Revoke share token
router.delete('/:token', auth, async (req, res) => {
  try {
    const { token } = req.params;
    const userId = req.user.id;

    const deleteResult = await pool.query(
      'DELETE FROM codespace_share WHERE token = $1 AND owner_id = $2 RETURNING *',
      [token, userId]
    );

    if (deleteResult.rows.length === 0) {
      return res.status(404).json({ error: 'Share token not found or access denied' });
    }

    res.json({
      success: true,
      message: 'Share token revoked successfully'
    });

  } catch (error) {
    console.error('Error revoking share token:', error);
    res.status(500).json({ error: 'Failed to revoke share token' });
  }
});

module.exports = router;