// server/routes/codespaceShare.js
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const pool = require('../db');
const auth = require('../middleware/auth');
const emailService = require('../emailService');

// Generate share token
router.post('/generate', auth, async (req, res) => {
  try {
    const { fileId, permission = 'read', expiresIn } = req.body;
    const userId = req.user.id;

    // Verify user owns the file or has access to it
    const fileCheck = await pool.query(
      'SELECT * FROM files WHERE id = $1 AND owner_id = $2',
      [fileId, userId]
    );

    if (fileCheck.rows.length === 0) {
      return res.status(404).json({ error: 'File not found or access denied' });
    }

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
      `INSERT INTO codespace_share (file_id, owner_id, token, permission, expires_at) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING *`,
      [fileId, userId, token, permission, expiresAt]
    );

    res.json({
      success: true,
      token: token,
      shareUrl: `${process.env.FRONTEND_URL}/share?token=${token}`,
      permission: permission,
      expiresAt: expiresAt
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
      `SELECT cs.*, f.name as file_name, f.type as file_type, u.name as owner_name
       FROM codespace_share cs
       JOIN files f ON cs.file_id = f.id
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

    // Grant access to the user (add to user_files if not already present)
    await pool.query(
      `INSERT INTO user_files (user_id, file_id, permission) 
       VALUES ($1, $2, $3) 
       ON CONFLICT (user_id, file_id) 
       DO UPDATE SET permission = EXCLUDED.permission`,
      [userId, share.file_id, share.permission]
    );

    res.json({
      success: true,
      fileId: share.file_id,
      fileName: share.file_name,
      fileType: share.file_type,
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
    const { recipientEmail, shareUrl, fileName, permission, message, expiresIn } = req.body;
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

    // Send email
    await emailService.sendShareEmail({
      recipientEmail,
      shareUrl,
      fileName,
      permission,
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

    const sharesResult = await pool.query(
      `SELECT cs.*, f.name as file_name, f.type as file_type
       FROM codespace_share cs
       JOIN files f ON cs.file_id = f.id
       WHERE cs.owner_id = $1
       ORDER BY cs.created_at DESC`,
      [userId]
    );

    res.json({
      success: true,
      shares: sharesResult.rows
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
