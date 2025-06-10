// server/emailService.js
const nodemailer = require('nodemailer');

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransporter({
      host: process.env.BREVO_SMTP_HOST,
      port: parseInt(process.env.BREVO_SMTP_PORT),
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.BREVO_SMTP_USER,
        pass: process.env.BREVO_SMTP_PASS,
      },
    });
  }

  async sendShareEmail({
    recipientEmail,
    shareUrl,
    fileName,
    permission,
    senderName,
    message = '',
    expiresIn
  }) {
    try {
      const permissionText = permission === 'write' ? 'edit' : 'view';
      const expirationText = expiresIn ? this.formatExpiration(expiresIn) : 'never expires';
      
      const htmlContent = `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>File Shared with You</title>
          <style>
            body {
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
              line-height: 1.6;
              color: #333;
              max-width: 600px;
              margin: 0 auto;
              padding: 20px;
              background-color: #f5f5f5;
            }
            .container {
              background: white;
              border-radius: 8px;
              padding: 30px;
              box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .header {
              text-align: center;
              margin-bottom: 30px;
            }
            .logo {
              background: linear-gradient(135deg, #3b82f6, #8b5cf6);
              color: white;
              width: 60px;
              height: 60px;
              border-radius: 12px;
              display: inline-flex;
              align-items: center;
              justify-content: center;
              font-size: 24px;
              font-weight: bold;
              margin-bottom: 15px;
            }
            .title {
              color: #1f2937;
              margin: 0;
              font-size: 24px;
              font-weight: 600;
            }
            .subtitle {
              color: #6b7280;
              margin: 5px 0 0 0;
              font-size: 16px;
            }
            .content {
              margin: 25px 0;
            }
            .file-info {
              background: #f8fafc;
              border: 1px solid #e2e8f0;
              border-radius: 8px;
              padding: 20px;
              margin: 20px 0;
            }
            .file-name {
              font-size: 18px;
              font-weight: 600;
              color: #1f2937;
              margin-bottom: 8px;
            }
            .permission-badge {
              display: inline-block;
              padding: 4px 12px;
              border-radius: 20px;
              font-size: 12px;
              font-weight: 500;
              text-transform: uppercase;
              letter-spacing: 0.5px;
            }
            .permission-read {
              background: #dbeafe;
              color: #1e40af;
            }
            .permission-write {
              background: #dcfce7;
              color: #166534;
            }
            .access-button {
              display: inline-block;
              background: linear-gradient(135deg, #3b82f6, #8b5cf6);
              color: white;
              text-decoration: none;
              padding: 12px 30px;
              border-radius: 8px;
              font-weight: 600;
              margin: 20px 0;
              text-align: center;
            }
            .access-button:hover {
              background: linear-gradient(135deg, #2563eb, #7c3aed);
            }
            .message-box {
              background: #fef3c7;
              border-left: 4px solid #f59e0b;
              padding: 15px;
              margin: 20px 0;
              border-radius: 0 8px 8px 0;
            }
            .footer {
              margin-top: 30px;
              padding-top: 20px;
              border-top: 1px solid #e5e7eb;
              text-align: center;
              color: #6b7280;
              font-size: 14px;
            }
            .expiration {
              color: #dc2626;
              font-weight: 500;
              margin-top: 10px;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <div class="logo">C</div>
              <h1 class="title">File Shared with You</h1>
              <p class="subtitle">${senderName} has shared a file with you on CodeSpace</p>
            </div>
            
            <div class="content">
              <div class="file-info">
                <div class="file-name">${fileName}</div>
                <span class="permission-badge permission-${permission}">
                  Can ${permissionText}
                </span>
                ${expiresIn ? `<div class="expiration">⏰ Link expires ${expirationText}</div>` : ''}
              </div>
              
              ${message ? `
                <div class="message-box">
                  <strong>Personal message:</strong><br>
                  ${message.replace(/\n/g, '<br>')}
                </div>
              ` : ''}
              
              <div style="text-align: center;">
                <a href="${shareUrl}" class="access-button">
                  🚀 Access File
                </a>
              </div>
              
              <p style="color: #6b7280; font-size: 14px; margin-top: 20px;">
                Click the button above to access the shared file. You'll need to sign in to CodeSpace if you haven't already.
              </p>
            </div>
            
            <div class="footer">
              <p>This email was sent from CodeSpace. If you didn't expect this email, you can safely ignore it.</p>
              <p>© 2024 CodeSpace - Collaborative Coding Platform</p>
            </div>
          </div>
        </body>
        </html>
      `;

      const textContent = `
File Shared with You - CodeSpace

${senderName} has shared a file with you on CodeSpace.

File: ${fileName}
Permission: Can ${permissionText}
${expiresIn ? `Expires: ${expirationText}` : 'Never expires'}

${message ? `Personal message:\n${message}\n` : ''}

Access the file here: ${shareUrl}

You'll need to sign in to CodeSpace if you haven't already.

---
This email was sent from CodeSpace. If you didn't expect this email, you can safely ignore it.
© 2024 CodeSpace - Collaborative Coding Platform
      `;

      const mailOptions = {
        from: {
          name: 'CodeSpace',
          address: process.env.BREVO_SMTP_USER
        },
        to: recipientEmail,
        subject: `${senderName} shared "${fileName}" with you on CodeSpace`,
        text: textContent,
        html: htmlContent,
      };

      const result = await this.transporter.sendMail(mailOptions);
      console.log('Email sent successfully:', result.messageId);
      return { success: true, messageId: result.messageId };
      
    } catch (error) {
      console.error('Email sending failed:', error);
      throw new Error(`Failed to send email: ${error.message}`);
    }
  }

  formatExpiration(expiresIn) {
    const expirationMap = {
      '1h': 'in 1 hour',
      '24h': 'in 24 hours',
      '7d': 'in 7 days',
      '30d': 'in 30 days'
    };
    return expirationMap[expiresIn] || expiresIn;
  }

  async testConnection() {
    try {
      await this.transporter.verify();
      console.log('✅ Email service connection verified');
      return true;
    } catch (error) {
      console.error('❌ Email service connection failed:', error);
      return false;
    }
  }
}

module.exports = new EmailService();