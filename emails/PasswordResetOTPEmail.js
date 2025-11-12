function PasswordResetOTPEmail(otp) {
  return `
  <!DOCTYPE html>
  <html>
  <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Reset Your Password - Mimaht</title>
      <style>
          body {
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
              background-color: #f8fafc;
              margin: 0;
              padding: 0;
              line-height: 1.6;
          }
          .container {
              max-width: 600px;
              margin: 0 auto;
              background: white;
              border-radius: 12px;
              overflow: hidden;
              box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
          }
          .header {
              background: linear-gradient(135deg, #dc2626, #ef4444);
              padding: 40px 20px;
              text-align: center;
              color: white;
          }
          .logo {
              font-size: 32px;
              font-weight: bold;
              margin-bottom: 10px;
          }
          .content {
              padding: 40px;
          }
          .otp-code {
              font-size: 48px;
              font-weight: bold;
              text-align: center;
              letter-spacing: 12px;
              margin: 40px 0;
              color: #dc2626;
              background: #fef2f2;
              padding: 30px;
              border-radius: 12px;
              border: 2px dashed #fecaca;
              font-family: 'Courier New', monospace;
          }
          .footer {
              background: #f8fafc;
              padding: 30px;
              text-align: center;
              color: #64748b;
              font-size: 14px;
              border-top: 1px solid #e2e8f0;
          }
          .security-alert {
              background: #fef2f2;
              border: 1px solid #fecaca;
              border-radius: 8px;
              padding: 16px;
              margin: 20px 0;
              color: #dc2626;
          }
          .instructions {
              background: #f0f9ff;
              border: 1px solid #7dd3fc;
              border-radius: 8px;
              padding: 16px;
              margin: 20px 0;
              color: #0369a1;
          }
          @media (max-width: 600px) {
              .content { padding: 20px; }
              .otp-code { font-size: 36px; letter-spacing: 8px; padding: 20px; }
          }
      </style>
  </head>
  <body>
      <div class="container">
          <div class="header">
              <div class="logo">MIMAHT</div>
              <h1>Reset Your Password</h1>
          </div>
          
          <div class="content">
              <p>Hello,</p>
              
              <p>We received a request to reset your Mimaht account password. Use the verification code below to proceed:</p>
              
              <div class="otp-code">${otp}</div>
              
              <div class="instructions">
                  <strong>🔑 Password Reset Steps:</strong>
                  <ol>
                      <li>Enter this code in the password reset screen</li>
                      <li>Create a new secure password</li>
                      <li>Sign in with your new password</li>
                  </ol>
              </div>
              
              <div class="security-alert">
                  <strong>🚨 Security Alert:</strong>
                  <ul>
                      <li>This code will expire in <strong>10 minutes</strong></li>
                      <li>If you didn't request this password reset, secure your account immediately</li>
                      <li>Never share this code with anyone</li>
                  </ul>
              </div>
              
              <p>If you remember your password or didn't request this reset, you can safely ignore this email.</p>
              
              <p>Stay secure,<br><strong>The Mimaht Team</strong></p>
          </div>
          
          <div class="footer">
              <p>© 2024 Mimaht. All rights reserved.</p>
              <p>If you need help, contact us at <a href="mailto:support@mimaht.com" style="color: #dc2626;">support@mimaht.com</a></p>
          </div>
      </div>
  </body>
  </html>
  `;
}

module.exports = PasswordResetOTPEmail;
