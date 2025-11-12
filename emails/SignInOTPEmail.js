function SignInOTPEmail(otp) {
  return `
  <!DOCTYPE html>
  <html>
  <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Sign In to Mimaht</title>
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
          .warning {
              background: #fffbeb;
              border: 1px solid #fcd34d;
              border-radius: 8px;
              padding: 16px;
              margin: 20px 0;
              color: #92400e;
          }
          .info {
              background: #eff6ff;
              border: 1px solid #93c5fd;
              border-radius: 8px;
              padding: 16px;
              margin: 20px 0;
              color: #1e40af;
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
              <h1>Sign In to Your Account</h1>
          </div>
          
          <div class="content">
              <p>Hello,</p>
              
              <p>To sign in to your Mimaht account, please use the verification code below:</p>
              
              <div class="otp-code">${otp}</div>
              
              <div class="info">
                  <strong>📱 Enter this code in the Mimaht app:</strong>
                  <p>Return to the Mimaht app and enter the 6-digit code above to complete your sign in.</p>
              </div>
              
              <div class="warning">
                  <strong>🔒 Security Notice:</strong>
                  <ul>
                      <li>This code will expire in <strong>10 minutes</strong></li>
                      <li>Never share this code with anyone</li>
                      <li>Mimaht will never ask for your verification code</li>
                  </ul>
              </div>
              
              <p>If you didn't request this sign in attempt, please secure your account immediately.</p>
              
              <p>Happy shopping!<br><strong>The Mimaht Team</strong></p>
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

module.exports = SignInOTPEmail;
