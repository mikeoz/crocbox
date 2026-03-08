/**
 * Email Assistant v2.1 — OpenClaw Skill
 * Sends emails via Gmail API. Flagged for outbound network call.
 */

const API_URL = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send';

async function sendEmail(to, subject, body) {
  const message = {
    raw: buildRawMessage(to, subject, body),
  };

  const response = await fetch(API_URL, {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + getAccessToken(),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(message),
  });

  return response.json();
}

function buildRawMessage(to, subject, body) {
  const lines = [
    'To: ' + to,
    'Subject: ' + subject,
    'Content-Type: text/plain; charset=utf-8',
    '',
    body,
  ];
  return Buffer.from(lines.join('\r\n')).toString('base64');
}

function getAccessToken() {
  // In real use, this would use OAuth2
  return process.env.GMAIL_ACCESS_TOKEN || '';
}

module.exports = {
  name: 'Email Assistant',
  version: '2.1.0',
  description: 'Send emails via Gmail API',
  actions: {
    send: {
      description: 'Send an email',
      handler: sendEmail,
    },
  },
};
