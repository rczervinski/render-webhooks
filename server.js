const express = require('express');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

const APP_SECRET = process.env.APP_SECRET;

function verifyWebhook(data, hmacHeader) {
  const hash = crypto.createHmac('sha256', APP_SECRET)
                     .update(data)
                     .digest('base64');
  return hash === hmacHeader;
}

function handleWebhook(req, res, label) {
  const hmacHeader = req.headers['x-linkedstore-hmac-sha256'];
  const data = JSON.stringify(req.body);

  if (!verifyWebhook(data, hmacHeader)) {
    console.warn(`HMAC inválido em ${label}`);
    return res.status(401).send('Invalid HMAC signature');
  }

  console.log(`${label} webhook recebido:`, req.body);
  res.status(200).send('OK');
}

// Webhook: store/redact
app.post('/webhooks/store-redact', (req, res) => {
  handleWebhook(req, res, 'store/redact');
});

// Webhook: customers/redact
app.post('/webhooks/customers-redact', (req, res) => {
  handleWebhook(req, res, 'customers/redact');
});

// Webhook: customers/data_request
app.post('/webhooks/customers-data-request', (req, res) => {
  handleWebhook(req, res, 'customers/data_request');
});

app.get('/', (req, res) => {
  res.send('Servidor de Webhooks da Nuvemshop está online!');
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
