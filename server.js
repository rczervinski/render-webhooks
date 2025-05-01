const express = require('express');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para parsear JSON
app.use(express.json());

// Validação HMAC (substitua pelo seu APP_SECRET)
const APP_SECRET = process.env.APP_SECRET;

function verifyWebhook(data, hmacHeader) {
  const hash = crypto.createHmac('sha256', APP_SECRET)
                     .update(data)
                     .digest('base64');
  return hash === hmacHeader;
}

// Endpoint do webhook
app.post('/webhook', (req, res) => {
  const hmacHeader = req.headers['x-linkedstore-hmac-sha256'];
  const data = JSON.stringify(req.body);

  if (!verifyWebhook(data, hmacHeader)) {
    return res.status(401).send('Invalid HMAC signature');
  }

  console.log('Webhook recebido:', req.body);
  res.status(200).send('OK');
});

// Rota de teste
app.get('/', (req, res) => {
  res.send('Webhook está funcionando!');
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});