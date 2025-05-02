const express = require('express');
const cryptoNativo = require('crypto');
const bodyParser = require('body-parser');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());

// Variáveis do .env
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const APP_SECRET = process.env.APP_SECRET;

// Armazenamento temporário (use banco em produção)
let storeAuthData = {};

// === Função para validar HMAC ===
function verifyWebhook(data, hmacHeader) {
  if (!hmacHeader) return false;
  const computedHash = cryptoNativo.createHmac('sha256', APP_SECRET)
                                   .update(data)
                                   .digest('base64');

  return cryptoNativo.timingSafeEqual(
    Buffer.from(computedHash),
    Buffer.from(hmacHeader)
  );
}

// === Rota para autenticação OAuth ===
app.get('/auth/start', (req, res) => {
  const authUrl = `https://www.nuvemshop.com.br/apps/authorize?` +
    `client_id=${CLIENT_ID}&` +
    `redirect_uri=${REDIRECT_URI}&` +
    `scope=read_products write_products write_webhooks&` +
    `response_type=code`;

  res.redirect(authUrl);
});

// === Callback OAuth ===
app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;

  if (!code) {
    console.warn(' Código ausente:', req.query);
    return res.status(400).send('Código de autorização não encontrado');
  }

  console.log('📦 Code recebido:', code);

  try {
    const response = await axios.post(
      'https://www.nuvemshop.com.br/apps/authorize/token',

      {
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: process.env.REDIRECT_URI
      },
      {
        headers: {
          'Content-Type': 'application/json'
        }
      }
    );

    console.log('Token recebido:', response.data);

    storeAuthData[response.data.user_id] = response.data;

    res.send(`
      <h2>Autenticado com sucesso!</h2>
      <pre>${JSON.stringify(response.data, null, 2)}</pre>
      <a href="/register-webhooks">Registrar Webhooks</a>
    `);

  } catch (error) {
    console.error('Erro ao trocar code por token:', {
      status: error.response?.status,
      data: error.response?.data,
      message: error.message,
      url: error.config?.url,
      method: error.config?.method
    });

    res.status(error.response?.status || 500).send(`
      <h2>Erro na autenticação</h2>
      <p><strong>Status:</strong> ${error.response?.status || 'Desconhecido'}</p>
      <pre>${JSON.stringify({
        data: error.response?.data,
        config: {
          url: error.config.url,
          method: error.config.method,
          dataSent: error.config.data
        }
      }, null, 2)}</pre>
    `);
  }
});

// === Registrar webhooks obrigatórios (LGPD) ===
app.get('/register-webhooks', async (req, res) => {
  const storeId = Object.keys(storeAuthData)[0];
  const accessToken = storeAuthData[storeId].access_token;
  const webhookBaseUrl = 'https://render-webhooks.onrender.com/webhooks';

  const webhooks = [
    {
      event: 'store/redact',
      url: `${webhookBaseUrl}/store-redact`
    },
    {
      event: 'customers/redact',
      url: `${webhookBaseUrl}/customers-redact`
    },
    {
      event: 'customers/data_request',
      url: `${webhookBaseUrl}/customers-data-request`
    }
  ];

  for (const wh of webhooks) {
    try {
      const response = await axios.post(
        'https://api.tiendanube.com/v1/webhooks',
        wh,
        {
          headers: {
            'Authentication': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      console.log(`Webhook registrado: ${wh.event}`, response.data);
    } catch (error) {
      console.error(`Erro registrando webhook ${wh.event}:`, error.response?.data || error.message);
    }
  }

  res.send('Webhooks obrigatórios registrados!');
});

// === Webhooks LGPD ===
app.post('/webhooks/store-redact', (req, res) => {
  handleWebhook(req, res, 'store/redact');
});

app.post('/webhooks/customers-redact', (req, res) => {
  handleWebhook(req, res, 'customers/redact');
});

app.post('/webhooks/customers-data-request', (req, res) => {
  handleWebhook(req, res, 'customers/data_request');
});

function handleWebhook(req, res, label) {
  const hmacHeader = req.headers['x-linkedstore-hmac-sha256'];
  const data = JSON.stringify(req.body);

  if (!verifyWebhook(data, hmacHeader)) {
    console.warn(`HMAC inválido em ${label}`);
    return res.status(401).send('Invalid HMAC signature');
  }

  console.log(`${label} recebido:`, req.body);


  res.status(200).send('OK');
}

// === Iniciar servidor ===
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});