import express from 'express';
import { createHmac, timingSafeEqual } from 'crypto';
import { json } from 'body-parser';
import { post } from 'axios';
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(json());

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
  const computedHash = createHmac('sha256', APP_SECRET)
                                   .update(data)
                                   .digest('base64');

  return timingSafeEqual(
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

  try {
    const tokenResponse = await post('https://api.tiendanube.com/v1/oauth/token', {
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      code,
      grant_type: 'authorization_code'
    });

    const { access_token, refresh_token, user_id } = tokenResponse.data;

    // Salvar tokens e user_id (ex.: no banco ou memória)
    storeAuthData[user_id] = {
      access_token,
      refresh_token,
      store_id: user_id
    };

    console.log('Autenticado para loja ID:', user_id);

    res.send(`
      <h1>Autenticado com sucesso!</h1>
      <p>Loja ID: ${user_id}</p>
      <p>Access Token: ${access_token}</p>
      <hr />
      <a href="/register-webhooks">Clique aqui para registrar webhooks obrigatórios</a>
    `);
  } catch (error) {
    console.error('Erro na autenticação:', error.response?.data || error.message);
    res.status(500).send('Erro na autenticação');
  }
});

// === Registrar webhooks obrigatórios (LGPD) ===
app.get('/register-webhooks', async (req, res) => {
  const storeId = Object.keys(storeAuthData)[0];
  const accessToken = storeAuthData[storeId].access_token;
  const webhookBaseUrl = 'https://seuapp.com/webhooks';

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
      const response = await post(
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