const express = require('express');
const bodyParser = require('body-parser');
const compression = require('compression');
const helmet = require('helmet');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const https = require('https');
const cluster = require('cluster');
const os = require('os');

const IP_LIMIT = 5;
const BLOCK_TIME = 60000; // 1 dakika
const ipRequests = {};

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent');

  if (ipRequests[ip]) {
    ipRequests[ip].count += 1;
    ipRequests[ip].userAgents.add(userAgent);

    if (ipRequests[ip].count > IP_LIMIT) {
      ipRequests[ip].blockedUntil = Date.now() + BLOCK_TIME;
      return res.redirect('/blocked-user.html');
    }
  } else {
    ipRequests[ip] = {
      count: 1,
      userAgents: new Set([userAgent]),
      blockedUntil: 0,
    };
  }

  next();
});

app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;

  if (ipRequests[ip].blockedUntil > Date.now()) {
    return res.redirect('/blocked-user.html');
  }

  next();
});

app.use(async (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;

  try {
    const torCheckResponse = await axios.get(`https://check.torproject.org/torbulkexitlist?ip=${ip}`);

    if (torCheckResponse.data && torCheckResponse.data.includes(ip)) {
      return res.redirect('/tor-blocked.html');
    }
  } catch (error) {
    console.error('Tor check failed:', error);
  }

  next();
});

app.use(helmet());
app.use(cors());
app.use(compression());

app.get('/', (req, res) => {
  res.send('Ana Sayfa');
});

app.get('/blocked-user.html', (req, res) => {
  res.send('Engellenen Kullanıcı Sayfası');
});

app.get('/tor-blocked.html', (req, res) => {
  res.send('Tor Ağından Gelen İstekler Engellendi');
});

const privateKey = fs.readFileSync('/path/to/private-key.pem', 'utf8');
const certificate = fs.readFileSync('/path/to/certificate.pem', 'utf8');
const credentials = { key: privateKey, cert: certificate };

if (cluster.isMaster) {
  for (let i = 0; i < os.cpus().length; i++) {
    cluster.fork();
  }
} else {
  const port = 443; // HTTPS için 443 portu
  const httpsServer = https.createServer(credentials, app);

  httpsServer.listen(port, () => {
    console.log(`Sunucu ${port} portunda çalışıyor (HTTPS)`);
  });
}


