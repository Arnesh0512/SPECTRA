#!/usr/bin/env node
/**
 * Spectra Enterprise CBOM Visualizer Server
 * ========================================
 * High-performance local HTTP server delivering the interactive CycloneDX 1.6
 * Cryptographic Bill of Materials (CBOM) & Mosca Quantum Risk Dashboard.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

// Configuration
const DEFAULT_PORT = parseInt(process.env.PORT || '3000', 10);
const DEFAULT_CBOM_PATH = process.env.CBOM_PATH || path.resolve('C:/Users/Arnesh/Desktop/cbom.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

let activeCbomPath = DEFAULT_CBOM_PATH;
let inMemoryCbom = null;

// MIME types
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

function getCbomData() {
  if (inMemoryCbom) {
    return inMemoryCbom;
  }
  const candidatePaths = [
    activeCbomPath,
    path.resolve(process.cwd(), 'cbom.json'),
    path.resolve('C:/Users/Arnesh/Desktop/cbom.json'),
    path.resolve(__dirname, '../cbom.json'),
  ];

  for (const p of candidatePaths) {
    if (fs.existsSync(p)) {
      try {
        const raw = fs.readFileSync(p, 'utf-8');
        activeCbomPath = p;
        return JSON.parse(raw);
      } catch (err) {
        console.error(`[Spectra Server] Error reading CBOM from ${p}:`, err.message);
      }
    }
  }
  return null;
}

function handleApiRequest(req, res, parsedUrl) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // GET /api/cbom
  if (parsedUrl.pathname === '/api/cbom' && req.method === 'GET') {
    const data = getCbomData();
    if (!data) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'No CBOM document found at active path', path: activeCbomPath }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
    return;
  }

  // POST /api/cbom
  if (parsedUrl.pathname === '/api/cbom' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const parsed = JSON.parse(body);
        inMemoryCbom = parsed;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'ok',
          components: parsed.components ? parsed.components.length : 0,
          message: 'CBOM ingested successfully'
        }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON payload: ' + err.message }));
      }
    });
    return;
  }

  // GET /api/status
  if (parsedUrl.pathname === '/api/status') {
    const data = getCbomData();
    const stats = fs.existsSync(activeCbomPath) ? fs.statSync(activeCbomPath) : null;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'online',
      activeCbomPath: activeCbomPath,
      exists: !!data,
      componentsCount: data && data.components ? data.components.length : 0,
      vulnerabilitiesCount: data && data.vulnerabilities ? data.vulnerabilities.length : 0,
      dependenciesCount: data && data.dependencies ? data.dependencies.length : 0,
      fileSizeKb: stats ? (stats.size / 1024.0).toFixed(1) : 0,
      lastModified: stats ? stats.mtime.toISOString() : null,
      serverTime: new Date().toISOString()
    }));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'API route not found' }));
}

function handleStaticRequest(req, res, parsedUrl) {
  let reqPath = parsedUrl.pathname === '/' ? '/index.html' : parsedUrl.pathname;
  let safePath = path.normalize(reqPath).replace(/^(\.\.[\/\\])+/, '');
  let filePath = path.join(PUBLIC_DIR, safePath);

  // If path doesn't exist or is a directory, fallback to index.html for SPA routing
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    filePath = path.join(PUBLIC_DIR, 'index.html');
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Not Found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(`Server Error: ${err.code}`);
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    }
  });
}

function startServer(port = DEFAULT_PORT) {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    if (parsedUrl.pathname.startsWith('/api/')) {
      handleApiRequest(req, res, parsedUrl);
    } else {
      handleStaticRequest(req, res, parsedUrl);
    }
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.warn(`[Spectra Server] Port ${port} is currently in use. Attempting port ${port + 1}...`);
      startServer(port + 1);
    } else {
      console.error('[Spectra Server] Fatal error:', err);
    }
  });

  server.listen(port, () => {
    console.log(`\n============================================================`);
    console.log(`  SPECTRA CYCLONEDX 1.6 CBOM VISUALIZER ONLINE`);
    console.log(`============================================================`);
    console.log(`  Local URL      : http://localhost:${port}`);
    console.log(`  Bound CBOM     : ${activeCbomPath}`);
    console.log(`  API Endpoint   : http://localhost:${port}/api/cbom`);
    console.log(`  Server Status  : http://localhost:${port}/api/status`);
    console.log(`============================================================\n`);
  });

  return server;
}

// Support command-line arguments: node server.js [port] [cbomPath]
const args = process.argv.slice(2);
if (args[0] && !isNaN(parseInt(args[0], 10))) {
  const customPort = parseInt(args[0], 10);
  if (args[1]) activeCbomPath = path.resolve(args[1]);
  startServer(customPort);
} else {
  if (args[0]) activeCbomPath = path.resolve(args[0]);
  startServer(DEFAULT_PORT);
}
