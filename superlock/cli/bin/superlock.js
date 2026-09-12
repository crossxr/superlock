#!/usr/bin/env node

const { program } = require('commander');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

// Unpadded base64url, per RFC 7636 (PKCE) and RFC 4648 §5.
function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── NEON VOLT TERMINAL DESIGN SYSTEM ──
const chalk = {
  volt: (t) => `\x1b[38;2;250;255;105m${t}\x1b[0m`,
  voltBg: (t) => `\x1b[48;2;250;255;105m\x1b[30m\x1b[1m${t}\x1b[0m`,
  red: (t) => `\x1b[38;2;239;68;68m${t}\x1b[0m`,
  redBg: (t) => `\x1b[48;2;239;68;68m\x1b[37m\x1b[1m${t}\x1b[0m`,
  dim: (t) => `\x1b[2m${t}\x1b[0m`,
  white: (t) => `\x1b[37m${t}\x1b[0m`,
  bold: (t) => `\x1b[1m${t}\x1b[0m`,
};

// Ctrl+C (or a closed stdin) at an interactive prompt is a cancellation, not a
// crash — inquirer signals it by rejecting with ExitPromptError, which would
// otherwise reach the user as a stack trace.
function handleFatal(err) {
  if (err && err.name === 'ExitPromptError') {
    console.log(chalk.dim('[ SYS ] Aborted.'));
    process.exit(130);
  }
  console.error(chalk.red('[ ERR ]') + ` ${err && err.stack ? err.stack : err}`);
  process.exit(1);
}
process.on('uncaughtException', handleFatal);
process.on('unhandledRejection', handleFatal);

const API_URL = process.env.SUPERLOCK_API_URL || 'https://superlock-api-587208374116.us-central1.run.app';
const DASHBOARD_URL = process.env.SUPERLOCK_DASHBOARD_URL || 'https://superlock.superxepic.dev';
const GLOBAL_CONFIG_PATH = path.join(os.homedir(), '.superlock.json');
const LOCAL_CONFIG_PATH = path.join(process.cwd(), '.superlockrc');

async function getConfig() {
  try {
    const data = await fs.readFile(GLOBAL_CONFIG_PATH, 'utf-8');
    return JSON.parse(data);
  } catch {
    return {};
  }
}

// Restricts the token file to the current user. fs.chmod's mode only applies
// on create (a pre-existing file keeps its old bits) and, on Windows, only
// toggles the read-only attribute rather than expressing owner-only access —
// so Windows gets an ACL reset instead of a POSIX mode.
async function restrictToOwner(filePath) {
  if (process.platform === 'win32') {
    const { execFile } = require('child_process');
    const username = os.userInfo().username;
    await new Promise((resolve) => {
      execFile('icacls', [filePath, '/inheritance:r', '/grant:r', `${username}:F`], () => resolve());
    });
    return;
  }
  await fs.chmod(filePath, 0o600).catch(() => {});
}

async function saveConfig(cfg) {
  const existing = await getConfig();
  // The token file holds a live credential — owner-only, whether it's being
  // created fresh or already existed with looser permissions.
  await fs.writeFile(GLOBAL_CONFIG_PATH, JSON.stringify({ ...existing, ...cfg }, null, 2), { mode: 0o600 });
  await restrictToOwner(GLOBAL_CONFIG_PATH);
}

async function getLocalConfig() {
  try {
    const data = await fs.readFile(LOCAL_CONFIG_PATH, 'utf-8');
    return JSON.parse(data);
  } catch {
    return {};
  }
}

async function saveLocalConfig(cfg) {
  const existing = await getLocalConfig();
  await fs.writeFile(LOCAL_CONFIG_PATH, JSON.stringify({ ...existing, ...cfg }, null, 2));
}

async function apiRequest(endpoint, method = 'GET', body = null) {
  const cfg = await getConfig();
  if (!cfg.token) {
    console.error(chalk.red('[ ERR ]') + ' Authentication required. Run `superlock auth login`.');
    process.exit(1);
  }

  const res = await fetch(`${API_URL}${endpoint}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${cfg.token}`
    },
    body: body ? JSON.stringify(body) : undefined
  });

  if (!res.ok) {
    let err;
    try {
      const data = await res.json();
      err = data.message || JSON.stringify(data);
    } catch {
      err = res.statusText;
    }
    console.error(chalk.red('[ ERR ]') + ` Protocol violation (${res.status}): ${err}`);
    process.exit(1);
  }
  
  if (res.status === 204) return null;
  return res.json();
}

async function getEnvId(projectId, envName) {
  const res = await apiRequest(`/v1/projects/${projectId}/envs`);
  const envs = res?.environments || res; 
  if (!Array.isArray(envs)) {
      console.error(chalk.red('[ ERR ]') + ' Workspace state parsing failed.');
      process.exit(1);
  }
  const env = envs.find(e => e.name === envName || e.slug === envName);
  if (!env) {
    console.error(chalk.red('[ ERR ]') + ` Environment '${envName}' not located in bounded project.`);
    process.exit(1);
  }
  return env.id;
}

// ── Local .env file handling ───────────────────────────────────────────────
//
// Example/template files are never sync candidates: they hold placeholders,
// and pushing them would overwrite real cloud values with dummy ones.
const ENV_TEMPLATE_SUFFIX = /\.(example|sample|template|dist)$/i;

async function detectEnvFiles() {
  let entries;
  try {
    entries = await fs.readdir(process.cwd(), { withFileTypes: true });
  } catch {
    return [];
  }
  return entries
    .filter((e) => e.isFile())
    .map((e) => e.name)
    .filter((name) => (name === '.env' || name.startsWith('.env.')) && !ENV_TEMPLATE_SUFFIX.test(name))
    .sort((a, b) => a.length - b.length || a.localeCompare(b));
}

// Finds the index of the quote that closes a value, skipping backslash-escaped
// quotes inside double-quoted values.
function findClosingQuote(text, quote) {
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\\' && quote === '"') {
      i++;
      continue;
    }
    if (text[i] === quote) return i;
  }
  return -1;
}

// Parses .env content into ordered { key, value } pairs. Handles comments,
// `export ` prefixes, quoted (including multi-line) values, escape sequences
// in double-quoted values, inline comments, and duplicate keys (last wins).
function parseEnvContent(content) {
  const entries = [];
  const indexByKey = new Map();
  const lines = content.replace(/\r\n?/g, '\n').split('\n');

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const decl = trimmed.startsWith('export ') ? trimmed.slice(7).trim() : trimmed;
    const eq = decl.indexOf('=');
    if (eq === -1) continue;

    const key = decl.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;

    const rest = decl.slice(eq + 1).trim();
    let value;
    const quote = rest[0];

    if (quote === '"' || quote === "'") {
      const buffer = [];
      let body = rest.slice(1);
      for (;;) {
        const close = findClosingQuote(body, quote);
        if (close !== -1) {
          buffer.push(body.slice(0, close));
          break;
        }
        buffer.push(body);
        i++;
        if (i >= lines.length) break;
        body = lines[i];
      }
      value = buffer.join('\n');
      if (quote === '"') {
        value = value
          .replace(/\\n/g, '\n')
          .replace(/\\r/g, '\r')
          .replace(/\\t/g, '\t')
          .replace(/\\"/g, '"')
          .replace(/\\\\/g, '\\');
      }
    } else {
      const inlineComment = rest.search(/\s#/);
      value = (inlineComment === -1 ? rest : rest.slice(0, inlineComment)).trim();
    }

    if (indexByKey.has(key)) {
      entries[indexByKey.get(key)].value = value;
    } else {
      indexByKey.set(key, entries.length);
      entries.push({ key, value });
    }
  }

  return entries;
}

function serializeEnvValue(value) {
  const raw = value == null ? '' : String(value);
  if (raw === '') return '';
  if (/[\s#'"\\]/.test(raw)) {
    return `"${raw.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r')}"`;
  }
  return raw;
}

// Keeps a plaintext secrets file out of version control. Silent no-op when the
// entry is already there.
async function ensureGitignored(fileName) {
  const gitignorePath = path.join(process.cwd(), '.gitignore');
  try {
    const gitignore = await fs.readFile(gitignorePath, 'utf-8');
    if (gitignore.split(/\r?\n/).some((line) => line.trim() === fileName)) return;
    const prefix = gitignore.endsWith('\n') ? '' : '\n';
    await fs.appendFile(gitignorePath, `${prefix}${fileName}\n`);
    console.log(chalk.dim(`[ SYS ] Added ${fileName} to .gitignore`));
  } catch {
    await fs.writeFile(gitignorePath, `${fileName}\n`);
    console.log(chalk.dim(`[ SYS ] Created .gitignore with ${fileName} entry`));
  }
}

// The environment `superlock link` bound to this directory wins when --env is
// omitted; 'production' stays the fallback for an unbound directory.
function resolveEnvName(flagValue, local) {
  return flagValue || local.envName || 'production';
}

program
  .name('superlock')
  .description('SuperLock Zero-Trust Platform CLI')
  .version('1.0.6');

// Login
const authCommand = program.command('auth').description('Authentication subroutines');
authCommand
  .command('login')
  .description('Authenticate device with cluster via SSO')
  .action(async () => {
    console.log(chalk.voltBg(' AUTH ') + chalk.bold(' Initializing secure handshake...'));

    // Per-attempt state nonce (checked against the loopback callback so an
    // unrelated page can't drive a request into it on its own) and a PKCE
    // pair (RFC 7636): the browser redirect never carries the API token —
    // only a one-time code bound to codeChallenge. Redeeming it here requires
    // codeVerifier, which never leaves this process, so a code exposed in
    // browser history, a Referer header, or a proxy log is worthless alone.
    const state = base64url(crypto.randomBytes(16));
    const codeVerifier = base64url(crypto.randomBytes(32));
    const codeChallenge = base64url(crypto.createHash('sha256').update(codeVerifier).digest());

    const port = Math.floor(Math.random() * 10000) + 10000;
    const validHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
    const server = http.createServer();

    let answered = false;
    let expireTimer;

    function finish(exitCode) {
      clearTimeout(expireTimer);
      server.close();
      process.exit(exitCode);
    }

    server.on('request', async (req, res) => {
      const hostHeader = req.headers.host || `127.0.0.1:${port}`;
      const url = new URL(req.url, `http://${hostHeader}`);

      // Anything other than the callback (browsers auto-request /favicon.ico,
      // for instance) is ignored rather than treated as our one answer.
      if (url.pathname !== '/callback') {
        res.writeHead(404).end();
        return;
      }

      // This is the callback — the server answers exactly once, whatever the
      // outcome, and then shuts down. No retries, so there's no window for
      // repeated guesses against state or the exchange endpoint.
      if (answered) {
        res.writeHead(410).end('ERR: Already Answered');
        return;
      }
      answered = true;

      if (!validHosts.has(hostHeader)) {
        res.writeHead(400).end('ERR: Invalid Host');
        console.error(chalk.red('[ ERR ]') + ` Callback arrived with unexpected Host: ${hostHeader}`);
        finish(1);
        return;
      }

      if (url.searchParams.get('state') !== state) {
        res.writeHead(400).end('ERR: State Mismatch');
        console.error(chalk.red('[ ERR ]') + ' Callback state did not match — rejecting.');
        finish(1);
        return;
      }

      const code = url.searchParams.get('code');
      if (!code) {
        res.writeHead(400).end('ERR: Missing Code');
        console.error(chalk.red('[ ERR ]') + ' Callback carried no authorization code.');
        finish(1);
        return;
      }

      let token;
      try {
        const exchangeRes = await fetch(`${API_URL}/v1/cli/auth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, code_verifier: codeVerifier }),
        });
        if (!exchangeRes.ok) {
          const body = await exchangeRes.json().catch(() => ({}));
          throw new Error(body.message || `exchange failed (${exchangeRes.status})`);
        }
        ({ token } = await exchangeRes.json());
        if (!token) throw new Error('exchange response carried no token');
      } catch (err) {
        res.writeHead(502).end('ERR: Exchange Failed');
        console.error(chalk.red('[ ERR ]') + ` Failed to redeem authorization code: ${err.message}`);
        finish(1);
        return;
      }

      await saveConfig({ token });
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`
            <!DOCTYPE html>
            <html lang="en">
              <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Authentication Integral</title>
                <style>
                  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@900&family=Inconsolata:wght@700;900&display=swap');
                  
                  body {
                    margin: 0; padding: 0;
                    background-color: #faff69;
                    color: #000000;
                    height: 100vh;
                    display: flex; align-items: center; justify-content: center;
                    font-family: 'Inter', sans-serif;
                    overflow: hidden;
                  }
                  .watermark {
                    position: absolute;
                    inset: 0;
                    display: flex; align-items: center; justify-content: center;
                    pointer-events: none; user-select: none;
                    font-size: 25vw; font-weight: 900; color: rgba(0,0,0,0.08);
                    letter-spacing: -0.05em; line-height: 1; z-index: 0;
                  }
                  .logo {
                    position: absolute; top: 48px; left: 48px;
                    display: flex; align-items: center; gap: 12px; z-index: 10;
                  }
                  .logo-box {
                    width: 32px; height: 32px;
                    background-color: #000000; border-radius: 4px;
                    display: flex; align-items: center; justify-content: center;
                  }
                  .logo-text {
                    font-weight: 900; text-transform: uppercase; font-size: 20px; letter-spacing: -0.05em;
                  }
                  .content {
                    position: relative; z-index: 10; text-align: center; max-width: 480px;
                  }
                  .status-pill {
                    display: inline-flex; align-items: center; gap: 12px;
                    background-color: #000000; color: #faff69;
                    padding: 8px 24px; border-radius: 9999px;
                    font-size: 12px; font-weight: 900; text-transform: uppercase;
                    letter-spacing: 0.3em; margin-bottom: 48px;
                  }
                  .status-dot {
                    width: 8px; height: 8px; border-radius: 50%; background-color: #faff69;
                    box-shadow: 0 0 8px #faff69; animation: pulse 2s infinite;
                  }
                  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
                  h1 {
                    font-size: 64px; font-weight: 900; line-height: 0.95;
                    margin: 0 0 24px 0; text-transform: uppercase; letter-spacing: -0.02em;
                  }
                  .divider {
                    height: 2px; width: 64px; background-color: rgba(0,0,0,0.1);
                    margin: 0 auto 32px auto;
                  }
                  p {
                    font-size: 11px; font-weight: 700; line-height: 1.6;
                    color: rgba(0,0,0,0.6); text-transform: uppercase;
                    letter-spacing: 0.2em; max-width: 320px; margin: 0 auto;
                    background-color: rgba(0,0,0,0.03); padding: 16px; border: 2px solid rgba(0,0,0,0.05);
                    border-radius: 8px;
                  }
                </style>
              </head>
              <body>
                <div class="watermark">SECURE</div>
                
                <div class="logo">
                  <div class="logo-box">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#faff69" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                  </div>
                  <div class="logo-text">SuperLock</div>
                </div>

                <div class="content">
                  <div class="status-pill">
                    <div class="status-dot"></div>
                    Handshake Integral
                    <div class="status-dot"></div>
                  </div>
                  <h1>CLI<br>Authenticated</h1>
                  <div class="divider"></div>
                  <p>Vault parameters successfully synced. Connection established. Return to terminal environment to continue.</p>
                </div>

                <div style="position: absolute; bottom: 48px; left: 48px; right: 48px; display: flex; justify-content: space-between; border-top: 1px solid rgba(0,0,0,0.08); padding-top: 32px;">
                   <div style="display: flex; flex-direction: column;">
                      <span style="font-size: 9px; font-weight: 900; color: rgba(0,0,0,0.3); text-transform: uppercase; letter-spacing: 0.1em;">Local Port</span>
                      <span style="font-family: 'Inconsolata', monospace; font-size: 12px; font-weight: 700; text-transform: uppercase;">${port}</span>
                   </div>
                   <div style="display: flex; flex-direction: column; text-align: right;">
                      <span style="font-size: 9px; font-weight: 900; color: rgba(0,0,0,0.3); text-transform: uppercase; letter-spacing: 0.1em;">Status</span>
                      <span style="font-family: 'Inconsolata', monospace; font-size: 12px; font-weight: 700; text-transform: uppercase;">READY_SYNCHRONIZED</span>
                   </div>
                </div>
                <script>window.setTimeout(() => window.close(), 5000)</script>
              </body>
            </html>
          `);
      console.log(chalk.volt('[ OK ]') + ' Cryptographic identity established');
      console.log(chalk.dim(`[ SYS ] Root token persisted to ${GLOBAL_CONFIG_PATH}`));
      finish(0);
    });

    // Loopback only — never on all interfaces. Anyone reachable at this
    // address before the real redirect lands can only burn the single answer
    // slot above; they cannot exchange a token without a valid code, and code
    // issuance itself requires a real, authenticated dashboard approval.
    server.listen(port, '127.0.0.1', async () => {
      const authUrl = `${DASHBOARD_URL}/cli/auth?port=${port}&state=${encodeURIComponent(state)}&challenge=${encodeURIComponent(codeChallenge)}`;
      console.log(chalk.dim(`[ SYS ] Browser launch vector: ${authUrl}`));
      try {
        const openPkg = await import('open');
        const openCmd = openPkg.default || openPkg;
        await openCmd(authUrl);
      } catch (err) {
        console.log(chalk.dim(`[ SYS ] Intercept trigger failed. Manual execution required: ${authUrl}`));
      }
    });

    expireTimer = setTimeout(() => {
      if (answered) return;
      answered = true;
      console.error(chalk.red('[ ERR ]') + ' Login timed out after 60s — no callback received.');
      finish(1);
    }, 60000);
  });

// ── Link: bind a local env file to a cloud environment ─────────────────────
//
// Interactive by design — every step can be skipped with a flag, and anything
// missing on the remote side (project, environment) can be created inline
// rather than sending the user to the dashboard mid-flow.

async function resolveProject(projectIdFlag) {
  const res = await apiRequest('/v1/projects');
  const projects = Array.isArray(res?.projects) ? res.projects : Array.isArray(res) ? res : [];

  if (projectIdFlag) {
    const found = projects.find((p) => p.id === projectIdFlag || p.slug === projectIdFlag);
    if (!found) {
      console.error(chalk.red('[ ERR ]') + ` Project '${projectIdFlag}' not resolved in this organization.`);
      process.exit(1);
    }
    return found;
  }

  const { select } = require('@inquirer/prompts');

  if (projects.length === 0) {
    console.log(chalk.dim('[ SYS ] Zero project boundaries detected in this organization.'));
    return createProjectInteractive();
  }

  const choice = await select({
    message: chalk.volt('Select project space to tether:'),
    choices: [
      ...projects.map((p) => ({
        name: chalk.bold(p.name) + chalk.dim(` (${p.slug})`),
        value: p.id,
      })),
      { name: chalk.volt('+ Instantiate new project'), value: '__create__' },
    ],
  });

  if (choice === '__create__') return createProjectInteractive();
  return projects.find((p) => p.id === choice);
}

async function createProjectInteractive() {
  const { input } = require('@inquirer/prompts');
  const name = await input({
    message: chalk.volt('New project name:'),
    validate: (v) => (v.trim() ? true : 'A name is required'),
  });
  const description = await input({ message: chalk.volt('Description (optional):') });

  const project = await apiRequest('/v1/projects', 'POST', {
    name: name.trim(),
    description: description.trim(),
  });
  console.log(chalk.volt('[ OK ]') + ` Project ${chalk.bold(project.name)} instantiated`);
  return project;
}

async function resolveEnvironment(projectId, envNameFlag) {
  const res = await apiRequest(`/v1/projects/${projectId}/envs`);
  const envs = Array.isArray(res?.environments) ? res.environments : Array.isArray(res) ? res : [];

  const { select, confirm } = require('@inquirer/prompts');

  if (envNameFlag) {
    const found = envs.find((e) => e.name === envNameFlag || e.slug === envNameFlag);
    if (found) return found;
    console.log(chalk.dim(`[ SYS ] Environment '${envNameFlag}' absent from this project boundary.`));
    const create = await confirm({
      message: chalk.volt(`Initialize environment '${envNameFlag}' now?`),
      default: true,
    });
    if (!create) process.exit(1);
    return createEnvironmentInteractive(projectId, envNameFlag);
  }

  if (envs.length === 0) {
    console.log(chalk.dim('[ SYS ] No environments detected in this project boundary.'));
    return createEnvironmentInteractive(projectId);
  }

  const choice = await select({
    message: chalk.volt('Select environment to bind:'),
    choices: [
      ...envs.map((e) => ({
        name: chalk.bold(e.name) + (e.is_protected ? chalk.red(' [SECURED]') : ''),
        value: e.id,
      })),
      { name: chalk.volt('+ Initialize new environment'), value: '__create__' },
    ],
  });

  if (choice === '__create__') return createEnvironmentInteractive(projectId);
  return envs.find((e) => e.id === choice);
}

async function createEnvironmentInteractive(projectId, presetName) {
  const { input, confirm } = require('@inquirer/prompts');
  const name =
    presetName ||
    (await input({
      message: chalk.volt('New environment name:'),
      default: 'development',
      validate: (v) => (v.trim() ? true : 'A name is required'),
    }));
  const isProtected = await confirm({
    message: chalk.volt('Mark as secured (owner/admin access only)?'),
    default: false,
  });

  const env = await apiRequest(`/v1/projects/${projectId}/envs`, 'POST', {
    name: name.trim(),
    is_protected: isProtected,
  });
  console.log(chalk.volt('[ OK ]') + ` Environment ${chalk.bold(env.name)} initialized`);
  return env;
}

async function resolveEnvFile(fileFlag) {
  if (fileFlag) return fileFlag;

  const { select, input } = require('@inquirer/prompts');
  const detected = await detectEnvFiles();
  if (detected.length === 0) {
    console.log(chalk.dim('[ SYS ] No local .env file detected in this directory.'));
  }

  const choice = await select({
    message: chalk.volt('Select the local env file to bind:'),
    choices: [
      ...detected.map((name) => ({ name: chalk.bold(name), value: name })),
      { name: chalk.dim('Specify a different path...'), value: '__manual__' },
      { name: chalk.dim('Skip — bind the environment only'), value: '__none__' },
    ],
  });

  if (choice === '__none__') return null;
  if (choice === '__manual__') {
    const manual = await input({
      message: chalk.volt('Path to local env file:'),
      default: '.env',
      validate: (v) => (v.trim() ? true : 'A path is required'),
    });
    return manual.trim();
  }
  return choice;
}

program.command('link')
  .description('Interactively bind a local env file to a SuperLock cloud environment')
  .option('-p, --project <projectId>', 'Project ID or slug (skips selection)')
  .option('-e, --env <envName>', 'Environment name (skips selection)')
  .option('-f, --file <path>', 'Local env file to bind (skips selection)')
  .option('--no-sync', 'Bind only — never offer to push or pull values')
  .action(async (options) => {
    console.log(chalk.voltBg(' LINK ') + chalk.bold(' Binding local workspace to cloud boundary...'));

    const project = await resolveProject(options.project);
    const env = await resolveEnvironment(project.id, options.env);
    const envFile = await resolveEnvFile(options.file);

    await saveLocalConfig({
      projectId: project.id,
      projectName: project.name,
      envId: env.id,
      envName: env.name,
      envFile: envFile || null,
    });

    console.log(chalk.volt('[ OK ]') + ` ${chalk.bold(project.name)} / ${chalk.bold(env.name)} tethered to this directory`);
    console.log(chalk.dim(`[ SYS ] Binding persisted to ${LOCAL_CONFIG_PATH}`));
    if (envFile) console.log(chalk.dim(`[ SYS ] Local file bound: ${envFile}`));

    if (!envFile || options.sync === false) return;

    // ── Sync step ──
    const filePath = path.isAbsolute(envFile) ? envFile : path.join(process.cwd(), envFile);
    let localEntries = [];
    let fileExists = true;
    try {
      localEntries = parseEnvContent(await fs.readFile(filePath, 'utf-8'));
    } catch {
      fileExists = false;
      console.log(chalk.dim(`[ SYS ] ${envFile} not present on disk yet.`));
    }

    const remoteRes = await apiRequest(`/v1/projects/${project.id}/envs/${env.id}/secrets`);
    const remoteSecrets = Array.isArray(remoteRes?.secrets) ? remoteRes.secrets : Array.isArray(remoteRes) ? remoteRes : [];

    console.log(
      chalk.dim(`[ SYS ] Local: ${localEntries.length} variable(s)  |  Cloud [${env.name}]: ${remoteSecrets.length} secret(s)`)
    );

    const { select, confirm } = require('@inquirer/prompts');
    const direction = await select({
      message: chalk.volt('Synchronize now?'),
      choices: [
        {
          name: `Push  ${chalk.dim(`${envFile} → [${env.name}]`)}`,
          value: 'push',
          disabled: localEntries.length === 0 ? '(no local variables)' : false,
        },
        {
          name: `Pull  ${chalk.dim(`[${env.name}] → ${envFile}`)}`,
          value: 'pull',
          disabled: remoteSecrets.length === 0 ? '(no cloud secrets)' : false,
        },
        { name: chalk.dim('Nothing — binding only'), value: 'none' },
      ],
    });

    if (direction === 'push') {
      const overwrite = await confirm({
        message: chalk.volt('Overwrite keys that already exist in the cloud?'),
        default: true,
      });

      const result = await apiRequest(
        `/v1/projects/${project.id}/envs/${env.id}/secrets/bulk`,
        'POST',
        { secrets: localEntries.map(({ key, value }) => ({ key, value })), overwrite }
      );

      console.log(
        chalk.volt('[ OK ]') +
          ` Push complete — ${result?.created ?? 0} created, ${result?.updated ?? 0} updated, ${result?.skipped ?? 0} skipped`
      );
      await ensureGitignored(path.basename(envFile));
      return;
    }

    if (direction === 'pull') {
      if (fileExists && localEntries.length > 0) {
        const overwriteFile = await confirm({
          message: chalk.red(`Overwrite ${envFile} (${localEntries.length} local variable(s)) with cloud values?`),
          default: false,
        });
        if (!overwriteFile) {
          console.log(chalk.dim('[ SYS ] Pull aborted — local file untouched.'));
          return;
        }
      }

      const values = await apiRequest(`/v1/envs/${env.id}/secrets/values`);
      if (!values || typeof values !== 'object') {
        console.error(chalk.red('[ ERR ]') + ' Failed to retrieve secrets from vault.');
        process.exit(1);
      }

      const keys = Object.keys(values);
      const header = [
        '# SuperLock-managed environment file',
        `# Project: ${project.name}`,
        `# Environment: ${env.name}`,
        `# Generated: ${new Date().toISOString()}`,
        '# WARNING: This file contains sensitive data. Do NOT commit to version control.',
        '',
      ].join('\n');
      const body = keys.map((key) => `${key}=${serializeEnvValue(values[key])}`).join('\n');
      await fs.writeFile(filePath, header + body + '\n');

      console.log(chalk.volt('[ OK ]') + ` ${keys.length} secret(s) written to ${chalk.bold(envFile)}`);
      await ensureGitignored(path.basename(envFile));
    }
  });

// Secret
const secretCommand = program.command('secret').description('Vault management directives');
secretCommand
  .command('set <key>')
  .description('Cipher a secret into a specific environment')
  .option('--env <environment>', 'Target environment (default: linked env)')
  .option('--value <value>', 'Raw payload value')
  .action(async (key, options) => {
    const local = await getLocalConfig();
    if (!local.projectId) {
      console.error(chalk.red('[ ERR ]') + ' Terminal detached. Trigger `superlock link` first.');
      process.exit(1);
    }

    const envName = resolveEnvName(options.env, local);
    const value = options.value || await require('@inquirer/prompts').password({ message: chalk.volt(`Input cipher value for [${key}]:`) });
    const envId = await getEnvId(local.projectId, envName);

    await apiRequest(`/v1/projects/${local.projectId}/envs/${envId}/secrets`, 'POST', {
      key,
      value
    });

    console.log(chalk.volt('[ OK ]') + ` Payload ${chalk.bold(key)} encrypted into [${envName}] boundary`);
  });

secretCommand
  .command('get <key>')
  .description('Decrypt a secret payload from an environment')
  .option('--env <environment>', 'Target environment (default: linked env)')
  .action(async (key, options) => {
    const local = await getLocalConfig();
    if (!local.projectId) {
      console.error(chalk.red('[ ERR ]') + ' Terminal detached. Trigger `superlock link` first.');
      process.exit(1);
    }
    const envName = resolveEnvName(options.env, local);
    const envId = await getEnvId(local.projectId, envName);

    const res = await apiRequest(`/v1/projects/${local.projectId}/envs/${envId}/secrets`);
    const secrets = res?.secrets || res;

    if (!Array.isArray(secrets)) {
        console.error(chalk.red('[ ERR ]') + ' Malformed decryption protocol.');
        process.exit(1);
    }

    const secret = secrets.find(s => s.key === key);
    
    if (!secret) {
      console.error(chalk.red('[ ERR ]') + ` Parameter [${key}] absent in [${envName}] boundary.`);
      process.exit(1);
    }

    console.log(secret.value || secret.decrypted_value || secret.encrypted_value);
  });

// Run
program
  .command('run')
  .description('Inject decrypted variables directly into a process execution shell')
  .option('--env <environment>', 'Target injection environment (default: linked env)')
  .argument('[cmd...]', 'Target execution command')
  .allowUnknownOption()
  .action(async (cmdArgs, options, command) => {
    if (!cmdArgs || cmdArgs.length === 0) {
      console.error(chalk.red('[ ERR ]') + ' Fatal: Empty execution vector.');
      process.exit(1);
    }

    const local = await getLocalConfig();
    if (!local.projectId) {
      console.error(chalk.red('[ ERR ]') + ' Terminal detached. Trigger `superlock link` first.');
      process.exit(1);
    }

    const envName = resolveEnvName(options.env, local);
    const envId = await getEnvId(local.projectId, envName);
    const res = await apiRequest(`/v1/projects/${local.projectId}/envs/${envId}/secrets`);
    const secrets = res?.secrets || res;

    const injectedEnv = {};
    if (secrets && Array.isArray(secrets)) {
      for (const s of secrets) {
         injectedEnv[s.key] = s.value || s.decrypted_value || s.encrypted_value;
      }
    }

    const targetEnv = { ...process.env, ...injectedEnv };
    console.log(chalk.voltBg(' EXEC ') + chalk.bold(` Overriding process shell with ${Object.keys(injectedEnv).length} parameters from [${envName}]`));

    const child = spawn(cmdArgs[0], cmdArgs.slice(1), {
      stdio: 'inherit',
      env: targetEnv,
      shell: true
    });
    
    child.on('exit', (code) => {
      process.exit(code);
    });
  });

// ── Phase 2: rotate command ────────────────────────────────────────────────
program
  .command('rotate <secret-key>')
  .description('Force cryptographic rotation cycle for a targeted secret')
  .requiredOption('-e, --env <envId>', 'Environment ID mapping')
  .action(async (secretKey, options) => {
    const cfg = await getConfig();
    const local = await getLocalConfig();
    if (!cfg.token) {
      console.error(chalk.red('[ ERR ]') + ' Authentication required.');
      process.exit(1);
    }
    if (!local.projectId) {
      console.error(chalk.red('[ ERR ]') + ' Terminal detached.');
      process.exit(1);
    }

    const listResp = await fetch(
      `${API_URL}/v1/projects/${local.projectId}/envs/${options.env}/secrets`,
      { headers: { Authorization: `Bearer ${cfg.token}` } }
    );
    if (!listResp.ok) {
      console.error(chalk.red('[ ERR ]') + ` Cluster fetch failed: ${listResp.status}`);
      process.exit(1);
    }
    const secrets = await listResp.json();
    const secret = (secrets.secrets || secrets.data || secrets).find(s => s.key === secretKey);
    if (!secret) {
      console.error(chalk.red('[ ERR ]') + ` Target coordinate '${secretKey}' not resolved`);
      process.exit(1);
    }

    const resp = await fetch(`${API_URL}/v1/secrets/${secret.id}/rotate`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${cfg.token}` },
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      console.error(chalk.red('[ ERR ]') + ` Rotation locked: ${err.error || resp.status}`);
      process.exit(1);
    }
    console.log(chalk.volt('[ OK ]') + ` Cryptographic sequence triggered for '${secretKey}'`);
  });

// ── Phase 2: verify-audit command ─────────────────────────────────────────
program
  .command('verify-audit')
  .description('Validate HMAC chain integrity of the immutable ledger')
  .option('--limit <n>', 'Vector trace depth', '100')
  .action(async (options) => {
    const cfg = await getConfig();
    if (!cfg.token) {
       console.error(chalk.red('[ ERR ]') + ' Authentication required.');
       process.exit(1);
    }

    console.log(chalk.dim('[ SYS ] Processing cryptographic trace...'));
    const resp = await fetch(
      `${API_URL}/v1/orgs/me/audit?limit=${options.limit}`,
      { headers: { Authorization: `Bearer ${cfg.token}` } }
    );
    if (!resp.ok) {
      console.error(chalk.red('[ ERR ]') + ` Pipeline fetch failed: ${resp.status}`);
      process.exit(1);
    }
    const apiRes = await resp.json();
    const events = apiRes.events || apiRes.data || apiRes;
    if (!events || events.length === 0) {
      console.log(chalk.dim('[ SYS ] Immutable ledger is barren.'));
      return;
    }

    let verified = 0;
    let broken = 0;
    for (let i = 0; i < events.length; i++) {
      const ev = events[i];
      if (i < events.length - 1) {
        if (ev.prev_hmac !== undefined && events[i + 1].hmac !== undefined) {
          if (ev.prev_hmac !== events[i + 1].hmac) {
            console.error(chalk.redBg(' ALERT ') + ` Chain divergence node id:${ev.id} (pos ${i})`);
            broken++;
          } else {
            verified++;
          }
        }
      }
    }

    if (broken === 0) {
      console.log(chalk.volt('[ OK ]') + ` Ledger integral. ${verified} hashes structurally validated.`);
    } else {
      console.error(chalk.red('[ ERR ]') + ` SECURITY VIOLATION: ${broken} compromised nodes identified.`);
      process.exit(1);
    }
  });

// ── Phase 4: pull command ─────────────────────────────────────────────────
program
  .command('pull')
  .description('Pull all secrets from a project environment into .env.superlock')
  .option('-p, --project <projectId>', 'Project ID (skip selection)')
  .option('-e, --env <envName>', 'Environment name (skip selection)')
  .action(async (options) => {
    const cfg = await getConfig();
    if (!cfg.token) {
      console.error(chalk.red('[ ERR ]') + ' Authentication required. Run `superlock auth login`.');
      process.exit(1);
    }

    console.log(chalk.voltBg(' PULL ') + chalk.bold(' Initiating secure environment sync...'));

    // Step 1: Select project
    let projectId = options.project;
    let projectName = '';

    if (!projectId) {
      const res = await apiRequest('/v1/projects');
      const projects = res?.projects || res;
      if (!projects || !Array.isArray(projects) || projects.length === 0) {
        console.error(chalk.red('[ ERR ]') + ' Zero active projects identified. Please instantiate on the dashboard.');
        process.exit(1);
      }

      const { select } = require('@inquirer/prompts');
      projectId = await select({
        message: chalk.volt('Select project to pull from:'),
        choices: projects.map(p => ({
          name: chalk.bold(p.name) + chalk.dim(` (${p.slug})`),
          value: p.id
        }))
      });
      projectName = projects.find(p => p.id === projectId)?.name || '';
    }

    // Step 2: Select environment
    let envId;
    let envName = options.env || '';

    const envRes = await apiRequest(`/v1/projects/${projectId}/envs`);
    const envs = envRes?.environments || envRes;
    if (!envs || !Array.isArray(envs) || envs.length === 0) {
      console.error(chalk.red('[ ERR ]') + ' No environments detected in this project boundary.');
      process.exit(1);
    }

    if (envName) {
      const env = envs.find(e => e.name === envName || e.slug === envName);
      if (!env) {
        console.error(chalk.red('[ ERR ]') + ` Environment '${envName}' not found in project.`);
        process.exit(1);
      }
      envId = env.id;
      envName = env.name;
    } else {
      const { select } = require('@inquirer/prompts');
      const envChoice = await select({
        message: chalk.volt('Select environment to pull:'),
        choices: envs.map(e => ({
          name: chalk.bold(e.name) + (e.is_protected ? chalk.red(' [SECURED]') : ''),
          value: { id: e.id, name: e.name }
        }))
      });
      envId = envChoice.id;
      envName = envChoice.name;
    }

    console.log(chalk.dim(`[ SYS ] Fetching encrypted payloads from [${envName}]...`));

    // Step 3: Fetch all secrets using BulkPullSecrets endpoint
    const secrets = await apiRequest(`/v1/envs/${envId}/secrets/values`);

    if (!secrets || typeof secrets !== 'object') {
      console.error(chalk.red('[ ERR ]') + ' Failed to retrieve secrets from vault.');
      process.exit(1);
    }

    const keys = Object.keys(secrets);
    if (keys.length === 0) {
      console.log(chalk.dim('[ SYS ] No secrets found in this environment.'));
      return;
    }

    // Step 4: Write .env.superlock file
    const envFilePath = path.join(process.cwd(), '.env.superlock');
    const header = [
      `# SuperLock Environment Variables`,
      `# Project: ${projectName || projectId}`,
      `# Environment: ${envName}`,
      `# Generated: ${new Date().toISOString()}`,
      `# WARNING: This file contains sensitive data. Do NOT commit to version control.`,
      ``,
    ].join('\n');

    const envContent = keys.map(key => `${key}=${secrets[key]}`).join('\n');
    await fs.writeFile(envFilePath, header + envContent + '\n');

    console.log(chalk.volt('[ OK ]') + ` ${keys.length} secrets exported to ${chalk.bold('.env.superlock')}`);
    console.log(chalk.dim(`[ SYS ] File: ${envFilePath}`));

    await ensureGitignored('.env.superlock');
  });

program.parse(process.argv);
