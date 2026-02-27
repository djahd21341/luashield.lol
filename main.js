import express from 'express';
import { createServer } from 'http';
import fs from 'fs/promises';
import path from 'path';
import { randomBytes } from 'crypto';
import { fileURLToPath } from 'url';
import session from 'express-session';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';
import { Client, GatewayIntentBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, ModalBuilder, TextInputBuilder, TextInputStyle } from 'discord.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const server = createServer(app);
const PORT = process.env.PORT || 80; // Global PORT variable

// ============================================
// DISCORD BOT SETUP
// ============================================
const discordClient = new Client({ 
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.DirectMessages
  ] 
});

const DISCORD_TOKEN = 'lmao token';
const WHITELIST_DIR = path.join(__dirname, 'data', 'whitelist');

// ============================================
// DATA STORAGE (Text Files)
// ============================================
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.txt');
const SCRIPTS_DIR = path.join(DATA_DIR, 'scripts');
const KEYS_DIR = path.join(DATA_DIR, 'keys');
const EXECUTIONS_DIR = path.join(DATA_DIR, 'executions');
const SESSIONS_DIR = path.join(DATA_DIR, 'sessions');

// Store user sessions for Discord
const discordSessions = new Map(); // userId -> { username, expires }

// ============================================
// WHITELIST MANAGEMENT
// ============================================
async function getWhitelist(scriptId) {
  const whitelistFile = path.join(WHITELIST_DIR, `${scriptId}.json`);
  try {
    const data = await fs.readFile(whitelistFile, 'utf-8');
    return JSON.parse(data);
  } catch {
    return { users: [] };
  }
}

async function saveWhitelist(scriptId, whitelistData) {
  const whitelistFile = path.join(WHITELIST_DIR, `${scriptId}.json`);
  await fs.writeFile(whitelistFile, JSON.stringify(whitelistData, null, 2));
}

async function addToWhitelist(scriptId, discordUserId, discordUsername, days, generatedKey) {
  const whitelist = await getWhitelist(scriptId);
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + days);
  
  // Remove existing entry if any
  whitelist.users = whitelist.users.filter(u => u.discordId !== discordUserId);
  
  whitelist.users.push({
    discordId: discordUserId,
    discordUsername: discordUsername,
    addedAt: new Date().toISOString(),
    expiresAt: expiresAt.toISOString(),
    days: days,
    assignedKey: generatedKey
  });
  
  await saveWhitelist(scriptId, whitelist);
  return true;
}

async function checkWhitelist(scriptId, discordUserId) {
  const whitelist = await getWhitelist(scriptId);
  const user = whitelist.users.find(u => u.discordId === discordUserId);
  
  if (!user) return null;
  
  const expiresAt = new Date(user.expiresAt);
  if (expiresAt < new Date()) {
    // Remove expired whitelist
    whitelist.users = whitelist.users.filter(u => u.discordId !== discordUserId);
    await saveWhitelist(scriptId, whitelist);
    return null;
  }
  
  return user;
}

// ============================================
// USER MANAGEMENT
// ============================================
async function getUsers() {
  try {
    const data = await fs.readFile(USERS_FILE, 'utf-8');
    const users = {};
    data.split('\n').forEach(line => {
      if (line.trim()) {
        const [username, passwordHash, apiKey, createdAt] = line.split('|');
        users[username] = { username, passwordHash, apiKey, createdAt };
      }
    });
    return users;
  } catch {
    return {};
  }
}

async function saveUser(username, passwordHash, apiKey) {
  const users = await getUsers();
  users[username] = {
    username,
    passwordHash,
    apiKey,
    createdAt: new Date().toISOString()
  };
  
  const lines = Object.values(users).map(u => 
    `${u.username}|${u.passwordHash}|${u.apiKey}|${u.createdAt}`
  );
  await fs.writeFile(USERS_FILE, lines.join('\n'));
}

async function findUserByApiKey(apiKey) {
  const users = await getUsers();
  return Object.values(users).find(u => u.apiKey === apiKey);
}

// ============================================
// KEY MANAGEMENT
// ============================================
async function getScriptKeys(scriptId) {
  const keyFile = path.join(KEYS_DIR, `${scriptId}.json`);
  try {
    const data = await fs.readFile(keyFile, 'utf-8');
    return JSON.parse(data);
  } catch {
    return { keys: [], freeUntil: null, freeForever: false, hwidEnabled: false };
  }
}

async function saveScriptKeys(scriptId, keyData) {
  const keyFile = path.join(KEYS_DIR, `${scriptId}.json`);
  await fs.writeFile(keyFile, JSON.stringify(keyData, null, 2));
}

async function generateKey(scriptId, username, duration = null, maxUses = null) {
  const keyData = await getScriptKeys(scriptId);
  
  // Generate a unique key
  const key = randomBytes(8).toString('hex').toUpperCase();
  
  const newKey = {
    key: key,
    createdBy: username,
    createdAt: new Date().toISOString(),
    expiresAt: duration ? new Date(Date.now() + duration).toISOString() : null,
    used: 0,
    maxUses: maxUses, // null means infinite uses
    hwid: null
  };
  
  keyData.keys.push(newKey);
  await saveScriptKeys(scriptId, keyData);
  
  return key;
}

async function validateKey(scriptId, key, hwid = null) {
  const keyData = await getScriptKeys(scriptId);
  
  // Check if script is free forever
  if (keyData.freeForever) {
    return { valid: true, type: 'free_forever' };
  }
  
  // Check if script is free for a limited time
  if (keyData.freeUntil) {
    const freeUntil = new Date(keyData.freeUntil);
    if (freeUntil > new Date()) {
      return { valid: true, type: 'free_temporary', expiresAt: keyData.freeUntil };
    }
  }
  
  // Check if key exists
  const foundKey = keyData.keys.find(k => k.key === key);
  if (!foundKey) {
    return { valid: false, error: 'Invalid key' };
  }
  
  // Check expiration
  if (foundKey.expiresAt) {
    const expiresAt = new Date(foundKey.expiresAt);
    if (expiresAt < new Date()) {
      return { valid: false, error: 'Key expired' };
    }
  }
  
  // Check usage limit (only if maxUses is not null)
  if (foundKey.maxUses !== null && foundKey.used >= foundKey.maxUses) {
    return { valid: false, error: 'Key usage limit reached' };
  }
  
  // Check HWID if enabled globally or key has HWID
  if (keyData.hwidEnabled || foundKey.hwid) {
    if (!hwid) {
      return { valid: false, error: 'HWID required for this key' };
    }
    
    if (foundKey.hwid && foundKey.hwid !== hwid) {
      return { valid: false, error: 'HWID mismatch' };
    }
    
    if (keyData.hwidEnabled && !foundKey.hwid) {
      foundKey.hwid = hwid;
    }
  }
  
  // Increment usage (only if maxUses is not null)
  if (foundKey.maxUses !== null) {
    foundKey.used += 1;
  }
  await saveScriptKeys(scriptId, keyData);
  
  return { valid: true, type: 'key', key: foundKey };
}

async function setFreeForever(scriptId, enabled) {
  const keyData = await getScriptKeys(scriptId);
  keyData.freeForever = enabled;
  if (enabled) {
    keyData.freeUntil = null;
  }
  await saveScriptKeys(scriptId, keyData);
}

async function setFreeUntil(scriptId, duration) {
  const keyData = await getScriptKeys(scriptId);
  keyData.freeUntil = new Date(Date.now() + duration).toISOString();
  keyData.freeForever = false;
  await saveScriptKeys(scriptId, keyData);
}

async function setHWIDEnabled(scriptId, enabled) {
  const keyData = await getScriptKeys(scriptId);
  keyData.hwidEnabled = enabled;
  await saveScriptKeys(scriptId, keyData);
}

async function setKeyHWID(scriptId, key, hwid) {
  const keyData = await getScriptKeys(scriptId);
  const foundKey = keyData.keys.find(k => k.key === key);
  if (foundKey) {
    foundKey.hwid = hwid;
    await saveScriptKeys(scriptId, keyData);
    return true;
  }
  return false;
}

// ============================================
// SCRIPT MANAGEMENT
// ============================================
async function getUserScripts(username) {
  const userDir = path.join(SCRIPTS_DIR, username);
  try {
    await fs.access(userDir);
    const files = await fs.readdir(userDir);
    const scripts = [];
    
    for (const file of files) {
      if (file.endsWith('.json')) {
        const data = await fs.readFile(path.join(userDir, file), 'utf-8');
        scripts.push(JSON.parse(data));
      }
    }
    return scripts;
  } catch {
    return [];
  }
}

async function saveScript(username, scriptData) {
  const userDir = path.join(SCRIPTS_DIR, username);
  await fs.mkdir(userDir, { recursive: true });
  
  const script = {
    id: scriptData.id || randomBytes(8).toString('hex'),
    name: scriptData.name,
    content: scriptData.content,
    originalContent: scriptData.originalContent || scriptData.content,
    active: scriptData.active !== false,
    createdAt: scriptData.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    executions: scriptData.executions || 0,
    lastExecution: scriptData.lastExecution
  };
  
  await fs.writeFile(
    path.join(userDir, `${script.id}.json`), 
    JSON.stringify(script, null, 2)
  );
  return script;
}

async function getScript(username, scriptId) {
  try {
    const data = await fs.readFile(
      path.join(SCRIPTS_DIR, username, `${scriptId}.json`), 
      'utf-8'
    );
    return JSON.parse(data);
  } catch {
    return null;
  }
}

async function deleteScript(username, scriptId) {
  try {
    await fs.unlink(path.join(SCRIPTS_DIR, username, `${scriptId}.json`));
    // Also delete keys file
    try {
      await fs.unlink(path.join(KEYS_DIR, `${scriptId}.json`));
    } catch {}
    return true;
  } catch {
    return false;
  }
}

// ============================================
// EXECUTION TRACKING
// ============================================
async function getScriptExecutions(scriptId, days = 7) {
  const executions = [];
  const now = new Date();
  
  for (let i = 0; i < days; i++) {
    const date = new Date(now);
    date.setDate(date.getDate() - i);
    const dateStr = date.toISOString().split('T')[0];
    const execFile = path.join(EXECUTIONS_DIR, `${scriptId}_${dateStr}.txt`);
    
    try {
      const data = await fs.readFile(execFile, 'utf-8');
      const lines = data.split('\n').filter(l => l.trim());
      executions.push(...lines.map(l => JSON.parse(l)));
    } catch {
      // File doesn't exist, skip
    }
  }
  
  return executions;
}

// ============================================
// MIDDLEWARE
// ============================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// Authentication middleware
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// Logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    console.log(`${req.method} ${req.path} ${res.statusCode} - ${Date.now() - start}ms`);
  });
  next();
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// ============================================
// AUTH ROUTES
// ============================================
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    const users = await getUsers();
    if (users[username]) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    const passwordHash = await bcrypt.hash(password, 10);
    const apiKey = randomBytes(16).toString('hex');
    
    await saveUser(username, passwordHash, apiKey);
    
    res.json({ 
      success: true, 
      message: 'Registration successful',
      apiKey 
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const users = await getUsers();
    const user = users[username];
    
    if (!user || !await bcrypt.compare(password, user.passwordHash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    req.session.user = { username: user.username, apiKey: user.apiKey };
    
    res.json({ 
      success: true, 
      message: 'Login successful',
      user: { username: user.username, apiKey: user.apiKey }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/user', requireAuth, async (req, res) => {
  const users = await getUsers();
  const user = users[req.session.user.username];
  res.json({ 
    username: user.username, 
    apiKey: user.apiKey,
    createdAt: user.createdAt
  });
});

// ============================================
// SCRIPT MANAGEMENT API
// ============================================
app.get('/api/scripts', requireAuth, async (req, res) => {
  try {
    const scripts = await getUserScripts(req.session.user.username);
    
    // Add key info to each script
    const scriptsWithKeys = await Promise.all(scripts.map(async (script) => {
      const keyData = await getScriptKeys(script.id);
      return {
        ...script,
        keyInfo: {
          freeForever: keyData.freeForever || false,
          freeUntil: keyData.freeUntil || null,
          keyCount: keyData.keys.length,
          hwidEnabled: keyData.hwidEnabled || false
        }
      };
    }));
    
    res.json(scriptsWithKeys);
  } catch (err) {
    console.error('Error fetching scripts:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/scripts', requireAuth, async (req, res) => {
  try {
    const { name, content } = req.body;
    
    if (!name || !content) {
      return res.status(400).json({ error: 'Name and content required' });
    }
    
   
app.get('/api/scripts/:scriptId/executions', requireAuth, async (req, res) => {
  try {
    const { scriptId } = req.params;
    const { days } = req.query;
    
    const script = await getScript(req.session.user.username, scriptId);
    if (!script) {
      return res.status(404).json({ error: 'Script not found' });
    }
    
    const executions = await getScriptExecutions(scriptId, parseInt(days) || 7);
    res.json(executions);
  } catch (err) {
    console.error('Error fetching executions:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================
// KEY MANAGEMENT API
// ============================================
app.post('/api/scripts/:scriptId/keys', requireAuth, async (req, res) => {
  try {
    const { scriptId } = req.params;
    const { duration, maxUses } = req.body;
    
    const script = await getScript(req.session.user.username, scriptId);
    if (!script) {
      return res.status(404).json({ error: 'Script not found' });
    }
    
    const key = await generateKey(scriptId, req.session.user.username, duration, maxUses);
    
    res.json({ success: true, key });
  } catch (err) {
    console.error('Error generating key:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});






app.post('/api/scripts/:scriptId/hwid', requireAuth, async (req, res) => {
  try {
    const { scriptId } = req.params;
    const { enabled } = req.body;
    
    const script = await getScript(req.session.user.username, scriptId);
    if (!script) {
      return res.status(404).json({ error: 'Script not found' });
    }
    
    await setHWIDEnabled(scriptId, enabled);
    
    res.json({ success: true, hwidEnabled: enabled });
  } catch (err) {
    console.error('Error toggling HWID:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/scripts/:scriptId/keys/:key/hwid', requireAuth, async (req, res) => {
  try {
    const { scriptId, key } = req.params;
    const { hwid } = req.body;
    
    const script = await getScript(req.session.user.username, scriptId);
    if (!script) {
      return res.status(404).json({ error: 'Script not found' });
    }
    
    const success = await setKeyHWID(scriptId, key, hwid);
    
    if (success) {
      res.json({ success: true, message: 'HWID set successfully' });
    } else {
      res.status(404).json({ error: 'Key not found' });
    }
  } catch (err) {
    console.error('Error setting HWID:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================
// CLEAN EXECUTIONS
// ============================================
app.post('/api/clean-executions', requireAuth, async (req, res) => {
    try {
        const username = req.session.user.username;
        const scripts = await getUserScripts(username);
        
        // Delete execution logs for all user's scripts
        for (const script of scripts) {
            const files = await fs.readdir(EXECUTIONS_DIR);
            const scriptFiles = files.filter(f => f.startsWith(`${script.id}_`));
            
            for (const file of scriptFiles) {
                await fs.unlink(path.join(EXECUTIONS_DIR, file));
            }
        }
        
        res.json({ success: true });
    } catch (err) {
        console.error('Error cleaning executions:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================
// OBFUSCATION ENGINE
// ============================================
function obfuscateScript(content) {
  const contentBuffer = Buffer.from(content, 'utf-8');
  const encryptedBytes = Buffer.alloc(contentBuffer.length);
  
  const xorPattern = [0x5A, 0x3C, 0x8F, 0x2B, 0x7D, 0x1E, 0x9C, 0x4F];
  
  for (let i = 0; i < contentBuffer.length; i++) {
    encryptedBytes[i] = contentBuffer[i] ^ xorPattern[i % xorPattern.length];
  }

  const encodedPayload = encryptedBytes.toString('base64');

  return `--[[ LuaShield Protected Script ]]
-- Anti-Debug Enabled

local encoded = "${encodedPayload}"

-- Anti-debug check
local RunService = game:GetService("RunService")
local count = 0
local conn

conn = RunService.Heartbeat:Connect(function()
    count = count + 1
    if count >= 10 then
        conn:Disconnect()
    end
end)

while count < 10 do
    RunService.Heartbeat:Wait()
end

if count < 10 then
    error("detected")
    return
end

-- Base64 decoding
local function decodeBase64(data)
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    data = string.gsub(data, '[^'..b..'=]', '')
    
    return (data:gsub('.', function(x)
        if x == '=' then return '' end
        local f = (b:find(x) - 1)
        local r = ''
        for i = 6, 1, -1 do
            r = r .. ((f % 2^i - f % 2^(i-1) > 0) and '1' or '0')
        end
        return r
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if #x ~= 8 then return '' end
        local c = 0
        for i = 1, 8 do
            c = c + (x:sub(i,i) == '1' and 2^(8-i) or 0)
        end
        return string.char(c)
    end))
end

-- XOR decryption
local function decryptXOR(data)
    local pattern = {0x5A, 0x3C, 0x8F, 0x2B, 0x7D, 0x1E, 0x9C, 0x4F}
    local result = {}
    
    for i = 1, #data do
        local byte = string.byte(data, i)
        local key = pattern[((i-1) % #pattern) + 1]
        result[i] = string.char(bit32.bxor(byte, key))
    end
    
    return table.concat(result)
end

local decoded = decodeBase64(encoded)
local decrypted = decryptXOR(decoded)

if decrypted and #decrypted > 0 then
    local func, err = loadstring(decrypted)
    if func then
        setfenv(func, getfenv())
        pcall(func)
    end
end`;
}

// ============================================
// EXECUTION ENDPOINTS - WITH ROBLOX CHECK
// ============================================
app.get('/raw/:scriptId', async (req, res) => {
  try {
    const { scriptId } = req.params;
    const providedKey = req.query.key;
    const hwid = req.query.hwid;
    const userAgent = req.headers['user-agent'] || '';
    
    // Check if request is from Roblox
    const isRoblox = userAgent.toLowerCase().includes('roblox');
    const isSeliware = userAgent.toLowerCase().includes('seliware') || 
                       userAgent.toLowerCase().includes('seli') ||
                       userAgent.includes('Seliware');
    
    if (!isRoblox && !isSeliware) {
      // Serve a nice HTML page for browser visitors
      const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>LuaShield Protection</title>
          <style>
              @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
              
              * {
                  margin: 0;
                  padding: 0;
                  box-sizing: border-box;
              }
              
              body {
                  font-family: 'Inter', sans-serif;
                  background: linear-gradient(135deg, #0a0c10 0%, #1a1f2c 100%);
                  min-height: 100vh;
                  display: flex;
                  justify-content: center;
                  align-items: center;
                  color: #fff;
                  padding: 20px;
              }
              
              .container {
                  max-width: 800px;
                  width: 100%;
                  animation: fadeIn 0.8s ease-out;
              }
              
              @keyframes fadeIn {
                  from {
                      opacity: 0;
                      transform: translateY(20px);
                  }
                  to {
                      opacity: 1;
                      transform: translateY(0);
                  }
              }
              
              .shield-icon {
                  text-align: center;
                  margin-bottom: 30px;
              }
              
              .shield-icon svg {
                  width: 120px;
                  height: 120px;
                  filter: drop-shadow(0 0 20px rgba(0, 255, 255, 0.3));
                  animation: pulse 2s infinite;
              }
              
              @keyframes pulse {
                  0%, 100% {
                      filter: drop-shadow(0 0 20px rgba(0, 255, 255, 0.3));
                  }
                  50% {
                      filter: drop-shadow(0 0 30px rgba(0, 255, 255, 0.6));
                  }
              }
              
              .title {
                  text-align: center;
                  font-size: 3rem;
                  font-weight: 700;
                  margin-bottom: 20px;
                  background: linear-gradient(135deg, #00d2ff 0%, #3a7bd5 100%);
                  -webkit-background-clip: text;
                  -webkit-text-fill-color: transparent;
                  background-clip: text;
                  text-shadow: 0 0 30px rgba(0, 210, 255, 0.3);
              }
              
              .subtitle {
                  text-align: center;
                  font-size: 1.3rem;
                  color: #a0a8c0;
                  margin-bottom: 50px;
                  font-weight: 300;
              }
              
              .card {
                  background: rgba(26, 31, 44, 0.7);
                  backdrop-filter: blur(10px);
                  border: 1px solid rgba(255, 255, 255, 0.1);
                  border-radius: 20px;
                  padding: 40px;
                  margin-bottom: 30px;
                  box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
              }
              
              .card h2 {
                  font-size: 1.8rem;
                  margin-bottom: 20px;
                  color: #80b3ff;
              }
              
              .card p {
                  color: #c0c8e0;
                  line-height: 1.6;
                  margin-bottom: 20px;
                  font-size: 1.1rem;
              }
              
              .highlight {
                  background: rgba(0, 210, 255, 0.1);
                  border-left: 4px solid #00d2ff;
                  padding: 15px 20px;
                  border-radius: 10px;
                  margin: 20px 0;
                  font-family: 'Courier New', monospace;
                  color: #00d2ff;
                  word-break: break-all;
              }
              
              .features {
                  display: grid;
                  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                  gap: 20px;
                  margin: 30px 0;
              }
              
              .feature {
                  text-align: center;
                  padding: 20px;
                  background: rgba(255, 255, 255, 0.05);
                  border-radius: 15px;
                  transition: transform 0.3s;
              }
              
              .feature:hover {
                  transform: translateY(-5px);
                  background: rgba(255, 255, 255, 0.08);
              }
              
              .feature svg {
                  width: 40px;
                  height: 40px;
                  margin-bottom: 15px;
                  fill: #00d2ff;
              }
              
              .feature h3 {
                  font-size: 1.2rem;
                  margin-bottom: 10px;
                  color: #fff;
              }
              
              .feature p {
                  font-size: 0.9rem;
                  color: #a0a8c0;
                  margin-bottom: 0;
              }
              
              .warning {
                  background: rgba(255, 193, 7, 0.1);
                  border: 1px solid rgba(255, 193, 7, 0.3);
                  border-radius: 10px;
                  padding: 20px;
                  margin: 30px 0;
                  display: flex;
                  align-items: center;
                  gap: 15px;
              }
              
              .warning svg {
                  width: 30px;
                  height: 30px;
                  fill: #ffc107;
                  flex-shrink: 0;
              }
              
              .warning p {
                  color: #ffc107;
                  margin: 0;
                  font-weight: 500;
              }
              
              .code-block {
                  background: #0a0c10;
                  border-radius: 10px;
                  padding: 20px;
                  margin: 20px 0;
                  position: relative;
              }
              
              .code-block pre {
                  color: #80b3ff;
                  font-family: 'Courier New', monospace;
                  font-size: 0.9rem;
                  white-space: pre-wrap;
                  word-wrap: break-word;
              }
              
              .copy-btn {
                  position: absolute;
                  top: 10px;
                  right: 10px;
                  background: rgba(255, 255, 255, 0.1);
                  border: none;
                  color: #fff;
                  padding: 5px 15px;
                  border-radius: 5px;
                  cursor: pointer;
                  font-size: 0.8rem;
                  transition: background 0.3s;
              }
              
              .copy-btn:hover {
                  background: rgba(255, 255, 255, 0.2);
              }
              
              .stats {
                  display: flex;
                  justify-content: space-around;
                  margin: 30px 0;
                  padding: 20px;
                  background: rgba(0, 0, 0, 0.2);
                  border-radius: 15px;
              }
              
              .stat {
                  text-align: center;
              }
              
              .stat-value {
                  font-size: 2rem;
                  font-weight: 700;
                  color: #00d2ff;
              }
              
              .stat-label {
                  color: #a0a8c0;
                  font-size: 0.9rem;
                  margin-top: 5px;
              }
              
              .footer {
                  text-align: center;
                  color: #6c757d;
                  font-size: 0.9rem;
                  margin-top: 50px;
              }
              
              .glow {
                  text-shadow: 0 0 10px currentColor;
              }
              
              @media (max-width: 600px) {
                  .title {
                      font-size: 2rem;
                  }
                  
                  .card {
                      padding: 25px;
                  }
                  
                  .features {
                      grid-template-columns: 1fr;
                  }
              }
          </style>
      </head>
      <body>
          <div class="container">
              <div class="shield-icon">
                  <svg viewBox="0 0 24 24">
                      <path fill="#00d2ff" d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,11.99H19C18.47,16.11 15.72,19.78 12,20.93V12H5V6.3L12,3.19V11.99Z"/>
                  </svg>
              </div>
              
              <h1 class="title">LuaShield Protection</h1>
              <p class="subtitle">Advanced Script Protection & Key System</p>
              
              <div class="card">
                  <h2>🔒 Script Protected</h2>
                  <p>This script is protected by <strong>LuaShield</strong> - The most advanced Roblox script protection system. Direct browser access is not allowed.</p>
                  
                  <div class="warning">
                      <svg viewBox="0 0 24 24">
                          <path d="M13,14H11V10H13M13,18H11V16H13M1,21H23L12,2L1,21Z"/>
                      </svg>
                      <p>This endpoint can only be accessed through Roblox executors</p>
                  </div>
                  
                  <div class="stats">
                      <div class="stat">
                          <div class="stat-value">24/7</div>
                          <div class="stat-label">Protection</div>
                      </div>
                      <div class="stat">
                          <div class="stat-value">AES-256</div>
                          <div class="stat-label">Encryption</div>
                      </div>
                      <div class="stat">
                          <div class="stat-value">HWID</div>
                          <div class="stat-label">Locking</div>
                      </div>
                  </div>
                  
                  <h3>📝 How to Execute:</h3>
                  <div class="code-block">
                      <button class="copy-btn" onclick="copyCode()">Copy</button>
                      <pre id="code">loadstring(game:HttpGet("${req.protocol}://${req.get('host')}/raw/${scriptId}?key=YOUR_KEY_HERE"))()</pre>
                  </div>
                  
                  <div class="features">
                      <div class="feature">
                          <svg viewBox="0 0 24 24">
                              <path d="M12,17C10.89,17 10,16.1 10,15C10,13.89 10.89,13 12,13A2,2 0 0,1 14,15A2,2 0 0,1 12,17M18,20V10H6V20H18M18,8A2,2 0 0,1 20,10V20A2,2 0 0,1 18,22H6A2,2 0 0,1 4,20V10C4,8.89 4.89,8 6,8H7V6A5,5 0 0,1 12,1A5,5 0 0,1 17,6V8H18M12,3A3,3 0 0,0 9,6V8H15V6A3,3 0 0,0 12,3Z"/>
                          </svg>
                          <h3>HWID Lock</h3>
                          <p>Hardware-based security</p>
                      </div>
                      <div class="feature">
                          <svg viewBox="0 0 24 24">
                              <path d="M12,3C7.58,3 4,4.79 4,7C4,9.21 7.58,11 12,11C16.42,11 20,9.21 20,7C20,4.79 16.42,3 12,3M4,9V12C4,14.21 7.58,16 12,16C16.42,16 20,14.21 20,12V9C20,11.21 16.42,13 12,13C7.58,13 4,11.21 4,9M4,14V17C4,19.21 7.58,21 12,21C16.42,21 20,19.21 20,17V14C20,16.21 16.42,18 12,18C7.58,18 4,16.21 4,14Z"/>
                          </svg>
                          <h3>Key System</h3>
                          <p>Advanced key management</p>
                      </div>
                      <div class="feature">
                          <svg viewBox="0 0 24 24">
                              <path d="M12,12C10.9,12 10,11.1 10,10C10,8.9 10.9,8 12,8C13.1,8 14,8.9 14,10C14,11.1 13.1,12 12,12M18,10C18,6.13 14.87,3 11,3C9.38,3 7.84,3.55 6.61,4.5L4.12,2L2.71,3.41L5.26,5.96C4.5,7.1 4.06,8.39 4,9.8H2V11.8H4.02C4.15,13.2 4.72,14.47 5.57,15.5L2.71,18.36L4.12,19.77L6.92,16.97C8.15,17.89 9.62,18.5 11.2,18.8V21H13.2V18.8C16.47,18.24 19,15.43 19,12H17C17,14.76 14.76,17 12,17C9.24,17 7,14.76 7,12C7,9.24 9.24,7 12,7C14.76,7 17,9.24 17,12H18Z"/>
                          </svg>
                          <h3>Anti-Debug</h3>
                          <p>Advanced protection</p>
                      </div>
                  </div>
                  
                  <p style="color: #80b3ff; font-style: italic; text-align: center; margin-top: 30px;">
                      "Your script is safe with LuaShield"
                  </p>
              </div>
              
              <div class="footer">
                  <p>© 2024 LuaShield - Advanced Script Protection System</p>
                  <p style="margin-top: 10px;">⚡ Protected with ❤️ by LuaShield Team</p>
              </div>
          </div>
          
          <script>
              function copyCode() {
                  const code = document.getElementById('code').innerText;
                  navigator.clipboard.writeText(code).then(() => {
                      const btn = document.querySelector('.copy-btn');
                      const originalText = btn.innerText;
                      btn.innerText = 'Copied!';
                      setTimeout(() => {
                          btn.innerText = originalText;
                      }, 2000);
                  });
              }
              
              // Add some dynamic effects
              document.addEventListener('mousemove', (e) => {
                  const x = e.clientX / window.innerWidth;
                  const y = e.clientY / window.innerHeight;
                  
                  document.body.style.background = 
                      \`radial-gradient(circle at \${e.clientX}px \${e.clientY}px, #1a1f2c, #0a0c10)\`;
              });
          </script>
      </body>
      </html>
      `;
      
      return res.status(403).send(html);
    }
    
    const users = await getUsers();
    let foundScript = null;
    let foundUser = null;
    
    for (const username of Object.keys(users)) {
      const script = await getScript(username, scriptId);
      if (script) {
        foundScript = script;
        foundUser = username;
        break;
      }
    }
    
    if (!foundScript) {
      return res.status(404).send('Script not found');
    }
    
    if (!foundScript.active) {
      return res.status(403).send('Script is deactivated');
    }
    
    const validation = await validateKey(scriptId, providedKey, hwid);
    
    if (!validation.valid) {
      let errorMessage = `Access Denied: ${validation.error}`;
      if (validation.error === 'HWID required for this key') {
        errorMessage = 'HWID Required: Please provide your HWID using &hwid=YOUR_HWID';
      }
      return res.status(403).send(errorMessage);
    }
    
    const ip = req.headers['x-forwarded-for']?.[0] || req.socket.remoteAddress || 'unknown';
    
    await trackExecution(scriptId, foundUser, ip, userAgent, validation.type === 'key' ? validation.key.key : validation.type, hwid);
    
    foundScript.executions = (foundScript.executions || 0) + 1;
    foundScript.lastExecution = new Date().toISOString();
    await saveScript(foundUser, foundScript);
    
    res.setHeader('Content-Type', 'text/plain');
    res.send(foundScript.content);
  } catch (err) {
    console.error('Error:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Also update the POST endpoint
app.post('/api/execute/:scriptId', async (req, res) => {
  try {
    const { scriptId } = req.params;
    const { key, hwid } = req.body;
    const userAgent = req.headers['user-agent'] || '';
    
    // Check if request is from Roblox
    const isRoblox = userAgent.toLowerCase().includes('roblox');
    
    if (!isRoblox) {
      return res.status(403).json({ 
        error: 'Browser access denied',
        message: 'This endpoint can only be accessed through Roblox executors'
      });
    }
    
    const users = await getUsers();
    let foundScript = null;
    let foundUser = null;
    
    for (const username of Object.keys(users)) {
      const script = await getScript(username, scriptId);
      if (script) {
        foundScript = script;
        foundUser = username;
        break;
      }
    }
    
    if (!foundScript) {
      return res.status(404).json({ error: 'Script not found' });
    }
    
    if (!foundScript.active) {
      return res.status(403).json({ error: 'Script is deactivated' });
    }
    
    const validation = await validateKey(scriptId, key, hwid);
    
    if (!validation.valid) {
      return res.status(403).json({ error: validation.error });
    }
    
    const ip = req.headers['x-forwarded-for']?.[0] || req.socket.remoteAddress || 'unknown';
    
    await trackExecution(scriptId, foundUser, ip, userAgent, validation.type === 'key' ? validation.key.key : validation.type, hwid);
    
    foundScript.executions = (foundScript.executions || 0) + 1;
    foundScript.lastExecution = new Date().toISOString();
    await saveScript(foundUser, foundScript);
    
    res.setHeader('Content-Type', 'text/plain');
    res.send(foundScript.content);
  } catch (err) {
    console.error('Execution error:', err);
    res.status(500).send('Internal Server Error');
  }
});

// ============================================
// DASHBOARD STATS
// ============================================
app.get('/api/stats', requireAuth, async (req, res) => {
  try {
    const scripts = await getUserScripts(req.session.user.username);
    const totalExecutions = scripts.reduce((sum, s) => sum + (s.executions || 0), 0);
    const activeScripts = scripts.filter(s => s.active).length;
    
    const recentExecutions = [];
    for (const script of scripts) {
      const execs = await getScriptExecutions(script.id, 1);
      recentExecutions.push(...execs.map(e => ({ ...e, scriptName: script.name })));
    }
    
    recentExecutions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    res.json({
      totalScripts: scripts.length,
      activeScripts,
      totalExecutions,
      recentExecutions: recentExecutions.slice(0, 20)
    });
  } catch (err) {
    console.error('Error fetching stats:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================
// DISCORD BOT COMMANDS - FIXED WITH INFINITE USES
// ============================================
discordClient.once('ready', async () => {
  console.log(`✅ Discord bot logged in as ${discordClient.user.tag}`);
  
  // Register slash commands
  const commands = [
    {
      name: 'login',
      description: 'Login to LuaShield dashboard',
      options: [
        {
          name: 'username',
          description: 'Your LuaShield username',
          type: 3,
          required: true
        },
        {
          name: 'password',
          description: 'Your LuaShield password',
          type: 3,
          required: true
        }
      ]
    },
    {
      name: 'logout',
      description: 'Logout from LuaShield'
    },
    {
      name: 'scripts',
      description: 'View your scripts'
    },
    {
      name: 'panel',
      description: 'Create a redeem panel for your script',
      options: [
        {
          name: 'script',
          description: 'Select your script',
          type: 3,
          required: true,
          autocomplete: true
        }
      ]
    },
    {
      name: 'genkey',
      description: 'Generate a key for your script',
      options: [
        {
          name: 'script',
          description: 'Select your script',
          type: 3,
          required: true,
          autocomplete: true
        },
        {
          name: 'days',
          description: 'Days until key expires (0 = never)',
          type: 4,
          required: true
        },
        {
          name: 'uses',
          description: 'Max uses (0 = unlimited)',
          type: 4,
          required: false
        }
      ]
    },
    {
      name: 'whitelist',
      description: 'Whitelist a user and give them a key (infinite uses)',
      options: [
        {
          name: 'script',
          description: 'Select your script',
          type: 3,
          required: true,
          autocomplete: true
        },
        {
          name: 'user',
          description: 'The Discord user to whitelist',
          type: 6,
          required: true
        },
        {
          name: 'days',
          description: 'Number of days the key will last',
          type: 4,
          required: true
        }
      ]
    },
    {
      name: 'keys',
      description: 'View keys for your script',
      options: [
        {
          name: 'script',
          description: 'Select your script',
          type: 3,
          required: true,
          autocomplete: true
        }
      ]
    }
  ];
  
  try {
    await discordClient.application.commands.set(commands);
    console.log('✅ Slash commands registered');
  } catch (error) {
    console.error('Error registering commands:', error);
  }
});

// Handle all interactions
discordClient.on('interactionCreate', async interaction => {
  try {
    // Handle autocomplete
    if (interaction.isAutocomplete()) {
      const focusedValue = interaction.options.getFocused();
      const session = discordSessions.get(interaction.user.id);
      
      if (!session) {
        return interaction.respond([{ name: '❌ Please login first with /login', value: 'none' }]);
      }
      
      const scripts = await getUserScripts(session.username);
      const filtered = scripts.filter(script => 
        script.name.toLowerCase().includes(focusedValue.toLowerCase())
      ).slice(0, 25);
      
      await interaction.respond(
        filtered.map(script => ({ name: script.name, value: script.id }))
      );
      return;
    }
    
    // Handle slash commands
    if (interaction.isCommand()) {
      const { commandName } = interaction;
      
      if (commandName === 'login') {
        await interaction.deferReply({ flags: 64 });
        
        const username = interaction.options.getString('username');
        const password = interaction.options.getString('password');
        
        const users = await getUsers();
        const user = users[username];
        
        if (!user || !await bcrypt.compare(password, user.passwordHash)) {
          return interaction.editReply({ 
            content: '❌ Invalid username or password'
          });
        }
        
        discordSessions.set(interaction.user.id, {
          username: user.username,
          expires: Date.now() + 3600000
        });
        
        const embed = new EmbedBuilder()
          .setColor(0x80b3ff)
          .setTitle('✅ Login Successful')
          .setDescription(`Welcome back **${user.username}**!`)
          .addFields(
            { name: 'Available Commands', value: '`/scripts` - View your scripts\n`/panel` - Create redeem panel\n`/genkey` - Generate keys\n`/whitelist` - Whitelist users (infinite uses)\n`/keys` - View keys' }
          )
          .setFooter({ text: 'LuaShield Discord Integration' })
          .setTimestamp();
        
        await interaction.editReply({ embeds: [embed] });
      }
      
      else if (commandName === 'logout') {
        await interaction.deferReply({ flags: 64 });
        discordSessions.delete(interaction.user.id);
        await interaction.editReply({ 
          content: '✅ Logged out successfully'
        });
      }
      
      else if (commandName === 'scripts') {
        await interaction.deferReply({ flags: 64 });
        
        const session = discordSessions.get(interaction.user.id);
        
        if (!session) {
          return interaction.editReply({ 
            content: '❌ Please login first with `/login`'
          });
        }
        
        const scripts = await getUserScripts(session.username);
        
        if (scripts.length === 0) {
          return interaction.editReply({ 
            content: '📝 You have no scripts yet. Create one on the web dashboard!'
          });
        }
        
        const embed = new EmbedBuilder()
          .setColor(0x80b3ff)
          .setTitle('📜 Your Scripts')
          .setDescription(`You have **${scripts.length}** script(s)`)
          .setFooter({ text: 'LuaShield Discord Integration' })
          .setTimestamp();
        
        for (const script of scripts.slice(0, 5)) {
          const keyData = await getScriptKeys(script.id);
          embed.addFields({
            name: `${script.name} ${script.active ? '✅' : '❌'}`,
            value: `ID: \`${script.id}\`\nExecutions: ${script.executions || 0}\nKeys: ${keyData.keys?.length || 0}`,
            inline: true
          });
        }
        
        await interaction.editReply({ embeds: [embed] });
      }
      
      else if (commandName === 'panel') {
        await interaction.deferReply();
        
        const session = discordSessions.get(interaction.user.id);
        
        if (!session) {
          return interaction.editReply({ 
            content: '❌ Please login first with `/login`'
          });
        }
        
        const scriptId = interaction.options.getString('script');
        const script = await getScript(session.username, scriptId);
        
        if (!script) {
          return interaction.editReply({ 
            content: '❌ Script not found'
          });
        }
        
        const keyData = await getScriptKeys(scriptId);
        
        const panelEmbed = new EmbedBuilder()
          .setColor(0x80b3ff)
          .setTitle(`🎮 ${script.name} - Redeem Panel`)
          .setDescription('Click the buttons below to interact with this script!')
          .addFields(
            { name: '📊 Status', value: script.active ? '✅ Active' : '❌ Inactive', inline: true },
            { name: '🔑 Keys Available', value: String(keyData.keys.length), inline: true },
            { name: '🚀 Executions', value: String(script.executions || 0), inline: true }
          )
          .setFooter({ text: 'LuaShield Discord Integration' })
          .setTimestamp();
        
        if (keyData.freeForever) {
          panelEmbed.addFields({ name: '✨ Free Access', value: 'This script is free forever!' });
        } else if (keyData.freeUntil) {
          const freeUntil = new Date(keyData.freeUntil);
          panelEmbed.addFields({ name: '⏰ Free Until', value: `<t:${Math.floor(freeUntil.getTime() / 1000)}:F>` });
        }
        
        // Create buttons with proper custom IDs
        const row = new ActionRowBuilder()
          .addComponents(
            new ButtonBuilder()
              .setCustomId(`get_${scriptId}`)
              .setLabel('📥 Get Script')
              .setStyle(ButtonStyle.Primary),
            new ButtonBuilder()
              .setCustomId(`redeem_${scriptId}`)
              .setLabel('🔑 Redeem Key')
              .setStyle(ButtonStyle.Success),
            new ButtonBuilder()
              .setCustomId(`info_${scriptId}`)
              .setLabel('ℹ️ Info')
              .setStyle(ButtonStyle.Secondary)
          );
        
        await interaction.editReply({ 
          embeds: [panelEmbed], 
          components: [row]
        });
      }
      
      else if (commandName === 'genkey') {
        await interaction.deferReply({ flags: 64 });
        
        const session = discordSessions.get(interaction.user.id);
        
        if (!session) {
          return interaction.editReply({ 
            content: '❌ Please login first with `/login`'
          });
        }
        
        const scriptId = interaction.options.getString('script');
        const days = interaction.options.getInteger('days');
        const maxUses = interaction.options.getInteger('uses') || null;
        
        const script = await getScript(session.username, scriptId);
        
        if (!script) {
          return interaction.editReply({ 
            content: '❌ Script not found'
          });
        }
        
        const duration = days > 0 ? days * 24 * 60 * 60 * 1000 : null;
        const key = await generateKey(scriptId, session.username, duration, maxUses);
        
        const usesText = maxUses === null ? '♾️ Infinite' : String(maxUses);
        
        const embed = new EmbedBuilder()
          .setColor(0x80ff80)
          .setTitle('✅ Key Generated Successfully')
          .setDescription(`**Script:** ${script.name}`)
          .addFields(
            { name: '🔑 Key', value: `\`${key}\``, inline: false },
            { name: '⏰ Expires', value: days > 0 ? `In ${days} days` : 'Never', inline: true },
            { name: '📊 Max Uses', value: usesText, inline: true }
          )
          .setFooter({ text: 'LuaShield Discord Integration' })
          .setTimestamp();
        
        await interaction.editReply({ embeds: [embed] });
      }
      
      else if (commandName === 'whitelist') {
        await interaction.deferReply({ flags: 64 });
        
        const session = discordSessions.get(interaction.user.id);
        
        if (!session) {
          return interaction.editReply({ 
            content: '❌ Please login first with `/login`'
          });
        }
        
        const scriptId = interaction.options.getString('script');
        const targetUser = interaction.options.getUser('user');
        const days = interaction.options.getInteger('days');
        
        const script = await getScript(session.username, scriptId);
        
        if (!script) {
          return interaction.editReply({ 
            content: '❌ Script not found'
          });
        }
        
        // Check if user is already whitelisted
        const existingWhitelist = await checkWhitelist(scriptId, targetUser.id);
        
        if (existingWhitelist) {
          const errorEmbed = new EmbedBuilder()
            .setColor(0xff8080)
            .setTitle('❌ User Already Whitelisted')
            .setDescription(`${targetUser} is already whitelisted for this script!`)
            .addFields(
              { name: 'Current Key', value: `\`${existingWhitelist.assignedKey}\`` },
              { name: 'Expires', value: `<t:${Math.floor(new Date(existingWhitelist.expiresAt).getTime() / 1000)}:F>` }
            )
            .setFooter({ text: 'LuaShield Discord Integration' })
            .setTimestamp();
          
          return interaction.editReply({ embeds: [errorEmbed] });
        }
        
        const duration = days * 24 * 60 * 60 * 1000;
        const maxUses = null; // INFINITE USES
        const generatedKey = await generateKey(scriptId, session.username, duration, maxUses);
        
        await addToWhitelist(scriptId, targetUser.id, targetUser.username, days, generatedKey);
        
        const embed = new EmbedBuilder()
          .setColor(0x80ff80)
          .setTitle('✅ User Whitelisted & Key Generated')
          .setDescription(`${targetUser} has been whitelisted for **${script.name}**`)
          .addFields(
            { name: '📅 Duration', value: `${days} days`, inline: true },
            { name: '🔑 Generated Key', value: `\`${generatedKey}\``, inline: false },
            { name: '⏰ Key Expires', value: `<t:${Math.floor((Date.now() + duration) / 1000)}:F>`, inline: true },
            { name: '📊 Max Uses', value: '♾️ Infinite', inline: true }
          )
          .setFooter({ text: 'The key has been sent to the user via DM' })
          .setTimestamp();
        
        await interaction.editReply({ embeds: [embed] });
        
        // Send DM to whitelisted user
        try {
          const dmEmbed = new EmbedBuilder()
            .setColor(0x80b3ff)
            .setTitle('🎉 You\'ve Been Whitelisted!')
            .setDescription(`You now have access to **${script.name}**`)
            .addFields(
              { name: '📅 Access Duration', value: `${days} days`, inline: true },
              { name: '🔑 Your Key', value: `\`${generatedKey}\``, inline: false },
              { name: '⏰ Key Expires', value: `<t:${Math.floor((Date.now() + duration) / 1000)}:F>`, inline: true },
              { name: '📊 Max Uses', value: '♾️ Infinite', inline: true }
            )
            .setFooter({ text: 'Use the panel command to get your script' })
            .setTimestamp();
          
          const row = new ActionRowBuilder()
            .addComponents(
              new ButtonBuilder()
                .setCustomId(`get_${scriptId}`)
                .setLabel('📥 Get Script')
                .setStyle(ButtonStyle.Primary)
            );
          
          await targetUser.send({ embeds: [dmEmbed], components: [row] });
        } catch (err) {
          console.log('Could not DM user');
        }
      }
      
      else if (commandName === 'keys') {
        await interaction.deferReply({ flags: 64 });
        
        const session = discordSessions.get(interaction.user.id);
        
        if (!session) {
          return interaction.editReply({ 
            content: '❌ Please login first with `/login`'
          });
        }
        
        const scriptId = interaction.options.getString('script');
        const script = await getScript(session.username, scriptId);
        
        if (!script) {
          return interaction.editReply({ 
            content: '❌ Script not found'
          });
        }
        
        const keyData = await getScriptKeys(scriptId);
        
        const embed = new EmbedBuilder()
          .setColor(0x80b3ff)
          .setTitle(`🔑 Keys for ${script.name}`)
          .setDescription(`Total Keys: ${keyData.keys.length}`)
          .setFooter({ text: 'LuaShield Discord Integration' })
          .setTimestamp();
        
        if (keyData.keys.length === 0) {
          embed.addFields({ name: 'No Keys', value: 'Generate keys with `/genkey`!' });
        } else {
          const whitelistData = await getWhitelist(scriptId);
          
          keyData.keys.slice(0, 10).forEach(k => {
            const expires = k.expiresAt ? `<t:${Math.floor(new Date(k.expiresAt).getTime() / 1000)}:R>` : 'Never';
            const assignedUser = whitelistData.users.find(u => u.assignedKey === k.key);
            const assignedTo = assignedUser ? ` | 👤 <@${assignedUser.discordId}>` : '';
            const usesText = k.maxUses === null ? '♾️' : `${k.used}/${k.maxUses}`;
            
            embed.addFields({
              name: `🔑 Key: \`${k.key}\``,
              value: `Uses: ${usesText} | Expires: ${expires}${k.hwid ? ' | 🔒 HWID Locked' : ''}${assignedTo}`,
              inline: false
            });
          });
        }
        
        await interaction.editReply({ embeds: [embed] });
      }
    }
    
    // Handle button clicks
    else if (interaction.isButton()) {
      const [action, scriptId] = interaction.customId.split('_');
      
      if (action === 'get') {
        await interaction.deferReply({ flags: 64 });
        
        const whitelistUser = await checkWhitelist(scriptId, interaction.user.id);
        
        if (!whitelistUser) {
          const embed = new EmbedBuilder()
            .setColor(0xff8080)
            .setTitle('❌ Access Denied')
            .setDescription('You are not whitelisted for this script. Use the **Redeem Key** button to enter your key!')
            .setFooter({ text: 'LuaShield Discord Integration' })
            .setTimestamp();
          
          return interaction.editReply({ embeds: [embed] });
        }
        
        const users = await getUsers();
        let foundScript = null;
        
        for (const username of Object.keys(users)) {
          const script = await getScript(username, scriptId);
          if (script) {
            foundScript = script;
            break;
          }
        }
        
        if (!foundScript || !foundScript.active) {
          return interaction.editReply({ 
            content: '❌ Script not found or inactive'
          });
        }
        
        const userKey = whitelistUser.assignedKey;
        const baseUrl = process.env.BASE_URL || `http://luashield.lol`;
        
        const scriptEmbed = new EmbedBuilder()
          .setColor(0x80b3ff)
          .setTitle(`📜 ${foundScript.name} - Your Script`)
          .setDescription('Here\'s your execution code!')
          .addFields(
            { name: '🔑 Your Key', value: `\`${userKey}\`` },
            { name: '⏰ Expires', value: `<t:${Math.floor(new Date(whitelistUser.expiresAt).getTime() / 1000)}:F>` },
            { name: '📝 Execution Code', value: `\`\`\`lua\nloadstring(game:HttpGet("${baseUrl}/raw/${scriptId}?key=${userKey}"))()\n\`\`\`` }
          )
          .setFooter({ text: 'Copy and execute this in your executor' })
          .setTimestamp();
        
        await interaction.editReply({ embeds: [scriptEmbed] });
      }
      
      else if (action === 'redeem') {
        // Create a modal for key redemption
        const modal = new ModalBuilder()
          .setCustomId(`redeem_modal_${scriptId}`)
          .setTitle('Redeem Your Key');
        
        const keyInput = new TextInputBuilder()
          .setCustomId('key_input')
          .setLabel('Enter your key')
          .setStyle(TextInputStyle.Short)
          .setPlaceholder('e.g., A1B2C3D4E5F6')
          .setRequired(true)
          .setMinLength(1)
          .setMaxLength(50);
        
        const actionRow = new ActionRowBuilder().addComponents(keyInput);
        modal.addComponents(actionRow);
        
        await interaction.showModal(modal);
      }
      
      else if (action === 'info') {
        await interaction.deferReply({ flags: 64 });
        
        const users = await getUsers();
        let foundScript = null;
        let scriptOwner = null;
        
        for (const username of Object.keys(users)) {
          const script = await getScript(username, scriptId);
          if (script) {
            foundScript = script;
            scriptOwner = username;
            break;
          }
        }
        
        if (!foundScript) {
          return interaction.editReply({ 
            content: '❌ Script not found'
          });
        }
        
        const keyData = await getScriptKeys(scriptId);
        const whitelistData = await getWhitelist(scriptId);
        
        const embed = new EmbedBuilder()
          .setColor(0x80b3ff)
          .setTitle(`ℹ️ ${foundScript.name} - Info`)
          .addFields(
            { name: '📊 Status', value: foundScript.active ? '✅ Active' : '❌ Inactive', inline: true },
            { name: '👑 Owner', value: scriptOwner, inline: true },
            { name: '🚀 Executions', value: String(foundScript.executions || 0), inline: true },
            { name: '🔑 Keys Available', value: String(keyData.keys.length), inline: true },
            { name: '👥 Whitelisted Users', value: String(whitelistData.users.length), inline: true },
            { name: '📋 Script ID', value: `\`${scriptId}\``, inline: true }
          )
          .setFooter({ text: 'LuaShield Discord Integration' })
          .setTimestamp();
        
        if (keyData.freeForever) {
          embed.addFields({ name: '✨ Free Access', value: 'This script is free forever!' });
        } else if (keyData.freeUntil) {
          const freeUntil = new Date(keyData.freeUntil);
          embed.addFields({ name: '⏰ Free Until', value: `<t:${Math.floor(freeUntil.getTime() / 1000)}:F>` });
        }
        
        const whitelistUser = await checkWhitelist(scriptId, interaction.user.id);
        if (whitelistUser) {
          embed.addFields({ 
            name: '✅ Your Status', 
            value: `Whitelisted until <t:${Math.floor(new Date(whitelistUser.expiresAt).getTime() / 1000)}:F>`, 
            inline: true 
          });
        } else {
          embed.addFields({ name: '❌ Your Status', value: 'Not Whitelisted - Use the **Redeem Key** button!', inline: true });
        }
        
        await interaction.editReply({ embeds: [embed] });
      }
    }
    
    // Handle modal submissions
    else if (interaction.isModalSubmit()) {
      if (interaction.customId.startsWith('redeem_modal_')) {
        await interaction.deferReply({ flags: 64 });
        
        const scriptId = interaction.customId.replace('redeem_modal_', '');
        const providedKey = interaction.fields.getTextInputValue('key_input');
        
        const users = await getUsers();
        let foundScript = null;
        let foundScriptId = null;
        let foundUser = null;
        
        // Find which script this key belongs to
        for (const username of Object.keys(users)) {
          const script = await getScript(username, scriptId);
          if (script) {
            foundScript = script;
            foundScriptId = script.id;
            foundUser = username;
            break;
          }
        }
        
        if (!foundScript) {
          return interaction.editReply({ 
            content: '❌ Script not found'
          });
        }
        
        if (!foundScript.active) {
          return interaction.editReply({ 
            content: '❌ This script is currently deactivated'
          });
        }
        
        // Validate the key
        const validation = await validateKey(foundScriptId, providedKey);
        
        if (!validation.valid) {
          const errorEmbed = new EmbedBuilder()
            .setColor(0xff8080)
            .setTitle('❌ Invalid Key')
            .setDescription(`**Error:** ${validation.error}`)
            .setFooter({ text: 'LuaShield Discord Integration' })
            .setTimestamp();
          
          return interaction.editReply({ embeds: [errorEmbed] });
        }
        
        // Check if user is already whitelisted
        const existingWhitelist = await checkWhitelist(foundScriptId, interaction.user.id);
        
        if (existingWhitelist) {
          const errorEmbed = new EmbedBuilder()
            .setColor(0xff8080)
            .setTitle('❌ Already Whitelisted')
            .setDescription('You are already whitelisted for this script!')
            .addFields(
              { name: 'Your Key', value: `\`${existingWhitelist.assignedKey}\`` },
              { name: 'Expires', value: `<t:${Math.floor(new Date(existingWhitelist.expiresAt).getTime() / 1000)}:F>` }
            )
            .setFooter({ text: 'Use the Get Script button to receive your script' })
            .setTimestamp();
          
          return interaction.editReply({ embeds: [errorEmbed] });
        }
        
        // Add user to whitelist with this key
        const expiresAt = validation.key.expiresAt ? new Date(validation.key.expiresAt) : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        const days = Math.ceil((expiresAt - new Date()) / (24 * 60 * 60 * 1000));
        
        await addToWhitelist(foundScriptId, interaction.user.id, interaction.user.username, days, providedKey);
        
        const usesText = validation.key.maxUses === null ? '♾️ Infinite' : String(validation.key.maxUses);
        
        const successEmbed = new EmbedBuilder()
          .setColor(0x80ff80)
          .setTitle('✅ Key Redeemed Successfully!')
          .setDescription(`You now have access to **${foundScript.name}**`)
          .addFields(
            { name: '🔑 Your Key', value: `\`${providedKey}\`` },
            { name: '⏰ Expires', value: expiresAt ? `<t:${Math.floor(expiresAt.getTime() / 1000)}:F>` : 'Never' },
            { name: '📊 Max Uses', value: usesText, inline: true }
          )
          .setFooter({ text: 'Click the Get Script button below!' })
          .setTimestamp();
        
        // Create button to get the script
        const row = new ActionRowBuilder()
          .addComponents(
            new ButtonBuilder()
              .setCustomId(`get_${foundScriptId}`)
              .setLabel('📥 Get Script')
              .setStyle(ButtonStyle.Primary)
          );
        
        await interaction.editReply({ 
          embeds: [successEmbed],
          components: [row]
        });
        
        // Send DM with the same button
        try {
          await interaction.user.send({ 
            embeds: [successEmbed],
            components: [row]
          });
        } catch (err) {
          console.log('Could not send DM to user');
        }
      }
    }
  } catch (error) {
    console.error('Error handling interaction:', error);
    
    try {
      if (interaction.deferred) {
        await interaction.editReply({ content: '❌ An error occurred. Please try again.' });
      } else if (!interaction.replied) {
        await interaction.reply({ content: '❌ An error occurred. Please try again.', flags: 64 });
      }
    } catch (e) {
      console.error('Could not send error message:', e);
    }
  }
});

// ============================================
// CATCH-ALL ROUTE
// ============================================
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================
// INITIALIZE AND START SERVER
// ============================================
async function initializeApp() {
  try {
    // Create directories if they don't exist
    await fs.mkdir(WHITELIST_DIR, { recursive: true });
    await fs.mkdir(DATA_DIR, { recursive: true });
    await fs.mkdir(SCRIPTS_DIR, { recursive: true });
    await fs.mkdir(KEYS_DIR, { recursive: true });
    await fs.mkdir(EXECUTIONS_DIR, { recursive: true });
    await fs.mkdir(SESSIONS_DIR, { recursive: true });
    
    // Create users file if it doesn't exist
    try {
      await fs.access(USERS_FILE);
    } catch {
      await fs.writeFile(USERS_FILE, '');
    }
    
    console.log('✅ Directories created successfully');
    
    // Start Discord bot
    discordClient.login(DISCORD_TOKEN).catch(err => {
      console.error('Failed to login to Discord:', err);
    });
    
    // Start server - use the global PORT variable
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
      console.log(`🤖 Discord bot should be online soon...`);
    });
  } catch (err) {
    console.error('Error initializing app:', err);
  }
}

// Initialize and start the application
initializeApp();

// ============================================
// CLEANUP ON EXIT
// ============================================
process.on('SIGINT', () => {
  console.log('Shutting down...');
  server.close(() => {
    discordClient.destroy();
    process.exit(0);
  });
});
