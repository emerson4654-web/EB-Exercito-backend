import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_FILE = path.resolve(__dirname, process.env.DATA_FILE || './data/data.json');
const GROUP_ID = String(process.env.ROBLOX_GROUP_ID || '');
const GAME_URL = process.env.ROBLOX_GAME_URL || 'https://www.roblox.com/';
const DISCORD_URL = 'https://discord.gg/QWMFQeqCr';
const ADMIN_IDS = new Set((process.env.ADMIN_ROBLOX_IDS || '').split(',').map(x => x.trim()).filter(Boolean));

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

async function readData() {
  try { return JSON.parse(await fs.readFile(DATA_FILE, 'utf8')); }
  catch { return { users: {}, trainings: [], audit: [] }; }
}
async function writeData(data) {
  await fs.mkdir(path.dirname(DATA_FILE), { recursive: true });
  await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2));
}

function isAdmin(req) {
  return !!req.session.robloxUser && ADMIN_IDS.has(String(req.session.robloxUser.sub));
}
function requireLogin(req, res, next) {
  if (!req.session.robloxUser) return res.status(401).json({ error: 'Faça login com o Roblox.' });
  next();
}
function requireAdmin(req, res, next) {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Acesso restrito ao administrador.' });
  next();
}

function base64url(buffer) { return buffer.toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_'); }
function randomString(n=32) { return base64url(crypto.randomBytes(n)); }
function sha256(input) { return crypto.createHash('sha256').update(input).digest(); }

app.get('/auth/roblox', (req, res) => {
  const clientId = process.env.ROBLOX_CLIENT_ID;
  const redirectUri = process.env.ROBLOX_REDIRECT_URI;
  if (!clientId || !redirectUri) return res.status(503).send('Configure ROBLOX_CLIENT_ID e ROBLOX_REDIRECT_URI no backend.');
  const state = randomString(24);
  const verifier = randomString(48);
  req.session.oauth = { state, verifier };
  const challenge = base64url(sha256(verifier));
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid profile',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  });
  res.redirect('https://apis.roblox.com/oauth/v1/authorize?' + params.toString());
});

app.get('/auth/roblox/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || state !== req.session.oauth?.state) return res.status(400).send('OAuth inválido.');
    const verifier = req.session.oauth.verifier;
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: String(code),
      client_id: process.env.ROBLOX_CLIENT_ID,
      redirect_uri: process.env.ROBLOX_REDIRECT_URI,
      code_verifier: verifier
    });
    if (process.env.ROBLOX_CLIENT_SECRET) body.set('client_secret', process.env.ROBLOX_CLIENT_SECRET);
    const tokenRes = await fetch('https://apis.roblox.com/oauth/v1/token', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body });
    const token = await tokenRes.json();
    if (!tokenRes.ok) return res.status(400).send('Falha ao trocar o código OAuth: ' + JSON.stringify(token));
    const userRes = await fetch('https://apis.roblox.com/oauth/v1/userinfo', { headers:{ Authorization:`Bearer ${token.access_token}` }});
    const user = await userRes.json();
    if (!userRes.ok) return res.status(400).send('Falha ao obter o usuário Roblox.');
    req.session.robloxUser = { sub: String(user.sub), name: user.name, preferred_username: user.preferred_username, picture: user.picture };
    req.session.robloxAccessToken = token.access_token;
    delete req.session.oauth;
    res.redirect('/?login=ok');
  } catch (e) { res.status(500).send('Erro no login Roblox.'); }
});

app.post('/auth/logout', (req,res) => req.session.destroy(() => res.json({ ok:true })));

async function publicGroupRoles(userId) {
  if (!GROUP_ID) return null;
  const r = await fetch(`https://groups.roblox.com/v2/users/${encodeURIComponent(userId)}/groups/roles`);
  if (!r.ok) throw new Error('Não foi possível consultar o grupo.');
  const json = await r.json();
  const item = (json.data || []).find(x => String(x.group?.id) === GROUP_ID);
  return item?.role || null;
}

async function cloud(pathname, options={}) {
  const key = process.env.ROBLOX_OPEN_CLOUD_API_KEY;
  if (!key) throw new Error('ROBLOX_OPEN_CLOUD_API_KEY não configurada.');
  const r = await fetch('https://apis.roblox.com' + pathname, {
    ...options,
    headers: { 'x-api-key': key, 'Content-Type': 'application/json', ...(options.headers||{}) }
  });
  const text = await r.text();
  let data; try { data = text ? JSON.parse(text) : {}; } catch { data = { raw:text }; }
  if (!r.ok) { const err = new Error(data.message || `Roblox Open Cloud ${r.status}`); err.status=r.status; err.data=data; throw err; }
  return data;
}

app.get('/api/config', (req,res) => res.json({ groupId: GROUP_ID, gameUrl: GAME_URL, discordUrl: DISCORD_URL, oauthConfigured: !!process.env.ROBLOX_CLIENT_ID }));

app.get('/api/me', requireLogin, async (req,res) => {
  try {
    const user = req.session.robloxUser;
    const role = await publicGroupRoles(user.sub);
    const data = await readData();
    const local = data.users[user.sub] || { ups:0, promotionHistory:[], trainingHistory:[] };
    res.json({ user, role, admin:isAdmin(req), ...local });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/roles', async (req,res) => {
  try {
    if (!GROUP_ID) return res.json({ roles:[] });
    const data = await cloud(`/cloud/v2/groups/${GROUP_ID}/roles?maxPageSize=100`);
    res.json({ roles: data.groupRoles || [] });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/promote', requireAdmin, async (req,res) => {
  try {
    const { userId, roleId, reason } = req.body || {};
    if (!userId || !roleId) return res.status(400).json({error:'Informe userId e roleId.'});
    const memberships = await cloud(`/cloud/v2/groups/${GROUP_ID}/memberships?maxPageSize=10&filter=${encodeURIComponent(`user == 'users/${userId}'`)}`);
    const membership = memberships.groupMemberships?.[0];
    if (!membership?.path) return res.status(404).json({error:'Usuário não encontrado no grupo.'});
    const membershipId = membership.path.split('/').pop();
    const result = await cloud(`/cloud/v2/groups/${GROUP_ID}/memberships/${membershipId}:assignRole`, { method:'POST', body:JSON.stringify({ role: `groups/${GROUP_ID}/roles/${roleId}` }) });
    const data = await readData();
    const entry = { userId:String(userId), roleId:String(roleId), reason:reason||'Promoção pelo portal', by:String(req.session.robloxUser.sub), at:new Date().toISOString() };
    data.audit.push({ type:'PROMOTION', ...entry });
    if (!data.users[String(userId)]) data.users[String(userId)]={ups:0,promotionHistory:[],trainingHistory:[]};
    data.users[String(userId)].promotionHistory.unshift(entry);
    await writeData(data);
    res.json({ ok:true, result });
  } catch(e) { res.status(e.status||500).json({error:e.message, details:e.data}); }
});

app.post('/api/training', requireAdmin, async (req,res) => {
  try {
    const { userId, title, ups=1, approved=true } = req.body || {};
    if (!userId || !title) return res.status(400).json({error:'Informe userId e título.'});
    const add = Math.max(0, Number(ups)||0);
    const data = await readData();
    const id = crypto.randomUUID();
    const item = { id, userId:String(userId), title:String(title), ups:add, approved:!!approved, by:String(req.session.robloxUser.sub), at:new Date().toISOString() };
    if (!data.users[String(userId)]) data.users[String(userId)]={ups:0,promotionHistory:[],trainingHistory:[]};
    data.users[String(userId)].ups += add;
    data.users[String(userId)].trainingHistory.unshift(item);
    data.trainings.unshift(item);
    data.audit.push({type:'TRAINING',...item});
    await writeData(data);
    res.json({ok:true,item, totalUps:data.users[String(userId)].ups});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/health', (req,res)=>res.json({ok:true}));
app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT, ()=>console.log(`Portal EB rodando em http://localhost:${PORT}`));
