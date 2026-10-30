'use strict';
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const { DatabaseSync } = require('node:sqlite');

const ROOT=__dirname, PUBLIC=path.join(ROOT,'public');
const DATA=path.resolve(process.env.HUSH_DATA_DIR||path.join(ROOT,'data'));
const PORT=Number(process.env.PORT||4173), HOST=process.env.HOST||'127.0.0.1';
const CERT=process.env.HUSH_TLS_CERT, KEY=process.env.HUSH_TLS_KEY;
const secureServer=Boolean(CERT&&KEY);
const TRUST_PROXY=process.env.TRUST_PROXY==='1';
if(!Number.isInteger(PORT)||PORT<1||PORT>65535)throw new Error('PORT must be a valid TCP port.');
if(Boolean(CERT)!==Boolean(KEY))throw new Error('Set both HUSH_TLS_CERT and HUSH_TLS_KEY, or neither.');
process.umask(0o077);
const MIME={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.webmanifest':'application/manifest+json','.svg':'image/svg+xml'};
fs.mkdirSync(DATA,{recursive:true,mode:0o700});
fs.chmodSync(DATA,0o700);
const DB_PATH=path.join(DATA,'chat.sqlite');
const db=new DatabaseSync(DB_PATH);
fs.chmodSync(DB_PATH,0o600);
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS accounts(puid TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, puid TEXT NOT NULL REFERENCES accounts(puid) ON DELETE CASCADE, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_puid ON sessions(puid);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS threads(id TEXT PRIMARY KEY, owner_puid TEXT REFERENCES accounts(puid), created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY, thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE, iv TEXT NOT NULL, ciphertext TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS messages_thread_cursor ON messages(thread_id,created_at DESC,id DESC);
CREATE TABLE IF NOT EXISTS signals(id TEXT PRIMARY KEY, recipient_puid TEXT NOT NULL REFERENCES accounts(puid) ON DELETE CASCADE, sender_puid TEXT NOT NULL REFERENCES accounts(puid) ON DELETE CASCADE, kind TEXT NOT NULL CHECK(kind IN ('offer','answer')), payload TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS signals_recipient_time ON signals(recipient_puid,created_at);
`);
try{db.exec('ALTER TABLE threads ADD COLUMN owner_puid TEXT REFERENCES accounts(puid)')}catch(e){if(!String(e.message).includes('duplicate column'))throw e}
db.exec('CREATE INDEX IF NOT EXISTS threads_owner_cursor ON threads(owner_puid,created_at DESC)')
const subscribers=new Set(), RATE=new Map();
const cleanupTimer=setInterval(()=>{const now=Date.now();db.prepare('DELETE FROM sessions WHERE expires_at<?').run(now);db.prepare('DELETE FROM signals WHERE created_at<?').run(now-5*60*1000)},15*60*1000);cleanupTimer.unref();
function json(res,status,data,headers={}){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers});res.end(JSON.stringify(data))}
function requestIsSecure(req){const forwarded=String(req.headers['x-forwarded-proto']||'').split(',')[0].trim().toLowerCase();return Boolean(req.socket.encrypted)||(TRUST_PROXY&&forwarded==='https')}
function originAllowed(req){const origin=req.headers.origin,mutating=['POST','PUT','PATCH','DELETE'].includes(req.method);if(!origin)return !mutating;const scheme=requestIsSecure(req)?'https':'http';return origin===`${scheme}://${req.headers.host}`}
function clientAddress(req){if(TRUST_PROXY){const forwarded=String(req.headers['x-forwarded-for']||'').split(',')[0].trim();if(net.isIP(forwarded))return forwarded}return req.socket.remoteAddress||'unknown'}
function rateLimited(req){const ip=clientAddress(req),now=Date.now();let entry=RATE.get(ip);if(!entry&&RATE.size>=10000){for(const [key,value] of RATE)if(now-value.start>60000)RATE.delete(key);if(RATE.size>=10000)return true}if(!entry||now-entry.start>60000){entry={start:now,count:0};RATE.set(ip,entry)}return ++entry.count>300}
function tokenHash(token){return crypto.createHash('sha256').update(token).digest('hex')}
function cookieToken(req){const raw=req.headers.cookie||'';const m=raw.match(/(?:^|;\s*)hush_session=([a-f0-9]{64})(?:;|$)/);return m?.[1]||null}
function accountFor(req){const token=cookieToken(req);if(!token)return null;const now=Date.now();return db.prepare('SELECT a.puid,a.username FROM sessions s JOIN accounts a ON a.puid=s.puid WHERE s.token_hash=? AND s.expires_at>?').get(tokenHash(token),now)||null}
function requireAccount(req,res){const account=accountFor(req);if(!account)json(res,401,{error:'Anonymous account required.'});return account}
function setSession(res,req,puid){const token=crypto.randomBytes(32).toString('hex'),now=Date.now();db.prepare('INSERT INTO sessions(token_hash,puid,created_at,expires_at) VALUES(?,?,?,?)').run(tokenHash(token),puid,now,now+365*86400000);const secure=requestIsSecure(req)?'; Secure':'';res.setHeader('Set-Cookie',`hush_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=31536000${secure}`)}
function notify(puid,event,data={},origin=''){const frame=`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;for(const sub of subscribers)if(sub.puid===puid&&!(event==='message'&&sub.client===origin))sub.res.write(frame)}
function parseCursor(v){if(!v)return null;try{const [t,id]=Buffer.from(v,'base64url').toString().split('|');const n=Number(t);return Number.isSafeInteger(n)&&id?{time:n,id}:null}catch{return null}}
function cursorFor(row){return Buffer.from(`${row.created_at}|${row.id}`).toString('base64url')}
async function readBody(req){if(!/^application\/json(?:\s*;|$)/i.test(String(req.headers['content-type']||'')))throw Object.assign(new Error('JSON content type required.'),{status:415});const declared=Number(req.headers['content-length']||0);if(declared>24000)throw Object.assign(new Error('Request is too large.'),{status:413});const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>24000)throw Object.assign(new Error('Request is too large.'),{status:413});chunks.push(chunk)}if(!size)return {};let value;try{value=JSON.parse(Buffer.concat(chunks).toString('utf8'))}catch{throw Object.assign(new Error('Invalid request.'),{status:400})}if(!value||typeof value!=='object'||Array.isArray(value))throw Object.assign(new Error('Invalid request.'),{status:400});return value}
async function handleRequest(req,res){
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','DENY');res.setHeader('Permissions-Policy','camera=(self), microphone=(), geolocation=()');if(requestIsSecure(req))res.setHeader('Strict-Transport-Security','max-age=31536000; includeSubDomains');
 const url=new URL(req.url,`${req.socket.encrypted?'https':'http'}://${req.headers.host||'localhost'}`);
 if(!originAllowed(req))return json(res,403,{error:'Origin not allowed.'});
 if(rateLimited(req))return json(res,429,{error:'Please slow down.'},{'Retry-After':'60'});
 if(req.method==='GET'&&url.pathname==='/api/v1/health')return json(res,200,{ok:true,storage:'sqlite',mode:'p2p-signaling'});
 if(req.method==='GET'&&url.pathname==='/api/v1/events'){
  const account=accountFor(req);if(!account)return json(res,401,{error:'Anonymous account required.'});res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache, no-transform','Connection':'keep-alive','X-Accel-Buffering':'no'});res.write('retry: 3000\nevent: ready\ndata: {}\n\n');const sub={res,puid:account.puid,client:String(url.searchParams.get('client')||'').slice(0,80)};subscribers.add(sub);const beat=setInterval(()=>res.write(': ping\n\n'),25000);res.on('close',()=>{clearInterval(beat);subscribers.delete(sub)});return;
 }
 if(url.pathname.startsWith('/api/')){
  let body={};if(['POST','PUT','PATCH'].includes(req.method)){try{body=await readBody(req)}catch(e){return json(res,e.status||400,{error:e.status?e.message:'Invalid request.'})}}
  if(req.method==='POST'&&url.pathname==='/api/v1/accounts'){
    if(accountFor(req))return json(res,409,{error:'This browser already has an account.'});
    const handle=`hush_${crypto.randomBytes(5).toString('hex')}`;const puid=crypto.randomUUID(),now=Date.now();
    try{db.prepare('INSERT INTO accounts(puid,username,created_at) VALUES(?,?,?)').run(puid,handle,now)}catch{return json(res,409,{error:'Could not create account.'})}
    if(db.prepare('SELECT COUNT(*) AS n FROM accounts').get().n===1)db.prepare('UPDATE threads SET owner_puid=? WHERE owner_puid IS NULL').run(puid);
    setSession(res,req,puid);return json(res,201,{username:handle,createdAt:now});
  }
  if(url.pathname.startsWith('/api/v1/')){
   const account=requireAccount(req,res);if(!account)return;
   if(req.method==='GET'&&url.pathname==='/api/v1/me')return json(res,200,{username:account.username});
   if(req.method==='PATCH'&&url.pathname==='/api/v1/me/username'){
    const username=String(body.username||'').toLowerCase();if(!/^[a-z0-9_]{3,24}$/.test(username))return json(res,400,{error:'Use 3–24 letters, numbers, or underscores.'});
    try{db.prepare('UPDATE accounts SET username=? WHERE puid=?').run(username,account.puid)}catch{return json(res,409,{error:'That username is already taken.'})}
    return json(res,200,{username});
   }
   if(req.method==='GET'&&url.pathname==='/api/v1/users'){
    const username=String(url.searchParams.get('username')||'').toLowerCase();if(!/^[a-z0-9_]{3,24}$/.test(username))return json(res,400,{error:'Enter a username.'});
    const found=db.prepare('SELECT username FROM accounts WHERE username=? AND puid<>?').get(username,account.puid);return found?json(res,200,{username:found.username}):json(res,404,{error:'Username not found.'});
   }
   if(req.method==='POST'&&url.pathname==='/api/v1/signals'){
    const username=String(body.username||'').toLowerCase(),kind=String(body.kind||''),payload=body.payload;
    if(!/^[a-z0-9_]{3,24}$/.test(username)||!['offer','answer'].includes(kind)||!payload||typeof payload!=='object')return json(res,400,{error:'Invalid peer signal.'});
    const encoded=JSON.stringify(payload);if(encoded.length>18000)return json(res,413,{error:'Peer signal is too large.'});
    const recipient=db.prepare('SELECT puid FROM accounts WHERE username=?').get(username);if(!recipient)return json(res,404,{error:'Username not found.'});if(recipient.puid===account.puid)return json(res,400,{error:'Choose another username.'});
    const now=Date.now();db.prepare('DELETE FROM signals WHERE created_at<?').run(now-5*60*1000);const pending=db.prepare('SELECT COUNT(*) AS n FROM signals WHERE recipient_puid=?').get(recipient.puid).n;if(pending>=20)return json(res,429,{error:'That inbox has too many pending connection requests.'});const id=crypto.randomUUID();db.prepare('INSERT INTO signals(id,recipient_puid,sender_puid,kind,payload,created_at) VALUES(?,?,?,?,?,?)').run(id,recipient.puid,account.puid,kind,encoded,now);notify(recipient.puid,'signal');return json(res,202,{queued:true});
   }
   if(req.method==='GET'&&url.pathname==='/api/v1/signals'){
    db.prepare('DELETE FROM signals WHERE created_at<?').run(Date.now()-5*60*1000);const rows=db.prepare('SELECT s.id,s.kind,s.payload,s.created_at,a.username AS fromUsername FROM signals s JOIN accounts a ON a.puid=s.sender_puid WHERE s.recipient_puid=? ORDER BY s.created_at LIMIT 20').all(account.puid);
    if(rows.length){const del=db.prepare('DELETE FROM signals WHERE id=? AND recipient_puid=?');const tx=db.transaction(items=>{for(const item of items)del.run(item.id,account.puid)});tx(rows)}
    return json(res,200,{signals:rows.map(x=>({id:x.id,kind:x.kind,payload:JSON.parse(x.payload),createdAt:x.created_at,fromUsername:x.fromUsername}))});
   }
   if(req.method==='GET'&&url.pathname==='/api/v1/threads'){
    const rows=db.prepare(`SELECT t.id,t.created_at,(SELECT m.created_at FROM messages m WHERE m.thread_id=t.id ORDER BY m.created_at DESC,m.id DESC LIMIT 1) AS last_at FROM threads t WHERE t.owner_puid=? ORDER BY COALESCE(last_at,t.created_at) DESC LIMIT 100`).all(account.puid);return json(res,200,{threads:rows});
   }
   if(req.method==='POST'&&url.pathname==='/api/v1/threads'){
    const id=crypto.randomUUID(),at=Date.now();db.prepare('INSERT INTO threads(id,owner_puid,created_at) VALUES(?,?,?)').run(id,account.puid,at);notify(account.puid,'thread',{id,created_at:at});return json(res,201,{id,created_at:at});
   }
   const match=url.pathname.match(/^\/api\/v1\/threads\/([a-f0-9-]+)(?:\/messages)?$/i);
   if(match&&url.pathname.endsWith('/messages')&&req.method==='GET'){
    const threadId=match[1];if(!db.prepare('SELECT id FROM threads WHERE id=? AND owner_puid=?').get(threadId,account.puid))return json(res,404,{error:'Chat not found.'});
    const raw=Number(url.searchParams.get('limit')||40),limit=Number.isFinite(raw)?Math.min(60,Math.max(1,Math.trunc(raw))):40,cursor=parseCursor(url.searchParams.get('before'));
    const rows=cursor?db.prepare('SELECT id,thread_id,iv,ciphertext,created_at FROM messages WHERE thread_id=? AND (created_at<? OR (created_at=? AND id<?)) ORDER BY created_at DESC,id DESC LIMIT ?').all(threadId,cursor.time,cursor.time,cursor.id,limit+1):db.prepare('SELECT id,thread_id,iv,ciphertext,created_at FROM messages WHERE thread_id=? ORDER BY created_at DESC,id DESC LIMIT ?').all(threadId,limit+1);
    const hasMore=rows.length>limit,page=rows.slice(0,limit);return json(res,200,{messages:page.reverse().map(m=>({...m,cursor:cursorFor(m)})),nextCursor:hasMore?cursorFor(page.at(-1)):null,hasMore});
   }
   if(match&&url.pathname.endsWith('/messages')&&req.method==='POST'){
    const threadId=match[1],iv=String(body.iv||''),ciphertext=String(body.ciphertext||'');if(!db.prepare('SELECT id FROM threads WHERE id=? AND owner_puid=?').get(threadId,account.puid))return json(res,404,{error:'Chat not found.'});
    if(!/^[A-Za-z0-9_-]{16,32}$/.test(iv)||!/^[A-Za-z0-9_-]{20,10000}$/.test(ciphertext))return json(res,400,{error:'Encrypted message is invalid.'});const m={id:crypto.randomUUID(),thread_id:threadId,iv,ciphertext,created_at:Date.now()};db.prepare('INSERT INTO messages(id,thread_id,iv,ciphertext,created_at) VALUES(?,?,?,?,?)').run(m.id,m.thread_id,m.iv,m.ciphertext,m.created_at);notify(account.puid,'message',m,String(req.headers['x-client-id']||''));return json(res,201,{...m,cursor:cursorFor(m)});
   }
   if(match&&!url.pathname.endsWith('/messages')&&req.method==='DELETE'){
    const result=db.prepare('DELETE FROM threads WHERE id=? AND owner_puid=?').run(match[1],account.puid);if(!result.changes)return json(res,404,{error:'Chat not found.'});notify(account.puid,'deleted',{id:match[1]});res.writeHead(204);return res.end();
   }
   return json(res,404,{error:'Route not found.'});
  }
 }
 if(req.method==='GET'){
  let pathname;try{pathname=decodeURIComponent(url.pathname)}catch{return json(res,400,{error:'Invalid path.'})}if(pathname==='/')pathname='/index.html';const target=path.resolve(PUBLIC,`.${pathname}`);if(!target.startsWith(PUBLIC+path.sep)&&target!==PUBLIC)return json(res,403,{error:'Forbidden.'});
  fs.readFile(target,(err,data)=>{if(err){res.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'});return res.end('Not found')}res.writeHead(200,{'Content-Type':MIME[path.extname(target)]||'application/octet-stream','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Permissions-Policy':'camera=(self), microphone=(), geolocation=()','Content-Security-Policy':"default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; media-src 'self' blob:; upgrade-insecure-requests",...(requestIsSecure(req)?{'Strict-Transport-Security':'max-age=31536000; includeSubDomains'}:{})});res.end(data)});return;
 }
 json(res,404,{error:'Not found.'});
}
const handler=(req,res)=>{handleRequest(req,res).catch(error=>{console.error('request_error',error?.name||'Error');if(res.headersSent)return res.destroy();return json(res,error.status||500,{error:error.status?error.message:'Internal server error.'})})};
const server=secureServer?https.createServer({cert:fs.readFileSync(CERT),key:fs.readFileSync(KEY)},handler):http.createServer(handler);
server.headersTimeout=10000;server.requestTimeout=30000;server.keepAliveTimeout=5000;
server.listen(PORT,HOST,()=>console.log(`hush is running at ${secureServer?'https':'http'}://localhost:${PORT}`));
function shutdown(){for(const s of subscribers)s.res.end();db.close();server.close(()=>process.exit(0))}process.on('SIGINT',shutdown);process.on('SIGTERM',shutdown);
