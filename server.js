import express from 'express';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const DATABASE_URL = process.env.DATABASE_URL;

const pool = DATABASE_URL ? new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
}) : null;

if (pool) {
  pool.query('SELECT 1').then(()=>console.log('Neon connected')).catch(e=>console.error('Neon error', e.message));
} else {
  console.warn('DATABASE_URL not set -- running without DB (health only)');
}

app.use(cors({ origin: process.env.CORS_ORIGIN || true }));
app.use(express.json());
app.use(express.static(__dirname));

// --- helper ---
function auth(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({error:'Missing token'});
  try { req.user = jwt.verify(h.replace('Bearer ',''), JWT_SECRET); next(); }
  catch { return res.status(401).json({error:'Invalid token'}); }
}

// --- health ---
app.get('/api/health', (req,res)=> res.json({ok:true, db: !!pool}));

// --- auth ---
app.post('/api/auth/register', async (req,res)=>{
  if(!pool) return res.status(500).json({error:'DB not configured'});
  const {username,email,password} = req.body;
  if(!username||!email||!password) return res.status(400).json({error:'Missing fields'});
  const hash = await bcrypt.hash(password, 10);
  try {
    const r = await pool.query(
      'INSERT INTO users (username,email,password_hash) VALUES ($1,$2,$3) RETURNING id, username, email',
      [username,email,hash]
    );
    const token = jwt.sign({id:r.rows[0].id, username}, JWT_SECRET, {expiresIn:'30d'});
    res.json({token, user:r.rows[0]});
  } catch(e){
    if(e.code==='23505') return res.status(409).json({error:'Username or email exists'});
    res.status(500).json({error:e.message});
  }
});

app.post('/api/auth/login', async (req,res)=>{
  if(!pool) return res.status(500).json({error:'DB not configured'});
  const {username,password} = req.body;
  const r = await pool.query('SELECT * FROM users WHERE username=$1 OR email=$1', [username]);
  if(!r.rows[0]) return res.status(401).json({error:'User not found'});
  const ok = await bcrypt.compare(password, r.rows[0].password_hash);
  if(!ok) return res.status(401).json({error:'Wrong password'});
  const token = jwt.sign({id:r.rows[0].id, username:r.rows[0].username}, JWT_SECRET, {expiresIn:'30d'});
  res.json({token, user:{id:r.rows[0].id, username:r.rows[0].username, email:r.rows[0].email}});
});

app.get('/api/me', auth, async (req,res)=>{
  const r = await pool.query('SELECT id, username, email, created_at FROM users WHERE id=$1', [req.user.id]);
  res.json(r.rows[0]);
});

// --- saves ---
app.post('/api/save', auth, async (req,res)=>{
  if(!pool) return res.status(500).json({error:'DB not configured'});
  const {difficulty, board, moves, threat, checkpoint_idx, bonuses} = req.body;
  await pool.query(`
    INSERT INTO saves (user_id, difficulty, board, moves, threat, checkpoint_idx, bonuses, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7, now())
    ON CONFLICT (user_id, difficulty) DO UPDATE SET board=$3, moves=$4, threat=$5, checkpoint_idx=$6, bonuses=$7, updated_at=now()
  `, [req.user.id, difficulty, JSON.stringify(board), moves, threat, checkpoint_idx, JSON.stringify(bonuses||[])]);
  res.json({ok:true});
});

app.get('/api/save/:difficulty', auth, async (req,res)=>{
  const r = await pool.query('SELECT * FROM saves WHERE user_id=$1 AND difficulty=$2', [req.user.id, req.params.difficulty]);
  res.json(r.rows[0]||null);
});

// --- records / win ---
app.post('/api/record/win', auth, async (req,res)=>{
  if(!pool) return res.status(500).json({error:'DB not configured'});
  const {difficulty, time_ms, moves} = req.body;
  const cur = await pool.query('SELECT * FROM records WHERE user_id=$1 AND difficulty=$2', [req.user.id, difficulty]);
  if(!cur.rows[0]){
    await pool.query('INSERT INTO records (user_id, difficulty, best_time_ms, best_moves, wins) VALUES ($1,$2,$3,$4,1)', [req.user.id, difficulty, time_ms, moves]);
  } else {
    const bestTime = cur.rows[0].best_time_ms==null || time_ms < cur.rows[0].best_time_ms ? time_ms : cur.rows[0].best_time_ms;
    const bestMoves = cur.rows[0].best_moves==null || moves < cur.rows[0].best_moves ? moves : cur.rows[0].best_moves;
    await pool.query('UPDATE records SET best_time_ms=$1, best_moves=$2, wins=wins+1 WHERE user_id=$3 AND difficulty=$4', [bestTime, bestMoves, req.user.id, difficulty]);
  }
  // example medal: first win
  await pool.query('INSERT INTO medals (user_id, code) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, `win_${difficulty}`]);
  res.json({ok:true});
});

// --- leaderboard ---
app.get('/api/leaderboard/:difficulty', async (req,res)=>{
  if(!pool) return res.status(500).json({error:'DB not configured'});
  const {difficulty} = req.params;
  const limit = Math.min(parseInt(req.query.limit||'100'), 100);
  const r = await pool.query(`
    SELECT u.username, r.best_time_ms, r.best_moves, r.wins
    FROM records r JOIN users u ON u.id=r.user_id
    WHERE r.difficulty=$1 AND r.best_time_ms IS NOT NULL
    ORDER BY r.best_time_ms ASC, r.best_moves ASC
    LIMIT $2
  `, [difficulty, limit]);
  res.json(r.rows);
});

app.get('/api/medals', auth, async (req,res)=>{
  const r = await pool.query('SELECT code, earned_at FROM medals WHERE user_id=$1 ORDER BY earned_at DESC', [req.user.id]);
  res.json(r.rows);
});

// fallback to index.html for SPA
app.get('*', (req,res)=> res.sendFile(path.join(__dirname,'index.html')));

app.listen(PORT, ()=> console.log(`500 server listening on ${PORT}`));
