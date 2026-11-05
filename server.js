const http = require('http');
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, 'public');
const types = { '.html':'text/html', '.css':'text/css', '.js':'application/javascript', '.json':'application/json' };
const starterJobs = [
  { id:'remotive-2091105', title:'Content Reviewer - English US', company:'TELUS Digital', location:'USA', category:'All others', type:'Part-time', url:'https://remotive.com/remote-jobs/all-others/content-reviewer-english-us-2091105', source:'Remotive', description:'Open this verified listing on Remotive to review requirements and submit an application.' },
  { id:'remotive-2091098', title:'Senior Golang Developer', company:'Lemon.io', location:'Europe, USA, UK, Canada, Australia, Singapore', category:'Software Development', type:'Contract', url:'https://remotive.com/remote-jobs/software-development/senior-golang-developer-2091098', source:'Remotive', description:'Open this verified listing on Remotive to review requirements and submit an application.' }
];
let jobCache = starterJobs;

function send(res, status, body, type='application/json') { res.writeHead(status, {'Content-Type': type, 'Cache-Control':'no-store'}); res.end(Buffer.isBuffer(body) || typeof body === 'string' ? body : JSON.stringify(body)); }
async function getJson(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 9000);
  try { const response = await fetch(url, { signal: controller.signal, headers: { 'User-Agent': 'CareerGuard/1.0' } }); if (!response.ok) throw Error(response.status); return response.json(); }
  finally { clearTimeout(timer); }
}
function clean(value='') { return String(value).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim(); }
async function jobs(res) {
  // Return a useful response immediately; refresh the free source in the background.
  send(res, 200, { jobs: jobCache, source:'Remotive' });
  try {
    const data = await getJson('https://remotive.com/api/remote-jobs?limit=40');
    const list = (data.jobs || []).map(j => ({ id:'remotive-'+j.id, title:j.title, company:j.company_name, location:j.candidate_required_location || 'Remote', category:j.category || 'Other', type:j.job_type || 'Full-time', url:j.url, source:'Remotive', description:clean(j.description).slice(0, 360) }));
    if (list.length) jobCache = list;
  } catch {}
  return;
  /*
  try {
    // Remotive provides a stable, free public API and each returned link opens its application page.
    const data = await getJson('https://remotive.com/api/remote-jobs?limit=40');
    const list = (data.jobs || []).map(j => ({ id:'remotive-'+j.id, title:j.title, company:j.company_name, location:j.candidate_required_location || 'Remote', category:j.category || 'Other', type:j.job_type || 'Full-time', url:j.url, source:'Remotive', description:clean(j.description).slice(0, 360) }));
    if (!list.length) throw Error('No jobs returned');
    send(res, 200, { jobs:list, source:'Remotive' });
  } catch { send(res, 502, { error:'The free job provider is temporarily unavailable. Refresh to try again.' }); } */
}
http.createServer((req,res) => {
  const route = new URL(req.url, 'http://localhost').pathname;
  if (route === '/api/jobs') return jobs(res);
  const requested = route === '/' ? '/index.html' : route;
  const file = path.normalize(path.join(root, requested));
  if (!file.startsWith(root)) return send(res,403,'Forbidden','text/plain');
  fs.readFile(file, (err, content) => err ? send(res,404,'Not found','text/plain') : send(res,200,content,types[path.extname(file)] || 'application/octet-stream'));
}).listen(process.env.PORT || 3000, () => console.log('CareerGuard: http://localhost:3000'));
