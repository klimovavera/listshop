'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');
const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, 'data', 'shop.json');
const SEED = path.join(ROOT, 'data', 'seed.json');
const SECRET = process.env.JWT_SECRET || 'local-student-demo-change-before-public-deploy';
const MAX_BODY = 100000;
const mime = {'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.ico':'image/x-icon','.json':'application/json; charset=utf-8'};
function getData(){ if(!fs.existsSync(DATA_FILE)) fs.copyFileSync(SEED,DATA_FILE); return JSON.parse(fs.readFileSync(DATA_FILE,'utf8')); }
function saveData(data){ const tmp = DATA_FILE+'.tmp'; fs.writeFileSync(tmp,JSON.stringify(data,null,2),'utf8'); fs.renameSync(tmp,DATA_FILE); }
function json(res,code,obj){res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Authorization, Content-Type','Access-Control-Allow-Methods':'GET,POST,PATCH,PUT,DELETE,OPTIONS'});res.end(JSON.stringify(obj));}
function err(res,code,message){json(res,code,{error:message});}
function b64(x){return Buffer.from(x).toString('base64url');}
function token(user){const head=b64(JSON.stringify({alg:'HS256',typ:'JWT'}));const payload=b64(JSON.stringify({sub:user.id,role:user.role,exp:Math.floor(Date.now()/1000)+86400}));const body=head+'.'+payload;const mac=crypto.createHmac('sha256',SECRET).update(body).digest('base64url');return body+'.'+mac;}
function getUser(req,data){let str=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');let parts=str.split('.');if(parts.length!==3)return null;try{const actual=crypto.createHmac('sha256',SECRET).update(parts[0]+'.'+parts[1]).digest();const supplied=Buffer.from(parts[2],'base64url');if(supplied.length!==actual.length||!crypto.timingSafeEqual(supplied,actual))return null;let claims=JSON.parse(Buffer.from(parts[1],'base64url').toString());if(!Number.isInteger(claims.exp)||claims.exp<=Date.now()/1000)return null;return data.users.find(u=>u.id===claims.sub)||null;}catch{return null;}}
function publicUser(u){return {id:u.id,name:u.name,email:u.email,role:u.role};}
function hashPassword(password,salt){return crypto.scryptSync(password,salt,64).toString('hex');}
function readBody(req){return new Promise((resolve,reject)=>{let body='';req.on('data',part=>{body+=part;if(body.length>MAX_BODY){reject({status:413,message:'Слишком большой запрос'});req.destroy();}});req.on('end',()=>{try{resolve(body?JSON.parse(body):{});}catch{reject({status:400,message:'Неверный формат JSON'});}});req.on('error',reject);});}
function requireUser(req,res,data){const u=getUser(req,data);if(!u)err(res,401,'Нужно войти в аккаунт');return u;}
function admin(req,res,data){const u=requireUser(req,res,data);if(!u)return null;if(u.role!=='admin'){err(res,403,'Недостаточно прав');return null;}return u;}
function nextId(records){return Math.max(0,...records.map(x=>x.id))+1;}
function cleanedProduct(p){return {id:p.id,name:p.name,description:p.description,category:p.category,price:p.price,inStock:!!p.inStock&&p.stock>0,stock:p.stock,icon:p.icon,image:p.image||null};}
async function api(req,res,url){let data=getData();let pathname=url.pathname;let method=req.method;
  if(method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Authorization, Content-Type','Access-Control-Allow-Methods':'GET,POST,PATCH,PUT,DELETE,OPTIONS'});res.end();return;}
  if(pathname==='/api/health'&&method==='GET')return json(res,200,{ok:true,storage:'local-json'});
  if(pathname==='/api/products'&&method==='GET'){let products=data.products.filter(p=>!url.searchParams.get('category')||p.category===url.searchParams.get('category'));return json(res,200,products.map(cleanedProduct));}
  if(pathname==='/api/admin/summary'&&method==='GET'){
    if(!admin(req,res,data))return;
    return json(res,200,{products:data.products.length,orders:data.orders.length,revenue:data.orders.reduce((s,o)=>s+o.totalPrice,0),lowStock:data.products.filter(p=>p.stock<=5).length});
  }
  if(pathname==='/api/admin/orders'&&method==='GET'){
    if(!admin(req,res,data))return;
    return json(res,200,data.orders.map(o=>({...o,customer:data.users.find(u=>u.id===o.userId)?.name||'Покупатель'})).sort((a,b)=>b.id-a.id));
  }
  const adminOrder=pathname.match(/^\/api\/admin\/orders\/(\d+)$/);
  if(adminOrder&&method==='PATCH'){
    if(!admin(req,res,data))return;
    const order=data.orders.find(o=>o.id===Number(adminOrder[1]));
    if(!order)return err(res,404,'Заказ не найден');
    const b=await readBody(req);
    if(!['new','processing','shipped','completed','cancelled'].includes(b.status))return err(res,400,'Неверный статус заказа');
    order.status=b.status;saveData(data);return json(res,200,order);
  }
  if(pathname==='/api/categories'&&method==='GET')return json(res,200,[...new Set(data.products.map(p=>p.category))]);
  if(pathname==='/api/auth/register'&&method==='POST'){
    let b=await readBody(req);let name=String(b.name||'').trim(),email=String(b.email||'').trim().toLowerCase(),pw=String(b.password||'');
    if(name.length<2||!/^\S+@\S+\.\S+$/.test(email)||pw.length<6)return err(res,400,'Укажите имя, корректную почту и пароль от 6 символов');
    if(data.users.some(u=>u.email===email))return err(res,409,'Пользователь с такой почтой уже есть');
    let salt=crypto.randomBytes(16).toString('hex');let user={id:nextId(data.users),name,email,salt,passwordHash:hashPassword(pw,salt),role:'user'};data.users.push(user);saveData(data);return json(res,201,{token:token(user),user:publicUser(user)});
  }
  if(pathname==='/api/auth/login'&&method==='POST'){
    let b=await readBody(req);let email=String(b.email||'').trim().toLowerCase();let user=data.users.find(u=>u.email===email);if(!user)return err(res,401,'Неверная почта или пароль');
    let check=hashPassword(String(b.password||''),user.salt);if(!crypto.timingSafeEqual(Buffer.from(check,'hex'),Buffer.from(user.passwordHash,'hex')))return err(res,401,'Неверная почта или пароль');
    return json(res,200,{token:token(user),user:publicUser(user)});
  }
  if(pathname==='/api/auth/me'&&method==='GET'){const u=requireUser(req,res,data);if(!u)return;return json(res,200,publicUser(u));}
  if(pathname==='/api/orders'&&method==='GET'){const u=requireUser(req,res,data);if(!u)return;return json(res,200,data.orders.filter(o=>o.userId===u.id).sort((a,b)=>b.id-a.id));}
  if(pathname==='/api/orders'&&method==='POST'){
    const u=requireUser(req,res,data);if(!u)return;const b=await readBody(req);if(!Array.isArray(b.items)||!b.items.length||b.items.length>50)return err(res,400,'Корзина пуста или содержит слишком много товаров');
    const counts=new Map();for(const item of b.items){const id=Number(item.productId),qty=Number(item.quantity);if(!Number.isInteger(id)||!Number.isInteger(qty)||qty<1||qty>99)return err(res,400,'Неверное количество товара');counts.set(id,(counts.get(id)||0)+qty);}
    const lines=[];for(const [id,quantity] of counts){const p=data.products.find(p=>p.id===id);if(!p||!p.inStock||p.stock<quantity)return err(res,400,'Товар отсутствует или его недостаточно на складе');lines.push({productId:p.id,name:p.name,price:p.price,quantity});}
    const totalPrice=lines.reduce((sum,x)=>sum+x.price*x.quantity,0);for(const line of lines){const p=data.products.find(p=>p.id===line.productId);p.stock-=line.quantity;if(p.stock===0)p.inStock=false;}
    const order={id:nextId(data.orders),userId:u.id,items:lines,totalPrice,status:'new',createdAt:new Date().toISOString()};data.orders.push(order);saveData(data);return json(res,201,order);
  }
  if(pathname==='/api/products'&&method==='POST'){if(!admin(req,res,data))return;const b=await readBody(req);const check=validateProduct(b);if(check)return err(res,400,check);const p={id:nextId(data.products),...productFields(b)};data.products.push(p);saveData(data);return json(res,201,cleanedProduct(p));}
  const match=pathname.match(/^\/api\/products\/(\d+)$/);if(match){const id=Number(match[1]);const p=data.products.find(x=>x.id===id);
    if(method==='GET')return p?json(res,200,cleanedProduct(p)):err(res,404,'Товар не найден');
    if(['PUT','PATCH','DELETE'].includes(method)){if(!admin(req,res,data))return;if(!p)return err(res,404,'Товар не найден');if(method==='DELETE'){data.products=data.products.filter(x=>x.id!==id);saveData(data);return json(res,200,{ok:true});}
    const b=await readBody(req),full={...p,...b};const check=validateProduct(full);if(check)return err(res,400,check);Object.assign(p,productFields(full));saveData(data);return json(res,200,cleanedProduct(p));}}
  return err(res,404,'Адрес API не найден');
}
function validateProduct(b){if(typeof b.name!=='string'||b.name.trim().length<2)return 'Введите название товара';if(typeof b.category!=='string'||!b.category.trim())return 'Введите категорию';if(!Number.isInteger(Number(b.price))||Number(b.price)<0)return 'Некорректная цена';if(!Number.isInteger(Number(b.stock))||Number(b.stock)<0)return 'Некорректный остаток';return ''}
function productFields(b){return {name:String(b.name).trim(),description:String(b.description||'').trim(),category:String(b.category).trim(),price:Number(b.price),stock:Number(b.stock),inStock:Number(b.stock)>0,icon:String(b.icon||'box'),image:b.image?String(b.image):null};}
function staticFile(req,res,url){let file=url.pathname==='/'?'/index.html':url.pathname;try{let full=path.resolve(ROOT,'public','.'+decodeURIComponent(file));let base=path.resolve(ROOT,'public');if(!full.startsWith(base+path.sep)&&full!==base)return err(res,403,'Доступ запрещён');let buf=fs.readFileSync(full);res.writeHead(200,{'Content-Type':mime[path.extname(full)]||'application/octet-stream','X-Content-Type-Options':'nosniff','Cache-Control':'no-store'});res.end(buf);}catch{res.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'});res.end('Страница не найдена');}}
function createServer(){return http.createServer((req,res)=>{let url;try{url=new URL(req.url,'http://localhost');}catch{return err(res,400,'Некорректный URL');}if(url.pathname.startsWith('/api/')){Promise.resolve(api(req,res,url)).catch(e=>{console.error('[API]',e.code||'',e.message);if(!res.headersSent)err(res,e.status||500,e.status?e.message:'Ошибка сервера');});}else if(req.method==='GET'||req.method==='HEAD')staticFile(req,res,url);else err(res,405,'Метод не поддерживается');});}
if(require.main===module)createServer().listen(PORT,HOST,()=>console.log(`Магазин «Лист»: http://${HOST}:${PORT}\nAPI: http://${HOST}:${PORT}/api/health\nБаза: локальный файл data/shop.json (создаётся автоматически)`));
module.exports={createServer};
