'use strict';
const fs=require('node:fs'),path=require('node:path');
const email=String(process.argv[2]||'').trim().toLowerCase();
if(!email){console.error('Использование: node make-admin.js email@example.com');process.exit(1);}
const f=path.join(__dirname,'data','shop.json');
const d=JSON.parse(fs.readFileSync(f,'utf8'));
const u=d.users.find(x=>x.email===email);
if(!u){console.error('Пользователь не найден. Сначала зарегистрируйтесь через сайт.');process.exit(1);}
u.role='admin';fs.writeFileSync(f,JSON.stringify(d,null,2));console.log('Роль admin назначена:',u.email);
