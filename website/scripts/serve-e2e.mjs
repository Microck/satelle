// Serve only the built static export with the same clean .html route convention.
import {createServer} from 'node:http';
import {readFile,stat} from 'node:fs/promises';
import {resolve,sep,extname} from 'node:path';
const root=resolve('out');
const types={'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml','.png':'image/png','.woff2':'font/woff2','.txt':'text/plain'};
createServer(async(req,res)=>{
 try{
  const path=resolve(root,'.'+decodeURIComponent(new URL(req.url,'http://local').pathname));
  if(path!==root&&!path.startsWith(root+sep)){res.writeHead(403);res.end();return;}
  for(const file of [path,path+'.html',resolve(path,'index.html')]){
   if(!file.startsWith(root+sep))continue;
   const info=await stat(file).catch(()=>null);
   if(!info?.isFile())continue;
   res.writeHead(200,{'Content-Type':types[extname(file)]??'application/octet-stream'});res.end(await readFile(file));return;
  }
  res.writeHead(404);res.end('Not found');
 }catch{res.writeHead(400);res.end('Bad request');}
}).listen(4184,'127.0.0.1');
