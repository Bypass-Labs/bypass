import fs from 'node:fs';
import http from 'node:http';
const server=http.createServer((req,res)=>{
  if(req.url.endsWith('SHASUMS256.txt'))res.end(['x64','arm64'].map(cpu=>'0'.repeat(64)+`  bypass-win-${cpu}.zip`).join('\n')+'\n');
  else if(req.url.endsWith('.zip'))res.end('deliberately corrupt archive');
  else{res.statusCode=404;res.end();}
});
server.listen(0,'127.0.0.1',()=>fs.writeFileSync(process.argv[2],String(server.address().port)));
