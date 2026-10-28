// Core HTTP deliberately preserves Host: the admin validates public authority,
// while the lab's TCP destination is a numeric private/loopback address.
import http from 'node:http';
export function fixtureFetch(url,{method='GET',headers={},body,timeoutMs=5000}={}) {
  return new Promise((resolve,reject)=>{
    const req=http.request(url,{method,headers},res=>{
      let size=0;const chunks=[];
      res.on('data',b=>{size+=b.length;if(size>1024*1024)req.destroy(Error('response_limit'));else chunks.push(b);});
      res.on('error',reject);
      res.on('end',()=>resolve({status:res.statusCode,headers:{get:key=>Array.isArray(res.headers[key])?res.headers[key][0]:res.headers[key]},
        json:async()=>JSON.parse(Buffer.concat(chunks)),text:async()=>Buffer.concat(chunks).toString('utf8')}));
    });
    req.setTimeout(timeoutMs,()=>req.destroy(Error('http_fixture_timeout')));
    req.on('error',reject);req.end(body);
  });
}
