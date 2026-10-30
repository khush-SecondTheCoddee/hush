'use strict';
/* Small dependency-free QR encoder: byte mode, version 3-L (up to 53 UTF-8 bytes). */
(() => {
  const N=29, DATA=55, ECC=15;
  function mul(x,y){let z=0;for(let i=7;i>=0;i--){z=(z<<1)^((z>>>7)*0x11d);if((y>>>i)&1)z^=x}return z}
  function generator(degree){let p=[1],root=1;for(let i=0;i<degree;i++){const q=Array(p.length+1).fill(0);for(let j=0;j<p.length;j++){q[j]^=p[j];q[j+1]^=mul(p[j],root)}p=q;root=mul(root,2)}return p}
  function ecc(data,count){const g=generator(count),out=Array(count).fill(0);for(const b of data){const factor=b^out.shift();out.push(0);for(let j=0;j<count;j++)out[j]^=mul(g[j+1],factor)}return out}
  function matrixFor(text){const bytes=[...new TextEncoder().encode(text)];if(bytes.length>53)throw Error('Invite is too long for a QR code. Use the username instead.');const bits=[];const append=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>>i)&1)};append(4,4);append(bytes.length,8);for(const b of bytes)append(b,8);for(let i=0;i<Math.min(4,DATA*8-bits.length);i++)bits.push(0);while(bits.length%8)bits.push(0);const words=[];for(let i=0;i<bits.length;i+=8){let x=0;for(let j=0;j<8;j++)x=(x<<1)|bits[i+j];words.push(x)}for(let pad=0;words.length<DATA;pad++)words.push(pad%2?0x11:0xec);const stream=[...words,...ecc(words,ECC)];const m=Array.from({length:N},()=>Array(N).fill(null));
    const finder=(r,c)=>{for(let dy=-1;dy<=7;dy++)for(let dx=-1;dx<=7;dx++){const y=r+dy,x=c+dx;if(y<0||y>=N||x<0||x>=N)continue;m[y][x]=dy>=0&&dy<=6&&dx>=0&&dx<=6&&(dy===0||dy===6||dx===0||dx===6||(dy>=2&&dy<=4&&dx>=2&&dx<=4))}};
    finder(0,0);finder(0,N-7);finder(N-7,0);
    for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++){const v=Math.max(Math.abs(dx),Math.abs(dy));m[22+dy][22+dx]=v!==1}
    for(let i=8;i<N-8;i++){if(m[6][i]===null)m[6][i]=i%2===0;if(m[i][6]===null)m[i][6]=i%2===0}
    for(let i=0;i<9;i++){if(i!==6){m[i][8]=false;m[8][i]=false}}for(let i=N-8;i<N;i++){m[i][8]=false;m[8][i]=false}
    let bitIndex=0,up=true;for(let right=N-1;right>=1;right-=2){if(right===6)right=5;for(let vert=0;vert<N;vert++){const y=up?N-1-vert:vert;for(let j=0;j<2;j++){const x=right-j;if(m[y][x]!==null)continue;const bit=bitIndex<stream.length*8?((stream[bitIndex>>>3]>>>(7-(bitIndex&7)))&1):0;bitIndex++;m[y][x]=Boolean(bit^((y+x)%2===0))}}up=!up}
    let format=(1<<3);let rem=format<<10;for(let i=14;i>=10;i--)if((rem>>>i)&1)rem^=0x537<<(i-10);const f=((format<<10)|rem)^0x5412;const fb=i=>((f>>>i)&1)!==0;
    for(let i=0;i<=5;i++)m[i][8]=fb(i);m[7][8]=fb(6);m[8][8]=fb(7);m[8][7]=fb(8);for(let i=9;i<15;i++)m[8][14-i]=fb(i);
    for(let i=0;i<8;i++)m[8][N-1-i]=fb(i);for(let i=8;i<15;i++)m[N-15+i][8]=fb(i);m[N-8][8]=true;return m}
  function svg(text){const m=matrixFor(text),q=4,size=N+q*2;let d='';for(let y=0;y<N;y++)for(let x=0;x<N;x++)if(m[y][x])d+=`M${x+q} ${y+q}h1v1h-1z`;return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" role="img" aria-label="QR code"><rect width="${size}" height="${size}" fill="#fff"/><path d="${d}" fill="#202720"/></svg>`}
  window.HushQR={svg};
})();
