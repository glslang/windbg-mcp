const { init } = require('z3-solver');
const fs = require('fs');
const path = require('path');
const data = require('./data.js');

const MASK = (1n << 64n) - 1n;

// parse g table: lines "G <pos> <digit> <hex>"
const g = Array.from({ length: 25 }, () => new Array(10).fill(0n));
for (const line of fs.readFileSync(path.join(__dirname, 'gtable.txt'), 'utf8').split(/\r?\n/)) {
  const m = line.match(/^G (\d+) (\d+) ([0-9a-fA-F]+)/);
  if (m) g[+m[1]][+m[2]] = BigInt('0x' + m[3]);
}

// sanity check: my input's hash
const myD = data.myInput.split('').map(Number);
let s = 0n;
for (let i = 0; i < 25; i++) s = (s + data.Y[i] * g[i][myD[i]]) & MASK;
console.log('sanity: my hash =', s.toString(16), '/ expected', data.myHash.toString(16), s === data.myHash ? 'OK' : 'MISMATCH');

// precompute per-position addend constants a[i][d] = Y[i]*g[i][d] mod 2^64
const a = Array.from({ length: 25 }, (_, i) => Array.from({ length: 10 }, (_, d) => (data.Y[i] * g[i][d]) & MASK));

(async () => {
  const { Context } = await init();
  const ctx = Context('main');
  const { BitVec, If } = ctx;
  const B = (v) => BitVec.val(v & MASK, 64);

  const solver = new ctx.Solver();
  const d = [];
  for (let i = 0; i < 25; i++) {
    const di = BitVec.const('d' + i, 64);
    d.push(di);
    solver.add(di.ule(B(9n)));           // 0 <= d_i <= 9 (unsigned)
  }
  // total = sum of ITE-selected addends
  let total = B(0n);
  for (let i = 0; i < 25; i++) {
    let contrib = B(a[i][9]);
    for (let v = 8; v >= 0; v--) contrib = If(d[i].eq(B(BigInt(v))), B(a[i][v]), contrib);
    total = total.add(contrib);
  }
  solver.add(total.eq(B(data.target)));

  const res = await solver.check();
  console.log('z3:', res);
  if (res === 'sat') {
    const m = solver.model();
    const digits = [];
    for (let i = 0; i < 25; i++) digits.push(Number(m.eval(d[i]).value()));
    const code = digits.join('');
    console.log('SOLUTION:', code);
    // verify
    let v = 0n;
    for (let i = 0; i < 25; i++) v = (v + a[i][digits[i]]) & MASK;
    console.log('verify hash =', v.toString(16), '/ target', data.target.toString(16), v === data.target ? 'OK' : 'BAD');
  }
  process.exit(0);
})();
