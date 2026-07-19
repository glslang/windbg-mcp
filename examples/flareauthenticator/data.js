// FlareAuthenticator hash model extracted via TTD.
// hash = sum_i  Y[i] * g( (i+1)*256 + 0x30 + d_i )   (mod 2^64)
// check target = 0x0bc42d5779fec401
// my input "1234567890123456789012345" -> hash 0x05b735c36628fcab (cross-check)
module.exports = {
  target: 0x0bc42d5779fec401n,
  myHash: 0x05b735c36628fcabn,
  myInput: "1234567890123456789012345",
  // Y[i] per-position weight (i = 0..24)
  Y: [
    0x0279342fn, 0x0c678db8n, 0x087d0f40n, 0x0cc48d40n, 0x0c60a7f3n,
    0x0716c0d7n, 0x032c5f65n, 0x0b49d7afn, 0x01b186d3n, 0x0545d8d5n,
    0x06b2f406n, 0x009a868cn, 0x07024229n, 0x048bdaaen, 0x05f8f14fn,
    0x09d5d059n, 0x0dc0222fn, 0x03d1d2b6n, 0x0d63209an, 0x0b3c02cbn,
    0x06fb781en, 0x0f2d7eeen, 0x0ca922ean, 0x0adf00dfn, 0x04775803n
  ],
  // g[i][d] filled by the live evaluator (g of arg (i+1)*256 + 0x30 + d)
  g: null,
  // cross-check g values for my input digits (from the trace), arg=(i+1)*256+0x30+myDigit
  gCheck: {
    // pos: [digit, arg, g]
    0: [1, 0x131, 0x6235f14n], 1: [2, 0x232, 0x806e2bn], 2: [3, 0x333, 0xe616e02n],
    3: [4, 0x434, 0xb797345n], 4: [5, 0x535, 0x5cfa0d4n], 5: [6, 0x636, 0xdbe9118n],
    6: [7, 0x737, 0x21bd10cn]
  }
};
