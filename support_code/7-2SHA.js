//= ===============================================================
// SHA1.js
//
// Module that replicates the SHA-1 Cryptographic Hash
// function in Javascript.
//= ===============================================================

// main variables
const CHAR_SIZE = 8;

/**
 * Adds padding to binary/hex string represention
 *
 * @param {string} str - string represention (binary/hex)
 * @param {int} bits - total number of bits wanted
 * @return {string} - string represention padding with empty (0) bits
 *
 * @example
 *      pad("10011", 8); // "00010011"
 */
function pad(str, bits) {
  let res = str;
  while (res.length % bits !== 0) {
    res = "0" + res;
  }
  return res;
}

/**
 * Separates string into chunks of the same size
 *
 * @param {string} str - string to separate into chunks
 * @param {int} size - number of characters wanted in each chunk
 * @return {array} - array of original string split into chunks
 *
 * @example
 *      chunkify("this is a test", 2); // ["th", "is", " i", "s ", "a ", "te", "st"]
 */
function chunkify(str, size) {
  const chunks = [];
  for (let i = 0; i < str.length; i += size) {
    chunks.push(str.slice(i, i + size));
  }
  return chunks;
}

/**
 * Rotates string representation of bits to the left
 *
 * @param {string} bits - string representation of bits
 * @param {int} turns - number of rotations to make
 * @return {string} - string representation of bits after rotation
 *
 * @example
 *      rotateLeft("1011", 3); // "1101"
 */
function rotateLeft(bits, turns) {
  return bits.substr(turns) + bits.substr(0, turns);
}

/**
 * Pre-processes message to feed the algorithm loop
 *
 * @param {string} message - message to pre-process
 * @return {string} - processed message
 */
function preProcess(message) {
  // convert message to binary representation padded to
  // 8 bits, and add 1
  let m =
    message
      .split("")
      .map((e) => e.charCodeAt(0)) // 轉換為ASCII CODE的ARRAY
      .map((e) => e.toString(2)) // 轉換成二進制數字，並改變資料型態為string
      .map((e) => pad(e, 8)) //把每個二進制數字前面塞入0，使得每個數字都有8 bits的長度。
      .join("") + "1"; // 把所有的字都串在一起，在最後面加上1。

  // 把這些二進制的數字後方再加入更多的0，直到總長度為 𝑥≡448 (𝑚𝑜𝑑 512)的值為止。
  while (m.length % 512 !== 448) {
    m += "0";
  }

  // 把第三步獲得的binary array內的bits全部串在一起，做成新的string。找到這個string的長度，以我們上面的例子來說，我們有6個8bits的元素在array內部，所以string長度為48。
  // 把第六步獲得的長度換成二進制，之後在這個二進制的數字前面塞入更多的0，直到總長度為64。
  let ml = (message.length * CHAR_SIZE).toString(2);
  ml = pad(ml, 8);
  ml = "0".repeat(64 - ml.length) + ml;

  return m + ml;
}

/**
 * Hashes message using SHA-1 Cryptographic Hash Function
 *
 * @param {string} message - message to hash
 * @return {string} - message digest (hash value)
 */
function SHA1(message) {
  // main variables
  let H0 = 0x67452301;
  let H1 = 0xefcdab89;
  let H2 = 0x98badcfe;
  let H3 = 0x10325476;
  let H4 = 0xc3d2e1f0;

  // pre-process message and split into 512 bit chunks
  const bits = preProcess(message); // 講義步驟1-8
  const chunks = chunkify(bits, 512); // 將第八步的string換成長度為512bits的小區塊。

  chunks.forEach(function (chunk, i) {
    // 將第九步獲得的每個小區塊換成16個32 bits的小小區塊。
    const words = chunkify(chunk, 32);

    // 將第十步所得到的16個32 bits的小小區塊，用bitwise operation XOR擴展成共有80個32 bits的小小區塊。
    for (let i = 16; i < 80; i++) {
      const val = [words[i - 3], words[i - 8], words[i - 14], words[i - 16]]
        .map((e) => parseInt(e, 2))
        .reduce((acc, curr) => curr ^ acc, 0);
      const bin = (val >>> 0).toString(2);
      const paddedBin = pad(bin, 32);
      const word = rotateLeft(paddedBin, 1);
      words.push(word);
    }

    // 創造五個隨意的16bits的變數。
    let [a, b, c, d, e] = [H0, H1, H2, H3, H4];
    // 用loop跑每個小小區塊，用bitwise operation把上面創造的五個變數內的值做改變。
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }
      // make sure f is unsigned
      f >>>= 0;

      const aRot = rotateLeft(pad(a.toString(2), 32), 5);
      const aInt = parseInt(aRot, 2) >>> 0;
      const wordInt = parseInt(words[i], 2) >>> 0;
      const t = aInt + f + e + k + wordInt;
      e = d >>> 0;
      d = c >>> 0;
      const bRot = rotateLeft(pad(b.toString(2), 32), 30);
      c = parseInt(bRot, 2) >>> 0;
      b = a >>> 0;
      a = t >>> 0;
    }

    // add values for this chunk to main hash variables (unsigned)
    H0 = (H0 + a) >>> 0;
    H1 = (H1 + b) >>> 0;
    H2 = (H2 + c) >>> 0;
    H3 = (H3 + d) >>> 0;
    H4 = (H4 + e) >>> 0;
  });

  // 把這五個變數的值換成十六進制的數字，串一起後，就是hash value！
  const HH = [H0, H1, H2, H3, H4]
    .map((e) => e.toString(16))
    .map((e) => pad(e, 8))
    .join("");

  return HH;
}

console.log(SHA1("A Test"));
console.log(SHA1("A Test"));
console.log(SHA1("A test"));
console.log(SHA1("A"));
