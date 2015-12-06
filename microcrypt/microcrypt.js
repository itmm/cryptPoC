/**
 * @overview
 * MicroCrypt for JavaScript.
 *
 * Provides methods for encrypting and decrypting streams with the
 * Advanced Encryption Standard (AES) using 256 bit long keys. As chaining
 * method CBC will be used. Additionally SHA-512 is implemented to hash
 * passwords and compute check sums.
 *
 * The methods belonging to AES start with the prefix <code>aes_</code>.
 *
 * The methods belonging to CBC start with the prefix <code>cbc_</code>.
 *
 * The methods belonging to SHA start with the prefix <code>sha_</code>.
 *
 * Methods without these prefixes are helper methods for general usage.
 *
 * @author Timm Knape
 * @version $Revision: 1.5 $
 */
// copyright (c) 2007 Timm Knape <timm@knp.de>
// All rights reserved.

/**
 * parses a string into an array of bytes
 *
 * The string contains a hexadecimal representation of bytes without
 * any padding or separating characters.
 *
 * @param {String} str string that contains the encoded bytes
 * @returns Array, that contains the bytes as integer values
 * @type Array
 */
function parse_hex_array(str)
{
  var res = new Array(str.length / 2);
  for (var i = 0; i < (str.length / 2); ++i)
  {
    res[i] = parseInt(str.substr(2 * i, 2), 16);
  }
  return res;
}

/**
 * creates an array with random bytes.
 *
 * @param {Integer} l size of the Array
 * @returns Array of size <code>l</code> with random bytes
 * @type Array
 */
function random_array(l)
{
  var res = new Array(l);
  for (var i = 0; i < l; ++i)
  {
    res[i] = (Math.random() * 256) & 0xff;
  }
  return res;
}


// {{{1 AES encryption

/// @private s-box for permutating bytes
var aes_sbox = null;
/// @private inverse of the s-box permutation
var aes_invsbox = new Array(256);

/**
 * @private
 * initializes the s-boxes for AES.
 *
 * The s-box is created from a hexadecimal String.
 * The inverse is calculated by the origin s-box.
 *
 * This method will be called automatically on load.
 */
function aes_init_sbox()
{
  var sinit =
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0" +
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275" +
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf" +
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2" +
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb" +
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08" +
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e" +
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16";

  aes_sbox = parse_hex_array(sinit);
  for (var i = 0; i < 256; ++i)
  {
    aes_invsbox[aes_sbox[i]] = i;
  }
}

aes_init_sbox();

/// @private temporary buffer used in encryption and decryption
var aes_temp = new Array(16);

/**
 * expands the key to be used in encryption or decryption
 *
 * The original key is 32 bytes long.
 * This method creates a derived key that is 240 bytes long.
 *
 * @param {Array} original key
 * @returns expanded key
 * @type Array
 */
function aes_expand_key(orig_key)
{
  var expanded_key = new Array(240);
  var i, j, k;
  
  for (i = 0; i < 32; ++i) { expanded_key[i] = orig_key[i]; }
  for (i = 32; i < 240; i += 4)
  {
    for (j = 0; j < 4; ++j) 
    {
      expanded_key[i + j] = expanded_key[i - 4 + j]; 
    }

    if (i % 16 == 0) 
    {
      if (i % 32 == 0)
      {
        k = expanded_key[i];
        for (j = 0; j < 3; ++j) 
        {
          expanded_key[i + j] = expanded_key[i + j + 1]; 
        }
        expanded_key[i + 3] = k;
      }
      for (j = 0; j < 4; ++j) 
      { 
        expanded_key[i + j] = aes_sbox[expanded_key[i + j] & 0xff]; 
      }
      if (i % 32 == 0) { expanded_key[i] ^= 1 << (i/32 - 1); }
    }

    for (j = 0; j < 4; ++j)
    {
      expanded_key[i + j] ^= expanded_key[i + j - 32];
    }
  }

  return expanded_key;
}

/**
 * @private
 * performs a multiplication of polyonmials in a finite field.
 *
 * Let's ignore the math.
 * This method takes two bytes and multiplies them in a way,
 * that the result fits also in a byte.
 *
 * @param {Integer} a first argument
 * @param {Integer} b second argument
 * @returns product of <code>a</code> and <code>b</code>
 * @type Integer
 */
function aes_mul(a, b)
{
  var result = 0;
  while (a != 0)
  {
    if (a & 0x01) { result ^= b; }
    a >>= 1;
    b = (b << 1) ^ (b & 0x80? 0x1b: 0x00);
  }
  return result & 0xff;
}

/**
 * encrypts a block using the AES algorithm
 *
 * The expanded key and the original block won't be modified.
 * Only the Array that contains the encrypted block will be modified.
 *
 * @param {Array} expanded_key expanded key
 * @param {Array} in_block Array of bytes that contains the plain message
 * @param {Array} out_block will contain the encrypted block on exit
 */
function aes_encrypt(expanded_key, in_block, out_block)
{
  var i, j, s0, s1, s2, s3;

  for (i = 0; i < 16; ++i) { out_block[i] = in_block[i] ^ expanded_key[i]; }

  for (i = 1; i <= 14; ++i)
  {
    for (j = 0; j < 16; ++j) { out_block[j] = aes_sbox[out_block[j]]; }

    aes_temp[0] = out_block[0]; aes_temp[1] = out_block[5];
    aes_temp[2] = out_block[10]; aes_temp[3] = out_block[15];
    aes_temp[4] = out_block[4]; aes_temp[5] = out_block[9];
    aes_temp[6] = out_block[14]; aes_temp[7] = out_block[3];
    aes_temp[8] = out_block[8]; aes_temp[9] = out_block[13];
    aes_temp[10] = out_block[2]; aes_temp[11] = out_block[7];
    aes_temp[12] = out_block[12]; aes_temp[13] = out_block[1];
    aes_temp[14] = out_block[6]; aes_temp[15] = out_block[11];

    if (i < 14) 
    {
      for (j = 0; j < 4; ++j)
      {
        s0 = aes_temp[4 * j];
        s1 = aes_temp[4 * j + 1];
        s2 = aes_temp[4 * j + 2];
        s3 = aes_temp[4 * j + 3];

        aes_temp[4 * j] = aes_mul(2, s0) ^ aes_mul(3, s1) ^ s2 ^ s3;
        aes_temp[4 * j + 1] = s0 ^ aes_mul(2, s1) ^ aes_mul(3, s2) ^ s3;
        aes_temp[4 * j + 2] = s0 ^ s1 ^ aes_mul(2, s2) ^ aes_mul(3, s3);
        aes_temp[4 * j + 3] = aes_mul(3, s0) ^ s1 ^ s2 ^ aes_mul(2, s3);
      }
    }

    for (j = 0; j < 16; ++j) 
    {
      out_block[j] = aes_temp[j] ^ expanded_key[16 * i + j]; 
    }
  }
}

/**
 * decrypts a block using the AES algorithm
 *
 * The expanded key and the encrypted block won't be modified.
 * Only the Array that contains the decrypted block will be modified.
 *
 * @param {Array} expanded_key expanded_key
 * @param {Array} in_block block with the encrypted data
 * @param {Array} out_block on exit this Array will contain the decrypted
 *   data
 */
function aes_decrypt(expanded_key, in_block, out_block)
{
  var i, j, s0, s1, s2, s3;

  for (i = 0; i < 16; ++i) 
  {
    out_block[i] = in_block[i] ^ expanded_key[224 + i]; 
  }

  for (i = 13; i >= 0; --i)
  {
    aes_temp[0] = out_block[0]; aes_temp[1] = out_block[13];
    aes_temp[2] = out_block[10]; aes_temp[3] = out_block[7];
    aes_temp[4] = out_block[4]; aes_temp[5] = out_block[1];
    aes_temp[6] = out_block[14]; aes_temp[7] = out_block[11];
    aes_temp[8] = out_block[8]; aes_temp[9] = out_block[5];
    aes_temp[10] = out_block[2]; aes_temp[11] = out_block[15];
    aes_temp[12] = out_block[12]; aes_temp[13] = out_block[9];
    aes_temp[14] = out_block[6]; aes_temp[15] = out_block[3];
    
    for (j = 0; j < 16; ++j) { out_block[j] = aes_invsbox[aes_temp[j]]; }

    for (j = 0; j < 16; ++j) { out_block[j] ^= expanded_key[i * 16 + j]; }

    if (i > 0) 
    {
      for (j = 0; j < 4; ++j)
      {
        s0 = out_block[4 * j];
        s1 = out_block[4 * j + 1];
        s2 = out_block[4 * j + 2];
        s3 = out_block[4 * j + 3];

        out_block[4 * j] = aes_mul(0x0e, s0) ^ aes_mul(0x0b, s1) ^ 
          aes_mul(0x0d, s2) ^ aes_mul(0x09, s3);
        out_block[4 * j + 1] = aes_mul(0x09, s0) ^ aes_mul(0x0e, s1) ^ 
          aes_mul(0x0b, s2) ^ aes_mul(0x0d, s3);
        out_block[4 * j + 2] = aes_mul(0x0d, s0) ^ aes_mul(0x09, s1) ^ 
          aes_mul(0x0e, s2) ^ aes_mul(0x0b, s3);
        out_block[4 * j + 3] = aes_mul(0x0b, s0) ^ aes_mul(0x0d, s1) ^ 
          aes_mul(0x09, s2) ^ aes_mul(0x0e, s3);
      }
    }
  }
}

// }}}1

// {{{1 CBC
/**
 * creates a CBC object
 *
 * It creates an opaque object that contains running data used by
 * the encryption or decryption.
 *
 * An instance can be used for encryption or decryption,
 * but not for both.
 *
 * @param {Array} key key that will be expanded for the use of AES
 * @param {Array} iv initial value of the state.
 * @returns opaque type to encapsulate the state
 * @type Cbc
 */
function cbc_init(key, iv)
{
  var result = new Object();
  result.key = aes_expand_key(key);
  result.block = new Array(16);
  result.block_used = 0;
  result.last = new Array(16);
  for (var i = 0; i < 16; ++i) { result.last[i] = iv[i]; }
  result.out_buffer = new Array(16);
  result.out_buffer_used = false;
  return result;
}

/**
 * encrypts the data using the CBC schema with AES
 *
 * If enough data for a new block is present, the block will be
 * encrypted and passed to the output stream. 
 * The output stream is a method that accepts an Array of bytes.
 *
 * @param {Cbc} cbc current state of the encryption
 * @param {Array} data to be encrypted
 * @param {Function} block_out output stream of the encrypted data.
 */
function cbc_encrypt(cbc, data, block_out)
{
  for (var byt = 0; byt < data.length; ++byt)
  {
    cbc.block[cbc.block_used++] = data[byt];
    if (cbc.block_used == 16)
    {
      for (var i = 0; i < 16; ++i) { cbc.last[i] ^= cbc.block[i]; }
      aes_encrypt(cbc.key, cbc.last, cbc.out_buffer);
      for (var i = 0; i < 16; ++i) { cbc.last[i] = cbc.out_buffer[i]; } 

      block_out(cbc.out_buffer);
      cbc.block_used = 0;
    }
  }
}

/**
 * concludes the encryption phase
 *
 * The current data will be padded.
 * The resulting block will be encrypted using {@link #cbc_encrypt}.
 *
 * @param {Cbc} cbc current state of the encryption
 * @param {Function} block_out output stream of the encrypted data
 */
function cbc_finish_encrypt(cbc, block_out)
{
  var pad = new Array(1);
  pad[0] = 16 - cbc.block_used;
  if (cbc.block_used == 0) { cbc_encrypt(cbc, pad, block_out); }
  while (cbc.block_used > 0) { cbc_encrypt(cbc, pad, block_out); }
}

/**
 * decrypts the data using the CBC schema with AES
 *
 * If enough data for a new block is present, 
 * any pending decrypted blocks will be sent to the output stream.
 * The block will be decrypted and marked as pending.
 * The pending is necessary,
 * because the last block contains padding information.
 *
 * The output stream is a method that accepts an Array of bytes.
 *
 * @param {Cbc} cbc current state of the decryption
 * @param {Array} data to be decrypted
 * @param {Function} block_out output stream of the decrypted data
 */
function cbc_decrypt(cbc, data, block_out)
{
  for (var byt = 0; byt < data.length; ++byt)
  {
    cbc.block[cbc.block_used++] = data[byt];
    if (cbc.block_used == 16)
    {
      if (cbc.out_buffer_used) 
      {
        block_out(cbc.out_buffer);
        cbc.out_buffer_used = false;
      }

      aes_decrypt(cbc.key, cbc.block, cbc.out_buffer);
      for (var i = 0; i < 16; ++i)
      {
        cbc.out_buffer[i] ^= cbc.last[i];
        cbc.last[i] = cbc.block[i];
      }
        
      cbc.out_buffer_used = true;
      cbc.block_used = 0;
    }
  }
}

/**
 * concludes the decryption phase
 *
 * The padding will be removed from the last pending block and
 * the decrypted bytes will be sent to the output stream.
 *
 * If the decryption fails, e.g. because an invalid padding is
 * present,
 * the method will return <code>false</code>.
 *
 * @param {Cbc} cbc current state of the decryption
 * @param {Function} block_out output stream of the decrypted data
 * @returns <code>true</code> iff the decryption hasn't failed
 * @type Boolean
 */
function cbc_finish_decrypt(cbc, block_out)
{
  if (cbc.block_used > 0) { return false; }
  if (! cbc.out_buffer_used) { return true; }

  var pad = cbc.out_buffer[15];
  if (pad <= 0 || pad > 16) { return false; }

  var left = 16 - pad;
  if (left == 0) { return true; }
  
  var result = new Array(left);
  for (var i = 0; i < left; ++i) { result[i] = cbc.out_buffer[i]; }
  block_out(result);
  return true;
}

// }}}1

// {{{1 SHA

/// @private values to disguise the algorithm a bit more
var sha_consts = [
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f,
  0xe9b5dba5, 0x8189dbbc, 0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
  0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118, 0xd807aa98, 0xa3030242,
  0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235,
  0xc19bf174, 0xcf692694, 0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
  0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65, 0x2de92c6f, 0x592b0275,
  0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f,
  0xbf597fc7, 0xbeef0ee4, 0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
  0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70, 0x27b70a85, 0x46d22ffc,
  0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6,
  0x92722c85, 0x1482353b, 0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
  0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30, 0xd192e819, 0xd6ef5218,
  0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99,
  0x34b0bcb5, 0xe19b48a8, 0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
  0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3, 0x748f82ee, 0x5defb2fc,
  0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915,
  0xc67178f2, 0xe372532b, 0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
  0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178, 0x06f067aa, 0x72176fba,
  0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc,
  0x431d67c4, 0x9c100d4c, 0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
  0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
];

/**
 * creates a SHA object
 *
 * It creates an opaque object that contains running data used by
 * hash algorithm.
 *
 * @returns opaque type to encapsulate the state
 * @type Sha
 */
function sha_init()
{
  var res = new Object();
  res.hash = [
    0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 
    0xa54ff53a, 0x5f1d36f1, 0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f,
    0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179
  ];
  res.buffer = new Array(4);
  res.buffer_used = 0;
  res.count = 0;
  res.work = new Array(160);
  res.work_used = 0;

  return res;
}

/// @private temporary storage for a 64 bit Integer
var sha_temp1 = [0, 0];
/// @private temporary storage for a 64 bit Integer
var sha_temp2 = [0, 0];
/// @private temporary storage for a 64 bit Integer
var sha_temp3 = [0, 0];
/// @private temporary storage for a 64 bit Integer
var sha_temp4 = [0, 0];
/// @private temporary storage for a 64 bit Integer
var sha_a = [0, 0];
/// @private temporary storage for a 64 bit Integer
var sha_b = [0, 0];
/// @private temporary storage for a 64 bit Integer
var sha_c = [0, 0];
/// @private temporary storage for a 64 bit Integer
var sha_d = [0, 0];
/// @private temporary storage for a 64 bit Integer
var sha_e = [0, 0];
/// @private temporary storage for a 64 bit Integer
var sha_f = [0, 0];
/// @private temporary storage for a 64 bit Integer
var sha_g = [0, 0];
/// @private temporary storage for a 64 bit Integer
var sha_h = [0, 0];

/**
 * adds two 64 bit Integers
 *
 * The integers are stored in Arrays at the given positions.
 * The value of <code>b</code> will be added to <code>a</code>.
 * The value of <code>a</code> will be modified by this method.
 *
 * @param {Array} a Array that stores the first operand and the result
 * @param {Integer} a_pos position of the number in <code>a</code>
 * @param {Array} b Array that stores the second operand
 * @param {Integer} b_pos position of the number in <code>b</code>
 */
function sha_add(a, a_pos, b, b_pos)
{
  var sum = (a[a_pos + 1] + b[b_pos + 1]) & 0xffffffff;
  if (sum < (a[a_pos + 1] | b[b_pos + 1]))
  {
    a[a_pos] = (a[a_pos] + b[b_pos] + 1) & 0xffffffff;
  }
  else
  {
    a[a_pos] = (a[a_pos] + b[b_pos]) & 0xffffffff;
  }
  a[a_pos + 1] = sum;
}

/**
 * shifts the 64 bit value of <code>b</code> <code>bits</code> bits
 * to the right
 *
 * The added bits are 0's. The value of <code>bits</code> must be smaller
 * than 32.
 *
 * The result is stored in <code>a</code> at the position 0 and 1.
 *
 * @param {Array} a place to store the shifted value
 * @param {Array} b original value
 * @param {Integer} b_pos position in <code>b</code> of the value
 * @param {Integer} bits number of bits to shift
 */
function sha_shift(a, b, b_pos, bits)
{
    a[0] = (b[b_pos] >>> bits);
    a[1] = b[b_pos + 1] >>> bits | (b[b_pos] << (32 - bits));
}

/**
 * rotates the 64 bit value of <code>b</code> <code>bits</code> bits
 * to the right
 *
 * Bits that are shifted off the one end are added at the other end.
 *
 * The result is stored in <code>a</code>.
 *
 * @param {Array} a place to store the rotated value
 * @param {Integer} a_pos position in <code>a</code> to store the value
 * @param {Array} b original value
 * @param {Integer} b_pos position in <code>b</code> of the value
 * @param {Integer} bits number of bits to shift
 */
function sha_rot(a, a_pos, b, b_pos, bits)
{
  var t1, t2;
  if (bits < 32)
  {
    a[a_pos] = (b[b_pos] >>> bits) | (b[b_pos + 1] << (32 - bits));
    a[a_pos + 1] = (b[b_pos + 1] >>> bits) | (b[b_pos] << (32 - bits));
  }
  else
  {
    a[a_pos] = (b[b_pos + 1] >>> (bits - 32)) | (b[b_pos] << (64 - bits));
    a[a_pos + 1] = (b[b_pos] >>> (bits - 32)) |
      (b[b_pos + 1] << (64 - bits));
  }
}

/**
 * appends whole array to the hash
 *
 * @param {Sha} sha current state
 * @param {Array} data bytes, that should be added to the hash
 */
function sha_append(sha, data)
{
  sha_append_with_count(sha, data, data.length);
}

/**
 * appends the first bytes of an array to the hash
 *
 * @param {Sha} sha current state
 * @param {Array} data bytes, that should be added to the hash
 * @param {Integer} count number of bytes to add
 */
function sha_append_with_count(sha, data, count)
{
  for (var byt = 0; byt < count; ++byt)
  {
    sha.buffer[sha.buffer_used++] = data[byt];
    sha.count += 8;
    if (sha.buffer_used == 4)
    {
      sha.work[sha.work_used++] = (sha.buffer[0] << 24) |
        (sha.buffer[1] << 16) | (sha.buffer[2] << 8) | sha.buffer[3];

      sha.buffer_used = 0;
      if (sha.work_used == 32)
      {
        for (i = 16; i < 80; ++i)
        {
          //sigma1(sha.work, i * 2, sha.work, (i - 2) * 2);
          var j = i * 2;
          var k = (i - 2) * 2;
          sha_rot(sha.work, j, sha.work, k, 19);
          sha_rot(sha_temp1, 0, sha.work, k, 61);
          sha.work[j] ^= sha_temp1[0];
          sha.work[j + 1] ^= sha_temp1[1];
          sha_shift(sha_temp1, sha.work, k, 6);
          sha.work[j] ^= sha_temp1[0];
          sha.work[j + 1] ^= sha_temp1[1];

          sha_add(sha.work, i * 2, sha.work, (i - 7) * 2);

          // sigma0(sha_temp2, 0, sha.work, (i - 15) * 2);
          j = (i - 15) * 2;
          sha_rot(sha_temp2, 0, sha.work, j, 1);
          sha_rot(sha_temp1, 0, sha.work, j, 8);
          sha_temp2[0] ^= sha_temp1[0];
          sha_temp2[1] ^= sha_temp1[1];
          sha_shift(sha_temp1, sha.work, j, 7);
          sha_temp2[0] ^= sha_temp1[0];
          sha_temp2[1] ^= sha_temp1[1];

          sha_add(sha.work, i * 2, sha_temp2, 0);
          sha_add(sha.work, i * 2, sha.work, (i - 16) * 2);
        }
        sha_a[0] = sha.hash[0]; sha_a[1] = sha.hash[1];
        sha_b[0] = sha.hash[2]; sha_b[1] = sha.hash[3];
        sha_c[0] = sha.hash[4]; sha_c[1] = sha.hash[5];
        sha_d[0] = sha.hash[6]; sha_d[1] = sha.hash[7];
        sha_e[0] = sha.hash[8]; sha_e[1] = sha.hash[9];
        sha_f[0] = sha.hash[10]; sha_f[1] = sha.hash[11];
        sha_g[0] = sha.hash[12]; sha_g[1] = sha.hash[13];
        sha_h[0] = sha.hash[14]; sha_h[1] = sha.hash[15];

        for (i = 0; i < 80; ++i)
        {
          sha_temp3[0] = sha_h[0]; sha_temp3[1] = sha_h[1];
          
          // Sigma1(sha_temp2, 0, sha_e, 0);
          sha_rot(sha_temp2, 0, sha_e, 0, 14);
          sha_rot(sha_temp1, 0, sha_e, 0, 18);
          sha_temp2[0] ^= sha_temp1[0];
          sha_temp2[1] ^= sha_temp1[1];
          sha_rot(sha_temp1, 0, sha_e, 0, 41);
          sha_temp2[0] ^= sha_temp1[0];
          sha_temp2[1] ^= sha_temp1[1];
          
          sha_add(sha_temp3, 0, sha_temp2, 0);

          // sha_ch(sha_temp2, sha_e, sha_f, sha_g);
          sha_temp2[0] = (sha_e[0] & sha_f[0]) ^ (~sha_e[0] & sha_g[0]);
          sha_temp2[1] = (sha_e[1] & sha_f[1]) ^ (~sha_e[1] & sha_g[1]);
  
          sha_add(sha_temp3, 0, sha_temp2, 0);
          sha_add(sha_temp3, 0, sha_consts, i * 2);
          sha_add(sha_temp3, 0, sha.work, i * 2);

          // Sigma0(sha_temp4, 0, sha_a, 0);
          sha_rot(sha_temp4, 0, sha_a, 0, 28);
          sha_rot(sha_temp1, 0, sha_a, 0, 34);
          sha_temp4[0] ^= sha_temp1[0];
          sha_temp4[1] ^= sha_temp1[1];
          sha_rot(sha_temp1, 0, sha_a, 0, 39);
          sha_temp4[0] ^= sha_temp1[0];
          sha_temp4[1] ^= sha_temp1[1];
  
          // sha_maj(sha_temp2, sha_a, sha_b, sha_c);
          sha_temp2[0] = (sha_a[0] & sha_b[0]) ^ (sha_a[0] & sha_c[0]) ^
            (sha_b[0] & sha_c[0]);
          sha_temp2[1] = (sha_a[1] & sha_b[1]) ^ (sha_a[1] & sha_c[1]) ^
            (sha_b[1] & sha_c[1]);

          sha_add(sha_temp4, 0, sha_temp2, 0);
          sha_h[0] = sha_g[0]; sha_h[1] = sha_g[1];
          sha_g[0] = sha_f[0]; sha_g[1] = sha_f[1];
          sha_f[0] = sha_e[0]; sha_f[1] = sha_e[1];
          sha_e[0] = sha_d[0]; sha_e[1] = sha_d[1];
          sha_add(sha_e, 0, sha_temp3, 0);
          sha_d[0] = sha_c[0]; sha_d[1] = sha_c[1];
          sha_c[0] = sha_b[0]; sha_c[1] = sha_b[1];
          sha_b[0] = sha_a[0]; sha_b[1] = sha_a[1];
          sha_a[0] = sha_temp3[0]; sha_a[1] = sha_temp3[1];
          sha_add(sha_a, 0, sha_temp4, 0);
        }

        sha_add(sha.hash, 0, sha_a, 0);
        sha_add(sha.hash, 2, sha_b, 0);
        sha_add(sha.hash, 4, sha_c, 0);
        sha_add(sha.hash, 6, sha_d, 0);
        sha_add(sha.hash, 8, sha_e, 0);
        sha_add(sha.hash, 10, sha_f, 0);
        sha_add(sha.hash, 12, sha_g, 0);
        sha_add(sha.hash, 14, sha_h, 0);

        sha.work_used = 0;
      }
    }
  }
}

/**
 * concludes the hashing
 *
 * Padding information is added to the hash.
 * After the call to this method,
 * the hash can be retrieved in <code>sha.hash</code>.
 *
 * @param {Sha} sha current state
 */
function sha_finish(sha)
{
  var c = sha.count;
  var pad = [ 0x80 ];
  var fill = [ 0x00 ];
  sha_append(sha, pad);
  while (sha.count % 1024 != 896) { sha_append(sha, fill); }
  var length = new Array(16);
  for (var i = 0; i < 16; ++i)
  {
    length[15 - i] = c & 0xff;
    c = c >>> 8;
  }
  sha_append(sha, length);
}

// }}}1 SHA
