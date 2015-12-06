/**
 * @overview
 * encrypts and decrypts strings using microcrypt.js
 *
 * A fixed data format will be assumed:
 *
 * <ul>
 *   <li>version number 0x01 (1 byte),</li>
 *   <li>salt (16 bytes),</li>
 *   <li>iv (16 bytes),</li>
 *   <li>encrypted part.</li>
 * </ul>
 *
 * The encrypted part contains the data followed by a SHA checksum.
 *
 * @author Timm Knape
 * @version $Revision: 1.2 $
 */
// copyright (c) 2007 Timm Knape <timm@knp.de>
// All rights reserved.

/**
 * @private
 * creates a byte Array from a password and a salt
 *
 * The resulting Array can be used as an AES key.
 *
 * @param {String} password Password string that will be expanded as
 *   byte Array of unicode letters (each character expands to two bytes)
 * @param {Array} salt random bytes
 * @returns bytes that can be used as key for AES
 * @type Array
 */
function hash_password(password, salt)
{
  var sha = sha_init();
  sha_append(sha, salt);
  var a = new Array(2);
  for (var i = 0; i < password.length; ++i)
  {
    a[0] = password.charCodeAt(i) >>> 8;;
    a[1] = password.charCodeAt(i) & 0xff;
    sha_append(sha, a);
  }
  sha_finish(sha);
  var pw = new Array(32);
  for (i = 0; i < 8; ++i)
  {
    pw[4 * i] = sha.hash[i] >>> 24;
    pw[4 * i + 1] = (sha.hash[i] >>> 16) & 0xff;
    pw[4 * i + 2] = (sha.hash[i] >>> 8) & 0xff;
    pw[4 * i + 3] = sha.hash[i] & 0xff;
  }
  return pw;
}

/**
 * encrypts a message with the given password.
 *
 * The resulting String is a hexadecimal representation of the ciphertext.
 *
 * @param {String} password password used in the encryption
 * @param {String} plain original message
 * @returns encrypted message
 * @type String
 */
function encrypt_string(password, plain)
{
  var salt = random_array(16);
  var iv = random_array(16);
  var pw = hash_password(password, salt);

  var result = '01';
  function encrypted_writer(block)
  {
    var val;
    for (var x = 0; x < block.length; ++x)
    {
      val = block[x].toString(16);
      if (block[x] < 16) { val = "0" + val; }
      result += val;
    }
  }

  encrypted_writer(salt);
  encrypted_writer(iv);
  var cbc = cbc_init(pw, iv);
  var sha = sha_init();
  var a = new Array(2);
  for (i = 0; i < plain.length; ++i)
  {
    a[0] = plain.charCodeAt(i) >>> 8;
    a[1] = plain.charCodeAt(i) & 0xff;
    sha_append(sha, a);
    cbc_encrypt(cbc, a, encrypted_writer);
  }
  sha_finish(sha);
  var sha_entry = new Array(4);
  for (i = 0; i < 8; ++i)
  {
    sha_entry[0] = sha.hash[i] >>> 24;
    sha_entry[1] = (sha.hash[i] >>> 16) & 0xff;
    sha_entry[2] = (sha.hash[i] >>> 8) & 0xff;
    sha_entry[3] = sha.hash[i] & 0xff;
    cbc_encrypt(cbc, sha_entry, encrypted_writer);
  }
  cbc_finish_encrypt(cbc, encrypted_writer);
  
  return result;
}

/**
 * decrypts a message with the given password.
 *
 * The encrypted String is a hexadecimal representation of the ciphertext.
 *
 * The password is wrong,
 * an error message will be returned instead.
 *
 * @param {String} password password used in the decryption
 * @param {String} encrypted encrypted message
 * @returns decrypted message or error message.
 * @type String
 */
function decrypt_string(password, encrypted)
{
  if (encrypted.substr(0, 2) != '01') { return "unknown version"; }
  
  var result = '';
  
  var salt = parse_hex_array(
    encrypted.substr(2, 32)
  );
  var iv = parse_hex_array(
    encrypted.substr(34, 32)
  );
  var payload = parse_hex_array(encrypted.substr(66, encrypted.length - 66));

  var pw = hash_password(password, salt);
  var cbc = cbc_init(pw, iv);
  
  var decrypted = new Array();

  function decrypted_writer(block)
  {
    var l = decrypted.length;
    for (var i = 0; i < block.length; ++i) 
    {
      decrypted[l + i] = block[i]; 
    }
  }
  
  cbc_decrypt(cbc, payload, decrypted_writer);
  if (!cbc_finish_decrypt(cbc, decrypted_writer))
  {
    return "error in decryption";
  }

  var sha = sha_init();
  var hash_start = decrypted.length - 32;
  sha_append_with_count(sha, decrypted, hash_start);
  sha_finish(sha);
  var cmp;
  for (i = 0; i < 8; ++i)
  {
    cmp = (decrypted[hash_start + 4 * i] << 24) |
      (decrypted[hash_start + 4 * i + 1] << 16) |
      (decrypted[hash_start + 4 * i + 2] << 8) |
      decrypted[hash_start + 4 * i + 3];

    if (cmp != sha.hash[i])
    {
      return "error in decryption";
    }
  }

  for (i = 0; i < hash_start; i += 2)
  {
    result += String.fromCharCode((decrypted[i] << 8) | decrypted[i + 1]);
  }

  return result;
}
