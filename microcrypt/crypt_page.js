function hash_password(password) {
    for (var j = 0; j < 100; ++j) {
        var sha = sha_init();
        sha_append(sha, password);
        sha_finish(sha);
        password = new Array(4 * sha.hash.length);
        for (var i = 0; i < sha.hash.length; ++i) {
            password[4 * i] = sha.hash[i] >>> 24;
            password[4 * i + 1] = (sha.hash[i] >>> 16) & 0xff;
            password[4 * i + 2] = (sha.hash[i] >>> 8) & 0xff;
            password[4 * i + 3] = sha.hash[i] & 0xff;
        }
    }
    return password;
}

function encrypt_string(password, plain) {
    var encoder = new base64.Encode();

    var pw = hash_password(utf8.toArray(password));

    function writer(bytes) { encoder.add(bytes); }

    var iv = random_array(16);
    writer(iv);
    var cbc = cbc_init(pw, iv);
    var p = utf8.toArray(plain);
    cbc_encrypt(cbc, p, writer);
    cbc_finish_encrypt(cbc, writer);

    return encoder.finish();
}

function decrypt_string(password, encrypted) {
    var bytes = base64.decode(encrypted);

    var iv = bytes.slice(0, 16);
    var pw = hash_password(utf8.toArray(password));
    var cbc = cbc_init(pw, iv);

    var decrypted = [];

    function writer(block) {
        decrypted = decrypted.concat(block);
    }

    cbc_decrypt(cbc, bytes.slice(16), writer);
    if (!cbc_finish_decrypt(cbc, writer)) {
        return "error in decryption";
    }

    return utf8.toString(decrypted);
}
