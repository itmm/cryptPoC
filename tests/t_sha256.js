'use strict';

var assert = require('assert');
var crypt = require('../microcrypt/microcrypt.js');

describe('sha-256', function () {
    var sha;
    beforeEach(function() {
        sha = crypt.sha_init();
    });

    function validate(expected) {
        for (var i = 0; i < expected.length; ++i) { expected[i] = expected[i] | 0; }
        crypt.sha_finish(sha);
        assert.deepEqual(expected, sha.hash);
    }

    it('empty', function() {
        validate([
            0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924,
            0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855
        ]);
    });
    it('abc', function() {
        crypt.sha_append(sha, [0x61, 0x62, 0x63]);
        validate([
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
            0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad
        ]);
    });
    it('one million chars', function() {
        var block = [0x61, 0x61, 0x61, 0x61, 0x61,  0x61, 0x61, 0x61, 0x61, 0x61];
        for (var i = 0; i < 100000; ++i) { crypt.sha_append(sha, block); }
        validate([
            0xcdc76e5c, 0x9914fb92, 0x81a1c7e2, 0x84d73e67,
            0xf1809a48, 0xa497200e, 0x046d39cc, 0xc7112cd0
        ]);
    });
 });
