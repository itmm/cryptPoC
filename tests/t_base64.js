'use strict';

var assert = require('assert');
var base64 = require('../base64.js');
var utf8 = require('../utf8.js');

describe('base64', function () {
    var encoder;
    
    beforeEach(function() {
        encoder = new base64.Encode();
    });

    function validate(reference, expected) {
        var encoded = encoder.add(reference).finish();
        if (expected) {
            assert.equal(encoded, expected);
        }
        var value = base64.decode(encoded);
        assert.deepEqual(reference, value);
        return encoded;
    }

    function validate_str(str, expected) {
        validate(utf8.toArray(str), expected);
    }

    it('empty', function() {
        validate([], "");
    });

    it('simple', function() {
        validate([0x00, 0xff, 0x80, 0x0f]);
    });

    it('wiki reference', function () {
        validate_str(
            "Polyfon zwitschernd aßen Mäxchens Vögel Rüben, Joghurt und Quark",
            "UG9seWZvbiB6d2l0c2NoZXJuZCBhw59lbiBNw6R4Y2hlbnMgVsO" +
            "2Z2VsIFLDvGJlbiwgSm9naHVydCB1bmQgUXVhcms=");
    });

    it('rfc ref single char', function() {
        validate_str("f", "Zg==");
    });

    it('rfc ref two chars', function() {
        validate_str("fo", "Zm8=");
    });

    it('rfc ref three chars', function() {
        validate_str("foo", "Zm9v");
    });

    it('rfc ref four chars', function() {
        validate_str("foob", "Zm9vYg==");
    });

    it('rfc ref five chars', function() {
        validate_str("fooba", "Zm9vYmE=");
    });

    it('rfc ref six chars', function() {
        validate_str("foobar", "Zm9vYmFy");
    });
});
