'use strict';

var assert = require('assert');
var utf8 = require('../utf8.js');

describe('utf8', function () {
    function validate(u16, u8) {
        var encoded = utf8.toArray(u16);
        assert.deepEqual(encoded, u8);
        var decoded = utf8.toString(u8);
        assert.equal(decoded, u16);
    }

    it('empty', function() {
        validate("", []);
    });

    it('multiple', function() {
        validate("abc", [0x61, 0x62, 0x63]);
    });

    it('one byte', function() {
        validate("y", [0x79]);
    });
    it('two byte sequence (umlaut)', function() {
        validate("ä", [0xc3, 0xa4]);
    });
    it('two byte sequence (trademark)', function() {
        validate("®", [0xc2, 0xae]);
    });
    it('three byte sequence (euro)', function() {
        validate("€", [0xe2, 0x82, 0xac]);
    });
    it('four byte sequence (violin key)', function() {
        validate("𝄞", [0xf0, 0x9d, 0x84, 0x9e]);
    });
    it('four byte sequence (han character)', function() {
        validate("𤽜", [0xf0, 0xa4, 0xbd, 0x9c]);
    });
});
