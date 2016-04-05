var base64 = {};

(function () {
    var lookup = [];
    var inv_lookup = {};

    var mapping = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var l = mapping.length;
    var last_ch = ' ';
    for (var i = 0; i < l; ++i) {
        var c = mapping.charAt(i);
        lookup.push(c);
        inv_lookup[c] = i;
    }

    function Encode() {
        this.encoded = '';
        this.buffer = 0;
        this.buffer_used = 0;
    }

    Encode.prototype.add = function (bytes) {
        var l = bytes.length;
        for (var i = 0; i < l; ++i) {
            this.buffer = this.buffer << 8 | bytes[i];
            if (++this.buffer_used == 3) {
                this.encoded += lookup[this.buffer >>> 18];
                this.encoded += lookup[(this.buffer >>> 12) & 0x3f];
                this.encoded += lookup[(this.buffer >>> 6) & 0x3f];
                this.encoded += lookup[this.buffer & 0x3f];
                this.buffer = 0;
                this.buffer_used = 0;
            }
        }
        return this;
    };
    Encode.prototype.finish = function () {
        var suffix = '';
        while (this.buffer_used != 0) {
            this.add([0]);
            suffix += '=';
        }
        for (var i = 0; i < 3 && this.encoded.length && this.encoded.charAt(this.encoded.length - 1) == 'A'; ++i) {
            this.encoded = this.encoded.substr(0, this.encoded.length - 1);
        }
        return this.encoded + suffix;
    };

    function decode(encoded) {
        var surplus_bytes = 0;
        var l = encoded.length;
        while (l && encoded.charAt(l - 1) == '=') {
            ++surplus_bytes;
            --l;
        }

        var result = [];
        for (var i = 0; i < l; i += 4) {
            var c = 0;
            for (var j = 0; j < 4; ++j) {
                var d = inv_lookup[encoded.charAt(i + j)];
                c = c << 6 | d;
            }
            result.push(c >>> 16, (c >>> 8) & 0xff, c & 0xff);
        }
        if (surplus_bytes) {
            return result.slice(0, -surplus_bytes);
        } else {
            return result;
        }
    }

    base64.Encode = Encode;
    base64.decode = decode;

    exports.Encode = Encode;
    exports.decode = decode;
})();
