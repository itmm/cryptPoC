var utf8 = {};

(function() {
    function toArray(str) {
        var result = [];
        var l = str.length;
        for (var i = 0; i < l; ++i) {
            var c = str.charCodeAt(i);
            if ((c & 0xfc00) == 0xd800) {
                ++i;
                if (i >= l) { return null; }
                var d = str.charCodeAt(i);
                if ((d & 0xfc00) != 0xdc00) { return null; }
                c = (((c & 0x3ff) << 10) | (d & 0x3ff)) + 0x10000;
            }
            if ((c & 0x7f) == c) {
                result.push(c & 0xff);
            } else if ((c & 0x3ff) == c) {
                result.push(
                    0xc0 | (c >>> 6),
                    0x80 | (c & 0x3f)
                );
            } else if ((c & 0x7fff) == c) {
                result.push(
                    0xe0 | (c >>> 12),
                    0x80 | ((c >>> 6) & 0x3f),
                    0x80 | (c & 0x3f)
                );
            } else if ((c & 0xfffff) == c) {
                result.push(
                    0xf0 | (c >>> 18),
                    0x80 | ((c >>> 12) & 0x3f),
                    0x80 | ((c >>> 6) & 0x3f),
                    0x80 | (c & 0x3f)
                );
            } else {
                return null;
            }
        }
        return result;
    }

    function addMultis(res, ary, i, cnt) {
        var e = i + cnt;
        if (e > ary.length) { return null; }
        for (var j = i; j < e; ++j) {
            var b = ary[j];
            if (b >> 6 != 0x02) { return null; }
            res = (res << 6) | (b & 0x3f);
        }
        return res;
    }

    function toString(ary) {
        var result = '';
        var l = ary.length;
        for (var i = 0; i < l; ++i) {
            var b = ary[i];
            var c = null;
            if ((b & 0x80) == 0) {
                c = b;
            } else if ((b & 0xc0) == 0x80) {
            } else if ((b & 0xe0) == 0xc0) {
                c = addMultis(b & 0x1f, ary, i + 1, 1);
                i += 1;
            } else if ((b & 0xf0) == 0xe0) {
                c = addMultis(b & 0x0f, ary, i + 1, 2);
                i += 2;
            } else if ((b & 0xf8) == 0xf0) {
                c = addMultis(b & 0x07, ary, i + 1, 3);
                i += 3;
            }
            
            if (! c) { return null; }
            if ((c & 0xffff) == c) {
                result += String.fromCharCode(c);
            } else {
                c = (c - 0x10000);
                result += String.fromCharCode(
                    0xd800 | (c >>> 10),
                    0xdc00 | (c & 0x03ff)
                );
            }
        }
        return result;
    }

    utf8.toArray = toArray;
    utf8.toString = toString;

    exports.toArray = toArray;
    exports.toString = toString;
})();