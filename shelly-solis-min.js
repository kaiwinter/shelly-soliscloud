/// <reference path="../../shelly-script.d.ts" />

function callURL(key, date, contentMd5, sign) {
    Shelly.call("HTTP.Request", {
      method: "POST",
      url: "https://www.soliscloud.com:13333/v1/api/inverterList",
      headers: {"Content-type": "application/json;charset=UTF-8",
                "Authorization": "API " + key + ":" + sign,
                "Content-MD5": contentMd5,
                "Date": date
                },
      body: "{}",
      content_type: "application/json;charset=UTF-8"
      }, function (response, error_code, error_message) {
        if (error_code === 0 && response.code === 200) {
          // print("Success Response: " + JSON.stringify(response));
          let result = JSON.parse(response.body);
          let psum = result.data.page.records[0].psum;
          if (psum > 3) { // Einspeisung größer als 3 kW?
            print("psum: " + psum + " > 3");
            // Shelly anschalten
            Shelly.call("Switch.Set", { id: 0, on: true });
          } else {
            print("psum: " + psum + " < 3");
            // Shelly ausschalten
            Shelly.call("Switch.Set", { id: 0, on: false });
          }
        } else {
          print("Fehler beim Abrufen der URL: " + error_message);
          if (response != undefined && response.code != 200) {
            print("HTTP Code: " + response.code);
            print("Response: " + JSON.stringify(response));
          }
        }
        print("--- Ende -----------------------");
    });
}

// ---- HMAC SHA1 ------------------------------------------------
// https://gist.github.com/Seldaek/1730205

var Crypto = {};

Crypto.sha1_hmac = function (msg, key) {
    //"use strict";
    var oKeyPad, iKeyPad, iPadRes, bytes, i, len;
    if (key.length > 64) {
        // keys longer than blocksize are shortened
        key = Crypto.sha1(key, true);
    }

    bytes = [];
    len = key.length;
    for (i = 0; i < 64; ++i) {
        bytes[i] = len > i ? key.charCodeAt(i) : 0x00;
    }

    oKeyPad = "";
    iKeyPad = "";

    for (i = 0; i < 64; ++i) {
        oKeyPad += String.fromCharCode(bytes[i] ^ 0x5C);
        iKeyPad += String.fromCharCode(bytes[i] ^ 0x36);
    }

    iPadRes = Crypto.sha1(iKeyPad + msg, true);

    return Crypto.sha1(oKeyPad + iPadRes);
};

Crypto.sha1 = function (msg, raw) {
    function rotate_left(n,s) {
        var t4 = ( n<<s ) | (n>>>(32-s));
        return t4;
    }

    function cvt_hex(val, raw) {
        var str="";
        var i;
        var v;

        for( i=7; i>=0; i-- ) {
            v = (val>>>(i*4))&0x0f;
            str += raw ? String.fromCharCode(v) : v.toString(16);
        }
        return str;
    }

    var blockstart;
    var i, j;
    var W = new Array(80);
    var H0 = 0x67452301;
    var H1 = 0xEFCDAB89;
    var H2 = 0x98BADCFE;
    var H3 = 0x10325476;
    var H4 = 0xC3D2E1F0;
    var A, B, C, D, E;
    var result, rawResult;

    var msg_len = msg.length;

    var word_array = [];
    for( i=0; i<msg_len-3; i+=4 ) {
        j = msg.charCodeAt(i)<<24 | msg.charCodeAt(i+1)<<16 |
        msg.charCodeAt(i+2)<<8 | msg.charCodeAt(i+3);
        word_array.push( j );
    }

    switch( msg_len % 4 ) {
        case 0:
            i = 0x080000000;
        break;
        case 1:
            i = msg.charCodeAt(msg_len-1)<<24 | 0x0800000;
        break;

        case 2:
            i = msg.charCodeAt(msg_len-2)<<24 | msg.charCodeAt(msg_len-1)<<16 | 0x08000;
        break;

        case 3:
            i = msg.charCodeAt(msg_len-3)<<24 | msg.charCodeAt(msg_len-2)<<16 | msg.charCodeAt(msg_len-1)<<8    | 0x80;
        break;
    }

    word_array.push( i );

    while( (word_array.length % 16) != 14 ) word_array.push( 0 );

    word_array.push( msg_len>>>29 );
    word_array.push( (msg_len<<3)&0x0ffffffff );

    for ( blockstart=0; blockstart<word_array.length; blockstart+=16 ) {
        for( i=0; i<16; i++ ) W[i] = word_array[blockstart+i];
        for( i=16; i<=79; i++ ) W[i] = rotate_left(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);

        A = H0;
        B = H1;
        C = H2;
        D = H3;
        E = H4;

        for( i= 0; i<=19; i++ ) {
            temp = (rotate_left(A,5) + ((B&C) | (~B&D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotate_left(B,30);
            B = A;
            A = temp;
        }

        for( i=20; i<=39; i++ ) {
            temp = (rotate_left(A,5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotate_left(B,30);
            B = A;
            A = temp;
        }

        for( i=40; i<=59; i++ ) {
            temp = (rotate_left(A,5) + ((B&C) | (B&D) | (C&D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotate_left(B,30);
            B = A;
            A = temp;
        }

        for( i=60; i<=79; i++ ) {
            temp = (rotate_left(A,5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotate_left(B,30);
            B = A;
            A = temp;
        }

        H0 = (H0 + A) & 0x0ffffffff;
        H1 = (H1 + B) & 0x0ffffffff;
        H2 = (H2 + C) & 0x0ffffffff;
        H3 = (H3 + D) & 0x0ffffffff;
        H4 = (H4 + E) & 0x0ffffffff;
    }

    result = (cvt_hex(H0) + cvt_hex(H1) + cvt_hex(H2) + cvt_hex(H3) + cvt_hex(H4)).toLowerCase();

    if (!raw) {
        return result;
    }

    rawResult = "";
    while (result.length) {
        rawResult += String.fromCharCode(parseInt(result.substr(0, 2), 16));
        result = result.substr(2);
    }
    return rawResult;
};

// https://stackoverflow.com/a/3745677
function hex2a(hexx) {
    var hex = hexx.toString();//force conversion
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

function run() {
  print("--- Starte -----------------------");
  
  let path = "/v1/api/inverterList";
  let contentMd5 = "mZFLkyvTelC5g8XnyQrpOw=="; // Hardcoded, da immer nur ein leerer Body enthalten ist
  let date = new Date().toUTCString();
  let param = "POST" + "\n" + contentMd5 + "\n" + "application/json" + "\n" + date + "\n" + path;
  
  // print("param: " + param);
  
  let key = "TODO: Bei Solis beantragen";
  let keySecret = "TODO: Bei Solis beantragen";
  let sha1hmacBase16 = Crypto.sha1_hmac(param, keySecret);
  let hex2Mac = hex2a(sha1hmacBase16);
  let sign = btoa(hex2Mac);
  
  try {
    callURL(key, date, contentMd5, sign);
  } catch (error) {
    console.error(error);
  }
  // console.log("sign: " + sign);
}

run();
Timer.set(5 * 60 * 1000, true, run);