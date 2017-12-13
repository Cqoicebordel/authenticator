/*
 *
 * USED FUNCTIONS
 * 
 **/

function hexToDec(number) {
  // Return error if number is not hexadecimal or contains more than ten characters (10 digits)
  if (!/^[0-9A-Fa-f]{1,10}$/.test(number)) return '#NUM!';

  // Convert hexadecimal number to decimal
  var decimal = parseInt(number, 16);

  // Return decimal number
  return (decimal >= 549755813888) ? decimal - 1099511627776 : decimal;
}

var getEpochSeconds = function() {
  return Math.floor(new Date().getTime() / 1000.0);
}

function leftpad (str, len, pad) {
	if (len + 1 >= str.length) {
		str = Array(len + 1 - str.length).join(pad) + str;
	}
	return str;
}

function dec2hex (s) {
	return (s < 15.5 ? '0' : '') + Math.round(s).toString(16);
}

function base32tohex (base32) {
	if (!base32) {
		return;
	}
	var base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	var bits = "";
	var hex = "";
	var i;
	for (i = 0; i < base32.length; i++) {
		var val = base32chars.indexOf(base32.charAt(i).toUpperCase());
		bits += leftpad(val.toString(2), 5, '0');
	}

	for (i = 0; i + 4 <= bits.length; i += 4) {
		var chunk = bits.substr(i, 4);
		hex = hex + parseInt(chunk, 2).toString(16);
	}
	return hex;
}

function TOTP(secretZBase32) {
  var stepSeconds = 30;
  this.secretZBase32 = secretZBase32.toUpperCase();

  this.getToken = function() {
	var key = base32tohex(this.secretZBase32);
	if (key.length % 2 !== 0) {
      if(key.endsWith('0')) {
        key = key.slice(0, -1);
      }else{
		key = '0' + key;
      }
    }
	var epoch = Math.floor(new Date().getTime() / 1000.0);
	var time = leftpad(dec2hex(Math.floor(epoch / 30)), 16, '0');
	/** global: jsSHA */
	var hmacObj = new jsSHA(time, 'HEX');
	var hmac = hmacObj.getHMAC(key, "HEX", 'SHA-1', 'HEX');
	var offset = hexToDec(hmac.substring(hmac.length - 1));
	var otp = (hexToDec(hmac.substr(offset * 2, 8)) & hexToDec('7fffffff')) + '';
	otp = (otp).substr(otp.length - 6, 6);
	return otp;
  }

  this.getRemainingSeconds = function() {
    return stepSeconds - getEpochSeconds() % stepSeconds;
  }
}

/*
 A JavaScript implementation of the SHA family of hashes, as
 defined in FIPS PUB 180-4 and FIPS PUB 202, as well as the corresponding
 HMAC implementation as defined in FIPS PUB 198a
 Copyright Brian Turek 2008-2017
 Distributed under the BSD License
 See http://caligatio.github.com/jsSHA/ for more information
 Several functions taken from Paul Johnston
*/
'use strict';(function(U){function z(a,b,c){var e=0,f=[0],k="",h=null,k=c||"UTF8";if("UTF8"!==k&&"UTF16BE"!==k&&"UTF16LE"!==k)throw"encoding must be UTF8, UTF16BE, or UTF16LE";if("HEX"===b){if(0!==a.length%2)throw"srcString of HEX type must be in byte increments";h=D(a);e=h.binLen;f=h.value}else if("TEXT"===b||"ASCII"===b)h=L(a,k),e=h.binLen,f=h.value;else if("B64"===b)h=M(a),e=h.binLen,f=h.value;else if("BYTES"===b)h=N(a),e=h.binLen,f=h.value;else throw"inputFormat must be HEX, TEXT, ASCII, B64, or BYTES";
this.getHash=function(a,b,c,k){var h=null,d=f.slice(),n=e,m;3===arguments.length?"number"!==typeof c&&(k=c,c=1):2===arguments.length&&(c=1);if(c!==parseInt(c,10)||1>c)throw"numRounds must a integer >= 1";switch(b){case "HEX":h=O;break;case "B64":h=P;break;case "BYTES":h=Q;break;default:throw"format must be HEX, B64, or BYTES";}if("SHA-1"===a)for(m=0;m<c;m+=1)d=A(d,n),n=160;else if("SHA-224"===a)for(m=0;m<c;m+=1)d=w(d,n,a),n=224;else if("SHA-256"===a)for(m=0;m<c;m+=1)d=w(d,n,a),n=256;else if("SHA-384"===
a)for(m=0;m<c;m+=1)d=w(d,n,a),n=384;else if("SHA-512"===a)for(m=0;m<c;m+=1)d=w(d,n,a),n=512;else throw"Chosen SHA variant is not supported";return h(d,R(k))};this.getHMAC=function(a,b,c,h,q){var d,n,m,t,r=[],u=[];d=null;switch(h){case "HEX":h=O;break;case "B64":h=P;break;case "BYTES":h=Q;break;default:throw"outputFormat must be HEX, B64, or BYTES";}if("SHA-1"===c)n=64,t=160;else if("SHA-224"===c)n=64,t=224;else if("SHA-256"===c)n=64,t=256;else if("SHA-384"===c)n=128,t=384;else if("SHA-512"===c)n=
128,t=512;else throw"Chosen SHA variant is not supported";if("HEX"===b)d=D(a),m=d.binLen,d=d.value;else if("TEXT"===b||"ASCII"===b)d=L(a,k),m=d.binLen,d=d.value;else if("B64"===b)d=M(a),m=d.binLen,d=d.value;else if("BYTES"===b)d=N(a),m=d.binLen,d=d.value;else throw"inputFormat must be HEX, TEXT, ASCII, B64, or BYTES";a=8*n;b=n/4-1;if(n<m/8){for(d="SHA-1"===c?A(d,m):w(d,m,c);d.length<=b;)d.push(0);d[b]&=4294967040}else if(n>m/8){for(;d.length<=b;)d.push(0);d[b]&=4294967040}for(n=0;n<=b;n+=1)r[n]=d[n]^
909522486,u[n]=d[n]^1549556828;c="SHA-1"===c?A(u.concat(A(r.concat(f),a+e)),a+t):w(u.concat(w(r.concat(f),a+e,c)),a+t,c);return h(c,R(q))}}function q(a,b){this.a=a;this.b=b}function L(a,b){var c=[],e,f=[],k=0,h,p,q;if("UTF8"===b)for(h=0;h<a.length;h+=1)for(e=a.charCodeAt(h),f=[],128>e?f.push(e):2048>e?(f.push(192|e>>>6),f.push(128|e&63)):55296>e||57344<=e?f.push(224|e>>>12,128|e>>>6&63,128|e&63):(h+=1,e=65536+((e&1023)<<10|a.charCodeAt(h)&1023),f.push(240|e>>>18,128|e>>>12&63,128|e>>>6&63,128|e&63)),
p=0;p<f.length;p+=1){for(q=k>>>2;c.length<=q;)c.push(0);c[q]|=f[p]<<24-k%4*8;k+=1}else if("UTF16BE"===b||"UTF16LE"===b)for(h=0;h<a.length;h+=1){e=a.charCodeAt(h);"UTF16LE"===b&&(p=e&255,e=p<<8|e>>8);for(q=k>>>2;c.length<=q;)c.push(0);c[q]|=e<<16-k%4*8;k+=2}return{value:c,binLen:8*k}}function D(a){var b=[],c=a.length,e,f,k;if(0!==c%2)throw"String of HEX type must be in byte increments";for(e=0;e<c;e+=2){f=parseInt(a.substr(e,2),16);if(isNaN(f))throw"String of HEX type contains invalid characters";
for(k=e>>>3;b.length<=k;)b.push(0);b[e>>>3]|=f<<24-e%8*4}return{value:b,binLen:4*c}}function N(a){var b=[],c,e,f;for(e=0;e<a.length;e+=1)c=a.charCodeAt(e),f=e>>>2,b.length<=f&&b.push(0),b[f]|=c<<24-e%4*8;return{value:b,binLen:8*a.length}}function M(a){var b=[],c=0,e,f,k,h,p;if(-1===a.search(/^[a-zA-Z0-9=+\/]+$/))throw"Invalid character in base-64 string";f=a.indexOf("=");a=a.replace(/\=/g,"");if(-1!==f&&f<a.length)throw"Invalid '=' found in base-64 string";for(f=0;f<a.length;f+=4){p=a.substr(f,4);
for(k=h=0;k<p.length;k+=1)e="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(p[k]),h|=e<<18-6*k;for(k=0;k<p.length-1;k+=1){for(e=c>>>2;b.length<=e;)b.push(0);b[e]|=(h>>>16-8*k&255)<<24-c%4*8;c+=1}}return{value:b,binLen:8*c}}function O(a,b){var c="",e=4*a.length,f,k;for(f=0;f<e;f+=1)k=a[f>>>2]>>>8*(3-f%4),c+="0123456789abcdef".charAt(k>>>4&15)+"0123456789abcdef".charAt(k&15);return b.outputUpper?c.toUpperCase():c}function P(a,b){var c="",e=4*a.length,f,k,h;for(f=0;f<e;f+=
3)for(h=f+1>>>2,k=a.length<=h?0:a[h],h=f+2>>>2,h=a.length<=h?0:a[h],h=(a[f>>>2]>>>8*(3-f%4)&255)<<16|(k>>>8*(3-(f+1)%4)&255)<<8|h>>>8*(3-(f+2)%4)&255,k=0;4>k;k+=1)c=8*f+6*k<=32*a.length?c+"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(h>>>6*(3-k)&63):c+b.b64Pad;return c}function Q(a){var b="",c=4*a.length,e,f;for(e=0;e<c;e+=1)f=a[e>>>2]>>>8*(3-e%4)&255,b+=String.fromCharCode(f);return b}function R(a){var b={outputUpper:!1,b64Pad:"="};try{a.hasOwnProperty("outputUpper")&&
(b.outputUpper=a.outputUpper),a.hasOwnProperty("b64Pad")&&(b.b64Pad=a.b64Pad)}catch(c){}if("boolean"!==typeof b.outputUpper)throw"Invalid outputUpper formatting option";if("string"!==typeof b.b64Pad)throw"Invalid b64Pad formatting option";return b}function x(a,b){return a<<b|a>>>32-b}function r(a,b){return a>>>b|a<<32-b}function u(a,b){var c=null,c=new q(a.a,a.b);return c=32>=b?new q(c.a>>>b|c.b<<32-b&4294967295,c.b>>>b|c.a<<32-b&4294967295):new q(c.b>>>b-32|c.a<<64-b&4294967295,c.a>>>b-32|c.b<<64-
b&4294967295)}function S(a,b){var c=null;return c=32>=b?new q(a.a>>>b,a.b>>>b|a.a<<32-b&4294967295):new q(0,a.a>>>b-32)}function V(a,b,c){return a&b^~a&c}function W(a,b,c){return new q(a.a&b.a^~a.a&c.a,a.b&b.b^~a.b&c.b)}function T(a,b,c){return a&b^a&c^b&c}function X(a,b,c){return new q(a.a&b.a^a.a&c.a^b.a&c.a,a.b&b.b^a.b&c.b^b.b&c.b)}function Y(a){return r(a,2)^r(a,13)^r(a,22)}function Z(a){var b=u(a,28),c=u(a,34);a=u(a,39);return new q(b.a^c.a^a.a,b.b^c.b^a.b)}function $(a){return r(a,6)^r(a,11)^
r(a,25)}function aa(a){var b=u(a,14),c=u(a,18);a=u(a,41);return new q(b.a^c.a^a.a,b.b^c.b^a.b)}function ba(a){return r(a,7)^r(a,18)^a>>>3}function ca(a){var b=u(a,1),c=u(a,8);a=S(a,7);return new q(b.a^c.a^a.a,b.b^c.b^a.b)}function da(a){return r(a,17)^r(a,19)^a>>>10}function ea(a){var b=u(a,19),c=u(a,61);a=S(a,6);return new q(b.a^c.a^a.a,b.b^c.b^a.b)}function C(a,b){var c=(a&65535)+(b&65535);return((a>>>16)+(b>>>16)+(c>>>16)&65535)<<16|c&65535}function fa(a,b,c,e){var f=(a&65535)+(b&65535)+(c&65535)+
(e&65535);return((a>>>16)+(b>>>16)+(c>>>16)+(e>>>16)+(f>>>16)&65535)<<16|f&65535}function E(a,b,c,e,f){var k=(a&65535)+(b&65535)+(c&65535)+(e&65535)+(f&65535);return((a>>>16)+(b>>>16)+(c>>>16)+(e>>>16)+(f>>>16)+(k>>>16)&65535)<<16|k&65535}function ga(a,b){var c,e,f;c=(a.b&65535)+(b.b&65535);e=(a.b>>>16)+(b.b>>>16)+(c>>>16);f=(e&65535)<<16|c&65535;c=(a.a&65535)+(b.a&65535)+(e>>>16);e=(a.a>>>16)+(b.a>>>16)+(c>>>16);return new q((e&65535)<<16|c&65535,f)}function ha(a,b,c,e){var f,k,h;f=(a.b&65535)+(b.b&
65535)+(c.b&65535)+(e.b&65535);k=(a.b>>>16)+(b.b>>>16)+(c.b>>>16)+(e.b>>>16)+(f>>>16);h=(k&65535)<<16|f&65535;f=(a.a&65535)+(b.a&65535)+(c.a&65535)+(e.a&65535)+(k>>>16);k=(a.a>>>16)+(b.a>>>16)+(c.a>>>16)+(e.a>>>16)+(f>>>16);return new q((k&65535)<<16|f&65535,h)}function ia(a,b,c,e,f){var k,h,p;k=(a.b&65535)+(b.b&65535)+(c.b&65535)+(e.b&65535)+(f.b&65535);h=(a.b>>>16)+(b.b>>>16)+(c.b>>>16)+(e.b>>>16)+(f.b>>>16)+(k>>>16);p=(h&65535)<<16|k&65535;k=(a.a&65535)+(b.a&65535)+(c.a&65535)+(e.a&65535)+(f.a&
65535)+(h>>>16);h=(a.a>>>16)+(b.a>>>16)+(c.a>>>16)+(e.a>>>16)+(f.a>>>16)+(k>>>16);return new q((h&65535)<<16|k&65535,p)}function A(a,b){var c=[],e,f,k,h,p,q,r,s,u,d=[1732584193,4023233417,2562383102,271733878,3285377520];for(e=(b+65>>>9<<4)+15;a.length<=e;)a.push(0);a[b>>>5]|=128<<24-b%32;a[e]=b;u=a.length;for(r=0;r<u;r+=16){e=d[0];f=d[1];k=d[2];h=d[3];p=d[4];for(s=0;80>s;s+=1)c[s]=16>s?a[s+r]:x(c[s-3]^c[s-8]^c[s-14]^c[s-16],1),q=20>s?E(x(e,5),f&k^~f&h,p,1518500249,c[s]):40>s?E(x(e,5),f^k^h,p,1859775393,
c[s]):60>s?E(x(e,5),T(f,k,h),p,2400959708,c[s]):E(x(e,5),f^k^h,p,3395469782,c[s]),p=h,h=k,k=x(f,30),f=e,e=q;d[0]=C(e,d[0]);d[1]=C(f,d[1]);d[2]=C(k,d[2]);d[3]=C(h,d[3]);d[4]=C(p,d[4])}return d}function w(a,b,c){var e,f,k,h,p,r,u,s,y,d,n,m,t,w,x,v,z,A,F,G,H,I,J,K,g,B=[],D,l=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,
1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];d=[3238371032,914150663,812702999,4144912697,4290775857,
1750603025,1694076839,3204075428];f=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225];if("SHA-224"===c||"SHA-256"===c)n=64,e=(b+65>>>9<<4)+15,w=16,x=1,g=Number,v=C,z=fa,A=E,F=ba,G=da,H=Y,I=$,K=T,J=V,d="SHA-224"===c?d:f;else if("SHA-384"===c||"SHA-512"===c)n=80,e=(b+128>>>10<<5)+31,w=32,x=2,g=q,v=ga,z=ha,A=ia,F=ca,G=ea,H=Z,I=aa,K=X,J=W,l=[new g(l[0],3609767458),new g(l[1],602891725),new g(l[2],3964484399),new g(l[3],2173295548),new g(l[4],4081628472),new g(l[5],
3053834265),new g(l[6],2937671579),new g(l[7],3664609560),new g(l[8],2734883394),new g(l[9],1164996542),new g(l[10],1323610764),new g(l[11],3590304994),new g(l[12],4068182383),new g(l[13],991336113),new g(l[14],633803317),new g(l[15],3479774868),new g(l[16],2666613458),new g(l[17],944711139),new g(l[18],2341262773),new g(l[19],2007800933),new g(l[20],1495990901),new g(l[21],1856431235),new g(l[22],3175218132),new g(l[23],2198950837),new g(l[24],3999719339),new g(l[25],766784016),new g(l[26],2566594879),
new g(l[27],3203337956),new g(l[28],1034457026),new g(l[29],2466948901),new g(l[30],3758326383),new g(l[31],168717936),new g(l[32],1188179964),new g(l[33],1546045734),new g(l[34],1522805485),new g(l[35],2643833823),new g(l[36],2343527390),new g(l[37],1014477480),new g(l[38],1206759142),new g(l[39],344077627),new g(l[40],1290863460),new g(l[41],3158454273),new g(l[42],3505952657),new g(l[43],106217008),new g(l[44],3606008344),new g(l[45],1432725776),new g(l[46],1467031594),new g(l[47],851169720),new g(l[48],
3100823752),new g(l[49],1363258195),new g(l[50],3750685593),new g(l[51],3785050280),new g(l[52],3318307427),new g(l[53],3812723403),new g(l[54],2003034995),new g(l[55],3602036899),new g(l[56],1575990012),new g(l[57],1125592928),new g(l[58],2716904306),new g(l[59],442776044),new g(l[60],593698344),new g(l[61],3733110249),new g(l[62],2999351573),new g(l[63],3815920427),new g(3391569614,3928383900),new g(3515267271,566280711),new g(3940187606,3454069534),new g(4118630271,4000239992),new g(116418474,
1914138554),new g(174292421,2731055270),new g(289380356,3203993006),new g(460393269,320620315),new g(685471733,587496836),new g(852142971,1086792851),new g(1017036298,365543100),new g(1126000580,2618297676),new g(1288033470,3409855158),new g(1501505948,4234509866),new g(1607167915,987167468),new g(1816402316,1246189591)],d="SHA-384"===c?[new g(3418070365,d[0]),new g(1654270250,d[1]),new g(2438529370,d[2]),new g(355462360,d[3]),new g(1731405415,d[4]),new g(41048885895,d[5]),new g(3675008525,d[6]),
new g(1203062813,d[7])]:[new g(f[0],4089235720),new g(f[1],2227873595),new g(f[2],4271175723),new g(f[3],1595750129),new g(f[4],2917565137),new g(f[5],725511199),new g(f[6],4215389547),new g(f[7],327033209)];else throw"Unexpected error in SHA-2 implementation";for(;a.length<=e;)a.push(0);a[b>>>5]|=128<<24-b%32;a[e]=b;D=a.length;for(m=0;m<D;m+=w){b=d[0];e=d[1];f=d[2];k=d[3];h=d[4];p=d[5];r=d[6];u=d[7];for(t=0;t<n;t+=1)16>t?(y=t*x+m,s=a.length<=y?0:a[y],y=a.length<=y+1?0:a[y+1],B[t]=new g(s,y)):B[t]=
z(G(B[t-2]),B[t-7],F(B[t-15]),B[t-16]),s=A(u,I(h),J(h,p,r),l[t],B[t]),y=v(H(b),K(b,e,f)),u=r,r=p,p=h,h=v(k,s),k=f,f=e,e=b,b=v(s,y);d[0]=v(b,d[0]);d[1]=v(e,d[1]);d[2]=v(f,d[2]);d[3]=v(k,d[3]);d[4]=v(h,d[4]);d[5]=v(p,d[5]);d[6]=v(r,d[6]);d[7]=v(u,d[7])}if("SHA-224"===c)a=[d[0],d[1],d[2],d[3],d[4],d[5],d[6]];else if("SHA-256"===c)a=d;else if("SHA-384"===c)a=[d[0].a,d[0].b,d[1].a,d[1].b,d[2].a,d[2].b,d[3].a,d[3].b,d[4].a,d[4].b,d[5].a,d[5].b];else if("SHA-512"===c)a=[d[0].a,d[0].b,d[1].a,d[1].b,d[2].a,
d[2].b,d[3].a,d[3].b,d[4].a,d[4].b,d[5].a,d[5].b,d[6].a,d[6].b,d[7].a,d[7].b];else throw"Unexpected error in SHA-2 implementation";return a}"function"===typeof define&&define.amd?define(function(){return z}):"undefined"!==typeof exports?"undefined"!==typeof module&&module.exports?module.exports=exports=z:exports=z:U.jsSHA=z})(this);



var DESTROYED_ERROR = 'Object is destroyed';

var Shape = function Shape(container, opts) {
    // Throw a better error if progress bars are not initialized with `new`
    // keyword
    if (!(this instanceof Shape)) {
        throw new Error('Constructor was called without new keyword');
    }

    // Prevent calling constructor without parameters so inheritance
    // works correctly. To understand, this is how Shape is inherited:
    //
    //   Line.prototype = new Shape();
    //
    // We just want to set the prototype for Line.
    if (arguments.length === 0) {
        return;
    }

    // Default parameters for progress bar creation
    this._opts = extend({
        color: '#555',
        strokeWidth: 1.0,
        trailColor: null,
        trailWidth: null,
        fill: null,
        text: {},
        svgStyle: {
            display: 'block',
            width: '100%'
        },
        warnings: false
    }, opts, true);  // Use recursive extend

    var svgView = this._createSvgView(this._opts);

    var element = container;

    if (!element) {
        throw new Error('Container does not exist: ' + container);
    }

    this._container = element;
    this._container.appendChild(svgView.svg);
    if (this._opts.warnings) {
        this._warnContainerAspectRatio(this._container);
    }

    // Expose public attributes before Path initialization
    this.svg = svgView.svg;
    this.path = svgView.path;
    this.trail = svgView.trail;
    this.text = null;

    var newOpts = extend({
        attachment: undefined,
        shape: this
    }, this._opts);
    this._progressPath = new Path(svgView.path, newOpts);

};

Shape.prototype.set = function set(progress) {
    if (this._progressPath === null) {
        throw new Error(DESTROYED_ERROR);
    }

    this._progressPath.set(progress);
};

Shape.prototype._createSvgView = function _createSvgView(opts) {
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    this._initializeSvg(svg, opts);

    var trailPath = null;
    // Each option listed in the if condition are 'triggers' for creating
    // the trail path

    var path = this._createPath(opts);
    svg.appendChild(path);

    return {
        svg: svg,
        path: path,
        trail: trailPath
    };
};

Shape.prototype._initializeSvg = function _initializeSvg(svg, opts) {
    svg.setAttribute('viewBox', '0 0 100 100');
};

Shape.prototype._createPath = function _createPath(opts) {
    var pathString = this._pathString(opts);
    return this._createPathElement(pathString, opts);
};

Shape.prototype._createPathElement = function _createPathElement(pathString, opts) {
    var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', pathString);
    path.setAttribute('stroke', opts.color);
    path.setAttribute('stroke-width', opts.strokeWidth);

    if (opts.fill) {
        path.setAttribute('fill', opts.fill);
    } else {
        path.setAttribute('fill-opacity', '0');
    }

    return path;
};


// Circle shaped progress bar

var Circle = function Circle(container, options) {
    // Use two arcs to form a circle
    // See this answer http://stackoverflow.com/a/10477334/1446092
    this._pathTemplate =
        'M 50,50 m 0,-{radius}' +
        ' a {radius},{radius} 0 1 1 0,{2radius}' +
        ' a {radius},{radius} 0 1 1 0,-{2radius}';

    this.containerAspectRatio = 1;

    Shape.apply(this, arguments);
};

Circle.prototype = new Shape();
Circle.prototype.constructor = Circle;

Circle.prototype._pathString = function _pathString(opts) {
    var widthOfWider = opts.strokeWidth;
    if (opts.trailWidth && opts.trailWidth > opts.strokeWidth) {
        widthOfWider = opts.trailWidth;
    }

    var r = 50 - widthOfWider / 2;

    return render(this._pathTemplate, {
        radius: r,
        '2radius': r * 2
    });
};


// Lower level API to animate any kind of svg path
var Path = function Path(path, opts) {
    // Throw a better error if not initialized with `new` keyword
    if (!(this instanceof Path)) {
        throw new Error('Constructor was called without new keyword');
    }

    var element = path;

    // Reveal .path as public attribute
    this.path = element;
    this._opts = opts;

    // Set up the starting positions
    var length = this.path.getTotalLength();
    this.path.style.strokeDasharray = length + ' ' + length;
    this.set(0);
};

Path.prototype.set = function set(progress) {
    this.path.style.strokeDashoffset = this._progressToOffset(progress);
};

Path.prototype._progressToOffset = function _progressToOffset(progress) {
    var length = this.path.getTotalLength();
    return length - progress * length;
};

// Utility functions

// Copy all attributes from source object to destination object.
// destination object is mutated.
function extend(destination, source, recursive) {
    destination = destination || {};
    source = source || {};
    recursive = recursive || false;

    for (var attrName in source) {
        if (source.hasOwnProperty(attrName)) {
            var destVal = destination[attrName];
            var sourceVal = source[attrName];
            destination[attrName] = sourceVal;
        }
    }

    return destination;
}

// Renders templates with given variables. Variables must be surrounded with
// braces without any spaces, e.g. {variable}
// All instances of variable placeholders will be replaced with given content
// Example:
// render('Hello, {message}!', {message: 'world'})
function render(template, vars) {
    var rendered = template;

    for (var key in vars) {
        if (vars.hasOwnProperty(key)) {
            var val = vars[key];
            var regExpString = '\\{' + key + '\\}';
            var regExp = new RegExp(regExpString, 'g');

            rendered = rendered.replace(regExp, val);
        }
    }

    return rendered;
}

function copyToClipboard(value) {
  // Create a temporary input
  var input = document.createElement("input");
  // Append it to body
  document.body.appendChild(input);

  // Set input value
  input.setAttribute("value", value);
  // Select input value
  input.select();
  // Copy input value
  document.execCommand("copy");

  // Remove input from body
  document.body.removeChild(input);
}

function showToast(value, timeout) {
  timeout = timeout || 2000;

  var toastElement = document.createElement("div");
  toastElement.classList.add('toast');
  toastElement.innerText = value;

  document.body.appendChild(toastElement);
  setTimeout(function() {
    document.body.removeChild(toastElement);
  }, timeout);
}

/*************************
 *                       *
 *    Principal logic    *
 *                       *
 *************************/


var calcs = document.getElementsByClassName('calculator');

// Create all the calculators for each line of settings
for(var i=1; i<settings.length; i++){
	var newCalc = document.createElement('div');
	newCalc.setAttribute("class", "calculator");
	newCalc.innerHTML = "<div class=\"account\"></div><div class=\"totp-token\"></div><div class=\"totp-token-remaining-seconds-circle\" ></div>";
	calcs[0].insertAdjacentElement("afterend", newCalc);
}

var accountElements = document.getElementsByClassName('account');

for(var i=0; i<accountElements.length; i++){
	accountElements[i].innerHTML = settings[i][1];
}

// Add the countdown circle to each
var circles = document.getElementsByClassName('totp-token-remaining-seconds-circle');
var totpRemainingSecondsCircle = [];
for(var i=0; i<circles.length; i++){
  totpRemainingSecondsCircle[i] = new Circle(circles[i], {
  strokeWidth: 50,
  title: "30s",
  duration: 1000,
  color: 'inherit', // null to support css styling
});
totpRemainingSecondsCircle[i].svg.style.transform = 'scale(-1, 1)';
}

// Add copy/paste possibility from clicking an element
['click', 'tap'].forEach(function(event) {
	var totpTokenElements = document.getElementsByClassName('totp-token');
	for(var i=0; i<totpTokenElements.length; i++){
		totpTokenElements[i].addEventListener(event, function() {
			copyToClipboard(this.innerText.replace(/\s/g, ''));
			showToast("Copié");
		}, false);
	}
});

// Add titles in SVGs for accessibility
var svgs = document.getElementsByTagName("svg");
for(var i=0; i<svgs.length; i++){
	var title = document.createElement('title');
	svgs[i].appendChild(title);
}

// Careful, index 0 is the title of the page. Start at 1.
var titles = document.getElementsByTagName("title");

setInterval(refresh_totp, 1000, settings);

function refresh_totp(settings) {
  var totpTokenElements = document.getElementsByClassName('totp-token');

  for(var i=0; i<totpTokenElements.length; i++){
    if (settings[i][0].startsWith("otpauth://")) {
      settings[i][0] = new URL(settings[i][0]).searchParams.get('secret');
    } else {
      settings[i][0] = settings[i][0].replace(/\s/g, '');
    }
    var totp = new TOTP(settings[i][0]);
    try {
      totpTokenElements[i].innerHTML = totp.getToken().replace(/(...)(?=.)/g, "$& ");
      if (totp.getRemainingSeconds() / 30.0 <= 0) {
        totpRemainingSecondsCircle[i].set(1.0);
		titles[i+1].innerText = "30s";
      } else {
        totpRemainingSecondsCircle[i].set(totp.getRemainingSeconds() / 30.0);
		titles[i+1].innerText = totp.getRemainingSeconds() + "s";
      }
    } catch (err) {
      console.log(err);
      totpTokenElements[i].innerHTML = "Invalid Secret!";
      totpRemainingSecondsCircle[i].set(0.0);
    }
  }
}

