function do_status(s) {
    document.ecdhtest.status.value = s;
}

var c = getSECCurveByName("secp128r1");
//secp128r1, secp160k1, secp160r1, secp192k1, secp192r1, secp224r1, secp256r1
var globQ = c.getCurve().getQ().toString();
var globA = c.getCurve().getA().toBigInteger().toString();
var globB = c.getCurve().getB().toBigInteger().toString();
var globGX = c.getG().getX().toBigInteger().toString();
var globGY = c.getG().getY().toBigInteger().toString();
var globN = c.getN().toString();

var rng;

if (globQ.length == 0) set_secp160r1();
rng = new SecureRandom();


function get_curve() {
    return new ECCurveFp(new BigInteger(globQ),
        new BigInteger(globA),
        new BigInteger(globB));
}

function get_G(curve) {
    return new ECPointFp(curve,
        curve.fromBigInteger(new BigInteger(globGX)),
        curve.fromBigInteger(new BigInteger(globGY)));
}

function pick_rand() {
    var n = new BigInteger(globN);
    var n1 = n.subtract(BigInteger.ONE);
    var r = new BigInteger(n.bitLength(), rng);
    return r.mod(n1).add(BigInteger.ONE);
}

function generate_priv() {
    var r = pick_rand();
    return r.toString();


}

function derive_pub(priv) {
    var before = new Date();
    var curve = get_curve();
    var G = get_G(curve);
    var a = new BigInteger(priv);
    var P = G.multiply(a);
    var after = new Date();

    var X = P.getX().toBigInteger().toString();
    var Y = P.getY().toBigInteger().toString();


    return { "X": X, "Y": Y }
}

function generate_secret(priv, pubX, pubY) {

    var before = new Date();
    var curve = get_curve();
    var P = new ECPointFp(curve,
        curve.fromBigInteger(new BigInteger(pubX)),
        curve.fromBigInteger(new BigInteger(pubY)));
    var a = new BigInteger(priv);
    var S = P.multiply(a);
    var after = new Date();
    secX = S.getX().toBigInteger().toString();
    secY = S.getY().toBigInteger().toString();

    return {
        "X": secX,
        "Y": secY
    };
}