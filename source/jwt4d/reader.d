module jwt4d.reader;

import std.json;
import std.base64;
import std.datetime;
import secured;

import jwt4d.model;

class JwtException : Exception {
    this(string message) {
        super(message);
    }
}

class JwtFormatException : JwtException {
    this(string message) {
        super(message);
    }
}

class JwtVerificationException : JwtException {
    this() {
        super("JWT could not be verified.");
    }
}

class JwtExpiredException : JwtException {
    this() {
        super("JWT has expired.");
    }
}

class JwtNotBeforeException : JwtException {
    this() {
        super("JWT is not valid yet (not before time).");
    }
}

/**
 * Reads a token and parses the claims. If the token is valid and its signature
 * is verified, this method will also evaluate the "exp" (expiration) and "nbf"
 * (not before) claims, and throw an exception if the token is not valid.
 * Params:
 *   token = The token to read.
 *   secret = The secret used to sign the token, to verify it.
 * Returns: The set of claims.
 */
JwtClaims readJwt(string token, string secret) {
    import std.algorithm : splitter;
    import std.array : array;

    auto parts = token.splitter('.').array;
    JSONValue headerObj = parseJSON(cast(string) Base64URLNoPadding.decode(parts[0]));
    verifyHeaderFormat(headerObj);
    string algorithm = headerObj.object["alg"].str;
    if (algorithm != "HS256") {
        throw new JwtFormatException("Unsupported algorithm: " ~ algorithm);
    }
    
    JSONValue claimsObj = parseJSON(cast(string) Base64URLNoPadding.decode(parts[1]));
    verifyClaimsFormat(claimsObj);

    ubyte[] signatureBytes = Base64URLNoPadding.decode(parts[2]);
    bool verified = hmac_verify_ex(
        signatureBytes,
        cast(ubyte[]) secret,
        cast(ubyte[]) (parts[0] ~ "." ~ parts[1]),
        HashAlgorithm.SHA2_256
    );
    if (!verified) {
        throw new JwtVerificationException();
    }

    JwtClaims claims = JwtClaims(claimsObj);
    verifyStandardTimeClaims(claims);
    return claims;
}

private void verifyHeaderFormat(in JSONValue j) {
    if (j.type != JSONType.OBJECT) {
        throw new JwtFormatException("Header must be a JSON object.");
    }
    if ("typ" !in j.object || j.object["typ"].type != JSONType.STRING) {
        throw new JwtFormatException("Header is missing the required 'typ' string property.");
    }
    if (j.object["typ"].str != "JWT") {
        throw new JwtFormatException("Header 'typ' property must be 'JWT'.");
    }
    if ("alg" !in j.object || j.object["alg"].type != JSONType.STRING) {
        throw new JwtFormatException("Header is missing the required 'alg' string property.");
    }
}

private void verifyClaimsFormat(in JSONValue j) {
    if (j.type != JSONType.OBJECT) {
        throw new JwtFormatException("Claims must be a JSON object.");
    }
}

private void verifyStandardTimeClaims(in JwtClaims claims) {
    long currentTimestamp = Clock.currTime(UTC()).toUnixTime!long;
    if (claims.expiration > 0 && claims.expiration <= currentTimestamp) {
        throw new JwtExpiredException();
    }
    if (claims.notBefore > 0 && claims.notBefore > currentTimestamp) {
        throw new JwtNotBeforeException();
    }
}

unittest {
    import jwt4d.writer;
    JwtClaims claims;
    claims.issuer = "example.com";
    string token = writeJwt(claims, "test");
    JwtClaims readClaims = readJwt(token, "test");
    import std.stdio;
    writeln(readClaims.toJson());
}