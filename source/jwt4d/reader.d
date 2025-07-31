/**
 * Defines the `readJwt` function for reading a JWT from a string token, and
 * associated exceptions which may be thrown for invalid tokens.
 */
module jwt4d.reader;

import std.json;
import std.base64;
import std.datetime;
import secured;

import jwt4d.model;

/// Base type for any exception thrown while attempting to read a JWT.
class JwtException : Exception {
    this(string message) {
        super(message);
    }
}

/// Thrown if a token is malformed and cannot be read.
class JwtFormatException : JwtException {
    this(string message) {
        super(message);
    }
}

/// Thrown if a token cannot be verified.
class JwtVerificationException : JwtException {
    this() {
        super("JWT could not be verified.");
    }
}

/// Thrown if a token's "exp" claim is present and not in the future.
class JwtExpiredException : JwtException {
    this() {
        super("JWT has expired.");
    }
}

/// Thrown if a token's "nbf" claim is present and not in the past.
class JwtNotBeforeException : JwtException {
    this() {
        super("JWT is not valid yet (not before time).");
    }
}

/// Internal struct for passing around JWT data after parsing it.
private struct JwtComponents {
    JSONValue headerObj;
    JSONValue claimsObj;
    string payloadForSigning;
    string algorithm;
    ubyte[] signature;
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
    JwtComponents components = extractComponents(token);
    bool verified = hmac_verify_ex(
        components.signature,
        cast(ubyte[]) secret,
        cast(ubyte[]) components.payloadForSigning,
        HashAlgorithm.SHA2_256
    );
    if (!verified) {
        throw new JwtVerificationException();
    }

    JwtClaims claims = JwtClaims(components.claimsObj);
    verifyStandardTimeClaims(claims);
    return claims;
}

private JwtComponents extractComponents(string token) {
    import std.algorithm : splitter;
    import std.array : array;

    auto parts = token.splitter('.').array;
    if (parts.length != 3 || parts[0].length == 0 || parts[1].length == 0 || parts[2].length == 0) {
        throw new JwtFormatException("Invalid token format. Couldn't parse header, payload, and signature parts.");
    }

    JSONValue headerObj;
    JSONValue claimsObj;
    ubyte[] signature;
    try {
        headerObj = parseJSON(cast(string) Base64URLNoPadding.decode(parts[0]));
        claimsObj = parseJSON(cast(string) Base64URLNoPadding.decode(parts[1]));
        signature = Base64URLNoPadding.decode(parts[2]);
    } catch (JSONException e) {
        throw new JwtFormatException("Invalid JSON format.");
    } catch (Base64Exception e) {
        throw new JwtFormatException("Invalid Base64 encoding.");
    }
    
    verifyHeaderFormat(headerObj);
    string algorithm = headerObj.object["alg"].str;
    if (algorithm != "HS256") {
        throw new JwtFormatException("Unsupported algorithm: " ~ algorithm);
    }
    verifyClaimsFormat(claimsObj);

    return JwtComponents(headerObj, claimsObj, parts[0] ~ "." ~ parts[1], algorithm, signature);
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

// README example.
unittest {
    import jwt4d;
    import std.stdio;

    const string MY_SECRET = "this is a secret!";

    string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTM5MjYzMjAsImlhdCI6MTc1MzkyNDUyMCwiaXNzIjoibXkud2VicGFnZS5jb20iLCJyb2xlIjoiYWRtaW4iLCJzdWIiOiJ1c2VyMTIzIn0.n5X2giJ3S5T3wrW4C0qlZrShr2ZwPiWIu6FxUzQ3K9s";

    JwtClaims claims = readJwt(token, MY_SECRET);
    writeln(claims.toJson());
}
