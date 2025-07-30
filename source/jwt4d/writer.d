module jwt4d.writer;

import std.json;
import std.base64;
import secured;

import jwt4d.model;

/**
 * Writes the given claims to a JWT, signed with the given secret.
 * Params:
 *   claims = The claims to encode.
 *   secret = The secret to use when signing the JWT.
 * Returns: The token.
 */
string writeJwt(in JwtClaims claims, string secret) {
    JSONValue headerObj = JSONValue.emptyObject;
    headerObj.object["typ"] = "JWT";
    headerObj.object["alg"] = "HS256";
    string headerBase64 = Base64URLNoPadding.encode(cast(ubyte[]) headerObj.toJSON());

    string claimsBase64 = Base64URLNoPadding.encode(cast(ubyte[]) claims.toJson());

    string prefix = headerBase64 ~ "." ~ claimsBase64;

    ubyte[] signatureBytes = hmac_ex(
        cast(ubyte[]) secret,
        cast(ubyte[]) (prefix),
        HashAlgorithm.SHA2_256
    );
    string signatureBase64 = Base64URLNoPadding.encode(signatureBytes);

    return prefix ~ "." ~ signatureBase64;
}

unittest {
    JwtClaims claims;
    claims.issuer = "example.com";
    claims.subject = "user123";
    claims.expiration = 123;

    string token = writeJwt(claims, "test");
    import std.stdio;
    writeln(token);
}