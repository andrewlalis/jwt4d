module jwt4d.model;

import std.json;
import std.typecons : Nullable;
import std.base64;
import secured;

/**
 * Enum defining the names of registered JWT claims, as per RFC 7519.
 */
enum JwtClaim {
    Issuer = "iss",
    Subject = "sub",
    Audience = "aud",
    Expiration = "exp",
    NotBefore = "nbf",
    IssuedAt = "iat",
    JwtId = "jti"
}

/**
 * Data structure containing a JWT's claims.
 */
struct JwtClaims {
    private JSONValue obj = JSONValue.emptyObject;
    
    ref issuer(string issuer) {
        if (issuer is null) {
            this.obj.object.remove(JwtClaim.Issuer);
        } else {
            this.obj.object[JwtClaim.Issuer] = issuer;
        }
        return this;
    }

    string issuer() const {
        if (JwtClaim.IssuedAt !in this.obj.object) return null;
        return this.obj.object[JwtClaim.Issuer].str;
    }

    ref subject(string subject) {
        if (subject is null) {
            this.obj.object.remove(JwtClaim.Subject);
        } else {
            this.obj.object[JwtClaim.Subject] = subject;
        }
        return this;
    }

    string subject() const {
        if (JwtClaim.Subject !in this.obj.object) return null;
        return this.obj.object[JwtClaim.Subject].str;
    }

    ref audience(string audience) {
        if (audience is null) {
            this.obj.object.remove(JwtClaim.Audience);
        } else {
            this.obj.object[JwtClaim.Audience] = audience;
        }
        return this;
    }

    ref audience(string[] audiences) {
        if (audiences is null || audiences.length == 0) {
            this.obj.object.remove(JwtClaim.Audience);
        } else {
            this.obj.object[JwtClaim.Audience] = audiences;
        }
        return this;
    }

    string audience() const {
        if (
            JwtClaim.Audience !in this.obj.object ||
            this.obj.object[JwtClaim.Audience].type != JSONType.STRING
        ) return null;
        return this.obj.object[JwtClaim.Audience].str;
    }

    string[] audiences() const {
        import std.algorithm : map;
        import std.array : array;
        if (
            JwtClaim.Audience !in this.obj.object ||
            this.obj.object[JwtClaim.Audience].type != JSONType.ARRAY
        ) return [];
        return this.obj.object[JwtClaim.Audience].array.map!(v => v.str).array;
    }

    ref expiration(long expiration) {
        if (expiration < 0) {
            this.obj.object.remove(JwtClaim.Expiration);
        } else {
            this.obj.object[JwtClaim.Expiration] = expiration;
        }
        return this;
    }

    ref notBefore(long notBefore) {
        if (notBefore < 0) {
            this.obj.object.remove(JwtClaim.NotBefore);
        } else {
            this.obj.object[JwtClaim.NotBefore] = notBefore;
        }
        return this;
    }

    ref issuedAt(long issuedAt) {
        if (issuedAt < 0) {
            this.obj.object.remove(JwtClaim.IssuedAt);
        } else {
            this.obj.object[JwtClaim.IssuedAt] = issuedAt;
        }
        return this;
    }

    ref jwtId(string jwtId) {
        if (jwtId is null) {
            this.obj.object.remove(JwtClaim.JwtId);
        } else {
            this.obj.object[JwtClaim.JwtId] = jwtId;
        }
        return this;
    }

    string toJson() const {
        return this.obj.toJSON();
    }
}

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

JwtClaims readJwt(string token, string secret) {
    import std.algorithm : splitter;
    import std.array : array;

    auto parts = token.splitter('.').array;
    JSONValue headerObj = parseJSON(cast(string) Base64URLNoPadding.decode(parts[0]));
    // TODO: Verify header object and algorithm.
    JSONValue claimsObj = parseJSON(cast(string) Base64URLNoPadding.decode(parts[1]));
    // TODO: Verify claims object structure.
    ubyte[] signatureBytes = Base64URLNoPadding.decode(parts[2]);
    bool verified = hmac_verify_ex(
        signatureBytes,
        cast(ubyte[]) secret,
        cast(ubyte[]) (parts[0] ~ "." ~ parts[1]),
        HashAlgorithm.SHA2_256
    );
    if (!verified) {
        throw new Exception("Verification failed!");
        // TODO: Custom error handling.
    }
    return JwtClaims(claimsObj);
}

unittest {
    JwtClaims claims;
    claims.issuer = "example.com";
    string token = writeJwt(claims, "test");
    JwtClaims readClaims = readJwt(token, "test");
    import std.stdio;
    writeln(readClaims.toJson());
}
