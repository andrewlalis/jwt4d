module jwt4d.model;

import std.json;
import std.base64;

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

    long expiration() const {
        if (JwtClaim.Expiration !in this.obj.object) return -1;
        return this.obj.object[JwtClaim.Expiration].integer;
    }

    ref notBefore(long notBefore) {
        if (notBefore < 0) {
            this.obj.object.remove(JwtClaim.NotBefore);
        } else {
            this.obj.object[JwtClaim.NotBefore] = notBefore;
        }
        return this;
    }

    long notBefore() const {
        if (JwtClaim.NotBefore !in this.obj.object) return -1;
        return this.obj.object[JwtClaim.NotBefore].integer;
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
