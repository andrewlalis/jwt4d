# JWT4D

A JSON Web Token library to generate, parse, sign, and verify JWTs.

Currently, only the "HS256" algorithm is supported.

## Example: Create a JWT
```d
import jwt4d;
import std.datetime; // To set expiration in duration.
import std.json; // To add a custom claim value.
import std.stdio;

const string MY_SECRET = "this is a secret!";

JwtClaims claims = JwtClaims()
    .issuer("my.webpage.com")
    .subject("user123")
    .issuedAtNow()
    .expiresIn(minutes(30))
    .customClaim("role", JSONValue("admin"));
string token = writeJwt(claims, MY_SECRET);
writeln(token);
```

## Example: Read a JWT
```d
import jwt4d;
import std.stdio;

const string MY_SECRET = "this is a secret!";

string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTM5MjYzMjAsImlhdCI6MTc1MzkyNDUyMCwiaXNzIjoibXkud2VicGFnZS5jb20iLCJyb2xlIjoiYWRtaW4iLCJzdWIiOiJ1c2VyMTIzIn0.n5X2giJ3S5T3wrW4C0qlZrShr2ZwPiWIu6FxUzQ3K9s";

JwtClaims claims = readJwt(token, MY_SECRET);
writeln(claims.toJson());
```
