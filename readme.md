# oidc-jwt-validator

Utility Library for validating JWTs from an OIDC Provider. 

Allows for automatic period updates of the JWKS used in the background.

Supports Multi threaded access.

## Usage

```

```


/*
The FHIR Bulk Data Access Implementation Guide from HL7 includes the following section:

The client SHOULD return a “Cache-Control” header in its JWKS response

The authorization server SHALL NOT cache a JWKS for longer than the client’s cache-control header indicates.
The authorization server SHOULD cache a client’s JWK Set according to the client’s cache-control header; it doesn’t need to retrieve it anew every time.


Situations:
 - No cache-control header not present
 Wild west I guess. Pick a value that makes sense
 - cache-control: no-cache
 Technically we're not supposed to be doing caching at all.
 But like cmon. That also makes no sense. Poll every 5 seconds maybe?
 - cache-control: max-age=X
 Respect the max-age


 Caching Optimizations

Store the parsed JWKset so it doesn't have to be de-serialized every time
Even if the cache is set to no-cache, We can validate the response is equal to the last to skip the de-serialization and cache updates

We can store the decoding key of each JWK so long as the jwks has not changed to prevent re-parsing them.
