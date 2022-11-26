# oidc-jwt-validator

Utility Library for validating JWTs from an OIDC Provider. 

Allows for automatic period updates of the JWKS used in the background.

Supports Multi threaded access.

## Usage

```

```


## Cache Strategy



- Cache should be able to have multiple concurrent readers accross threads.

Utilize an [Arc](https://doc.rust-lang.org/std/sync/struct.Arc.html) + [RWLock](https://docs.rs/tokio/latest/tokio/sync/struct.RwLock.html). 

This allows for as many simultanious readers, with only 1 writer at a single time.

Writing to the cache implies no readers are allowed, which prevents any validation from occouring while we're writing.

Only use a write lock when absolutely critical, and validate that it's necessary with a read lock prior to attempting any writes. 


- A JWT with an unknown KID should attempt a cache invalidation.




- Cache Should respect the Cache Control header. 

[RFC7517](https://www.rfc-editor.org/rfc/rfc7517) doesn't provide any specific guidance on caching of JWKs. 


There should be two options to specify how we cache the URL.
`Automatic` - Respect the cache-control header.
`Manual` - Poll at the specified interval. 




If `Automatic` was chosen


Special Cases with respecting the [cache-control header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control).

- The cache-control header can change over time, we should be able to change the caching strategy dynamically after every request. 


- `must-revalidate`: [rfc7234 - section-5.2.2.1](https://datatracker.ietf.org/doc/html/rfc7234#section-5.2.2.1)

We can cache the request. But if the cache has expired, we must make a new request. 

- `no-cache` or `noStoreExists` or `max-age=0` or the `cache-control` header not present

Poll the JWKS endpoint at a minimum interval, like 1 second. Still cache the data for performance, but re-validate it as much as possible. 

Possible optimization on if the KID is unknown, and we're already polling every second. We don't need to re-validate the JWKS and can just fail.


Others:
`stale-if-error`
`max-stale`

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
