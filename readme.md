# JWT Helpers

## Message Groups

A few console logs are enabled if `JwtManager.debugMode` is set to `true`.
They are grouped together into code chunks for easier lookup and filtering.

01-20 - General messages - Log level: Info

* 001 - Initialization - Provides information on when an instance was made.
* 002 - Token expiration - Logs when a token has expired and can no longer be used.

21-40 - Potential security related issues: Log Level: Warn

* 021 - No expiration - Warns of a token being potentially dangerous. Without an expire time, it is valid indefinitely. Tokens should all have expiration times. This is checked at every use of the token, thus it can be noisy if a token is not fixed.
