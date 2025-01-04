# JWT Helpers

This project provides a JSON Web Tokens (JWT) manager. It
helps streamline the use of JWTs in your applications.
Primarily the manager is the work-horse in production code.
It facilitates the storage and retrieval of data from the
token. Beyond that, there is also a helper for making
mock tokens when unit testing. By using mock tokens teams
are able to isolate their front-end tests from any
back-end to help ensure a robust and reliable experience
for people using the applications.

There is a focus on keeping dependencies minimal. Right now,
the only production dependency is `jwt-decode`. This
remaining as a dependency will be based upon a deeper review
of what the complexity is with the decode process. So long
as there are no blockers with handling the algorithms, it
will be removed in time.

## Installation

Install the package using NPM with:

```shell
npm install @garbee/jwt
```

## Manager

The manager is a class that handles storage of a JWT. It
also facilitates retrieval of information from the token.
Validation that the token is still valid is done at every
use.

### Usage

To import the manager class use the following:

```javascript
import {JwtManager} from '@garbee/jwt/manager.js';
```

Once imported, it is recommended to extend the class to
add your own helpers. Since JWTs are designed to flex
to different organization's needs, the base manager only
provides helpers for what the specification defines.

For example, if you have a JWT with a `username` and `email`
field. This is one way of extending the helper in order
to re-export your own for use within the application. (This
example is using TypeScript as well.)

```typescript
import {JwtManager, type JwtPayload} from '@garbee/jwt/manager.js';

// The definition for custom attributes that extend the standard
// specified properties of JWTs.
interface PayloadOverload extends JwtPayload {
  // The name of the user. Optional since they may not have provided it.
  name?: string;
  // The email for the user. Required entry, so it is always available.
  email: string;
}

class AppJwtManager extends JwtManager<PayloadOverload> {
  get name(): string | undefined {
    return this.data?.name;
  }

  get email(): string {
    return this.data.email;
  }
}

export {AppJwtManager};
```

### API

#### Manager

The manager in TypeScript does offer a generic type. It takes a Payload definition to define any custom properties on your JWT's data. It should extent `JwtPayload` (exported by the same file) so no collisions with the standard expectations are put into place.

##### Constructor

The constructor takes 1 or 2 options.
The first parameter is the string to
be used as the key for the JWT value when stored.
The second parameter is what type of storage to use. This defaults to `'session'` for session storage. To select local storage, provide `'local'`.

##### Errors

CriteriaNotBefore is thrown when the not before (`nbf`) value is supplied in the token and the time is before it is allowed.

TokenExpired is thrown when the expiration (`exp`) field is set in the token and the time is equal to or after that time.

These float up the call stack when the token is being **set**. When it is being retrieved the errors stop in the manager and `undefined` is returned after the token is removed from storage.

##### Static Properties

The only static property is `debugMode`. This is off by default and enables some logging that might be beneficial in development. Since all the operations in the core class are extremely fast, no performance logging is provided. However, this might be a useful property to check in any custom validation or other extensions that may take compute time.

##### Properties

Properties are the primary way of getting information about both the manager and the token data.

| Property       | Type                            | Description                                                                                                                        |
|----------------|---------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| storageType    | 'session' \| 'local'            | The type of storage to use for holding the token. Defaults to session storage.                                                     |
| token          | string                          | The token currently in use. When set, validation occurs before storage. When read, validation occurs before the value is returned. |
| data           | PayloadOverload \| undefined    | The decoded token data as an object. If no token is stored or it is invalid, undefined is returned.                                |
| issuer         | string \| undefined             | Identifies principal that issued the JWT.                                                                                          |
| expirationTime | number \| undefined             | Identifies the expiration time on and after which the JWT must not be accepted for processing.                                     |
| subject        | string \| undefined             | Identifies the subject of the JWT.                                                                                                 |
| audience       | string \| string[] \| undefined | Identifies the recipients that the JWT is intended for.                                                                            |
| notBefore      | number \| undefined             | Identifies the time on which the JWT will start to be accepted for processing.                                                     |
| issuedAt       | number \| undefined             | Identifies the time at which the JWT was issued.                                                                                   |
| jwtId          | string \| undefined             | Case-sensitive unique identifier of the token even among different issuers.                                                        |

##### Methods

There are no public methods other than the empty placeholder for custom validation.

### Validation

Every time the token is accessed, it is pulled from storage
and the validity of it based on the expiration and not
before times are confirmed. If a token misses either
time-frame, it is removed and no longer used.

For the front-end of a web app, this is the most aggressive
level of validating a token for use that works across as
many applications as possible. There is a method which
can be implemented called `customValidation`. This runs
after the time checks are valid to allow for any additional
checks to be ran.

Remember, this is ONLY validation of the token's ability
to be used. None of it is proper security, aside from
ensuring there is an expiration time at all, since on the
front-end all of the usage can be manipulated anyways. It
is up to the **back-end** systems to both validate and
authenticate the tokens sent to it.

#### Using Custom Validation

Extend the class as seen in it's usage section. Then
implement the following method. Remember that the method
**must** throw an error when validation fails. No return
value is used.

```typescript
/**
* Hook for consumers to provide custom validation logic.
* This is run after the time validation is complete and
* valid. This must throw errors if the token is invalid.
*/
public override customValidation(_tokenData: PayloadOverload): void {
  // For example
  if (this.email.split('@')[1] !== 'example.com') {
    throw new Error('The user is not from the organization. Access denied.');
  }
};
```

## Unit Testing

### Create Mock

A function is exported for assisting in making a mock token.
It is extremely small with no API design for comfort. As,
most of the time you make one token for a set of tests. If
your project is complex enough to need or just want a lot of
tokens, it is recommended you create a custom wrapper.

Here is a sample of how to use the function pulled from
the package's unit tests.
```typescript
import {createMockJwt} from '@garbee/jwt/create-mock.js';

const jwtPayload = {
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor((Date.now() + 2000) / 1000),
  name: 'can store jwt Test',
};

const mockJwt = createMockJwt(jwtPayload);
```

Remember, since the token is checked for validity at all
uses you will want to override the clock system so you
control the timing in all tests where a JWT is in use.

## Message Groups

A few console logs are enabled if `JwtManager.debugMode` is set to `true`.
They are grouped together into code chunks for easier lookup and filtering.

The following groups are defined:

* 01 - 20 - General messages logged at the level of  `info`
* 21-40 - Potential security related issues at the log level of `warn`

### General Messages

* 001 - Initialization - Provides information on when an instance was made.
* 002 - Token expiration - Logs when a token has expired and can no longer be used.

### Potential security Issues

* 021 - No expiration - Warns of a token being potentially dangerous. Without an expire time, it is valid indefinitely. Tokens should all have expiration times. This is checked at every use of the token, thus it can be noisy if a token is not fixed.
