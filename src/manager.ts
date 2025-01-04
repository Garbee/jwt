import { jwtDecode, type JwtPayload } from '#jwt-decode.js';
import { CriteriaNotBefore } from '#errors/criteria-not-before.js';
import { TokenExpired } from '#errors/token-expired.js';

/**
 * A manager for handling JWT tokens in the browser. This
 * enforces the time constraints of a token at every access
 * to ensure the token is valid before processing it.
 */
class JwtManager<PayloadOverload extends JwtPayload> {
  /**
   * Enable debug mode to log information for triage of
   * issues.
   */
  static debugMode = false;

  /**
   * The local storage system to use for keeping the token.
   * Defaults to session storage so it expires by default
   * with the session for the simplest security system.
   */
  #storageType: 'session' | 'local' = 'session';

  /**
   * The name of the key used when storing the token in
   * storage.
   */
  #key: string;

  /**
   * Retrieve the configured storage system to use.
   */
  get storageType() {
    return this.#storageType;
  }

  /**
   * Get the storage system from the browser.
   */
  get #storage(): Storage {
    if (this.#storageType === 'local') {
      return window.localStorage;
    }

    return window.sessionStorage;
  }

  /**
   * Provide the token value that should be stored.
   * This will validate it is not expired before storage.
   * If expired, the token will not be stored since it is
   * not usable. When the token is valid, it is stored in
   * the storage system configured at initialization.
   *
   * @throws CriteriaNotBeforeError when the token is set before it can be used.
   * @throws TokenExpired when the token is expired making it invalid.
   */
  set token(value: string) {
    this.#isValidTime(value);

    this.#storage.setItem(this.#key, value);
  }

  /**
   * Retrieve the token string value from storage.
   * If the the token is expired upon retrieval, it is
   * removed from storage and undefined is returned as if
   * no token is set. Otherwise, the string value is
   * returned.
   */
  get token(): string | undefined {
    const token = this.#storage.getItem(this.#key);

    if (token === null) {
      return undefined;
    }

    try {
      this.#isValidTime(token);
    } catch {
      this.#storage.removeItem(this.#key);

      console.info('JWT 002: The token has expired or failed custom validation logic. It is removed from storage.')

      return undefined
    }

    return token;
  }

  /**
   * Retrieve the body of the JWT data as an object.
   * If the JWT is expired or not present, undefined is
   * returned.
   */
  get data(): PayloadOverload | undefined {
    const {token} = this;

    if (token === undefined) {
      return undefined;
    }

    return this.#decode(token);
  }

  /**
   * Identifies principal that issued the JWT.
   */
  get issuer(): string | undefined {
    return this.data?.iss;
  }

  /**
   * Identifies the expiration time on and after which the
   * JWT must not be accepted for processing.
   */
  get expirationTime(): number | undefined {
    return this.data?.exp;
  }

  /**
   * Identifies the subject of the JWT.
   */
  get subject(): string | undefined {
    return this.data?.sub;
  }

  /**
   * Identifies the recipients that the JWT is intended for.
   */
  get audience(): string | string[] | undefined {
    return this.data?.aud;
  }

  /**
   * Identifies the time on which the JWT will start to be
   * accepted for processing.
   */
  get notBefore(): number | undefined {
    return this.data?.nbf;
  }

  /**
   * Identifies the time at which the JWT was issued.
   */
  get issuedAt(): number | undefined {
    return this.data?.iat;
  }

  /**
   * Case-sensitive unique identifier of the token even among
   * different issuers.
   */
  get jwtId(): string | undefined {
    return this.data?.jti;
  }

  constructor(
    key: string,
    storageType: 'session' | 'local' = 'session',
  ) {
    this.#key = key;
    this.#storageType = storageType;

    if (JwtManager.debugMode) {
      console.info(
        'JWT 001: initialized with storage key:',
        key,
        ' and using storage type: ',
        storageType,
      );
    }
  }

  /**
   * Decode the token into an object from the string value.
   */
  #decode(token: string): PayloadOverload {
    return jwtDecode<PayloadOverload>(token);
  }

  /**
   * Hook for consumers to provide custom validation logic.
   * This is run after the time validation is complete and
   * valid. This must throw errors if the token is invalid.
   */
  public customValidation(_tokenData: PayloadOverload): void {};

  /**
   * Determine the validity based on the `exp` and `nbf`
   * fields. If the `nbf` field is present, verify the current
   * time is after it. If the `exp` field is not present,
   * the token is valid indefinitely. Otherwise, compare
   * `exp` against current time to ensure it has not passed.
   * Finally, the custom validation is run to allow for
   * any special case checking to be performed by consumers.
   */
  #isValidTime(token: string): void {
    const decoded = this.#decode(token);
    const currentTime = Math.floor(Date.now() / 1000);

    if (
      decoded.nbf &&
      currentTime < decoded.nbf
    ) {
        throw new CriteriaNotBefore(decoded.nbf, currentTime);
    }

    if (!decoded.exp) {
      if (JwtManager.debugMode) {
        console.warn(
          'JWT 021: A token was provided that had no expiration time. This can be a security risk since if the token leaks it is valid indefinitely.',
        );
      }
      return undefined;
    }

    if(decoded.exp <= currentTime) {
      throw new TokenExpired(decoded.exp, currentTime);
    }

    this.customValidation(decoded);
  }
}

export {
  JwtManager,
  type JwtPayload,
};
