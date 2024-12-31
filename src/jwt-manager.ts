import { jwtDecode, type JwtPayload } from 'jwt-decode';

class JwtManager<PayloadOverload extends JwtPayload> {
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
  get storage(): Storage {
    if (this.#storageType === 'local') {
      return localStorage;
    }

    return sessionStorage;
  }

  /**
   * Provide the token value that should be stored.
   * This will validate it is not expired before storage.
   * If expired, the token will not be stored since it is
   * not usable. When the token is valid, it is stored in
   * the storage system configured at initialization.
   */
  set token(value: string) {
    if (this.#hasExpired(value)) {
      console.error('An expired JWT was given to be stored.');
      return;
    }

    this.storage.setItem(this.#key, value);
  }

  /**
   * Retrieve the token string value from storage.
   * If the the token is expired upon retrieval, it is
   * removed from storage and undefined is returned as if
   * no token is set. Otherwise, the string value is
   * returned.
   */
  get token(): string | undefined {
    const token = this.storage.getItem(this.#key);

    if (token === null) {
      return undefined;
    }

    if (this.#hasExpired(token)) {
      this.storage.removeItem(this.#key);

      return undefined;
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

  constructor(
    key: string,
    storageType: 'session' | 'local' = 'session',
  ) {
    this.#storageType = storageType;
    this.#key = key;
  }

  /**
   * Decode the token into an object from the string value.
   */
  #decode(token: string): PayloadOverload {
    return jwtDecode<PayloadOverload>(token);
  }

  /**
   * Determine the expiration state based on the `exp` field.
   * If the field is not present, the token is valid
   * indefinitely. Otherwise, compare against current time.
   */
  #hasExpired(token: string): boolean {
    const decoded = this.#decode(token);

    if (!decoded.exp) {
      return false;
    }

    const currentTime = Math.floor(Date.now() / 1000);

    return decoded.exp < currentTime;
  }
}

export {
  JwtManager,
};
