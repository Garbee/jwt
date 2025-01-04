class TokenExpired extends Error {
    expiredAt: number;
    currentTime: number;

    constructor(expiredAt: number, currentTime: number) {
        super('The token has expired.');
        this.expiredAt = expiredAt;
        this.currentTime = currentTime;
    }
}

export {TokenExpired};
