class CriteriaNotBefore extends Error {
    notBefore: number;
    currentTime: number;

    constructor(notBefore: number, currentTime: number) {
        super('The not before time has not yet passed.');
        this.notBefore = notBefore;
        this.currentTime = currentTime;
    }
}

export {CriteriaNotBefore};
