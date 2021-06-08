export interface PrimeGroup {
    N: bigint;
    g: bigint;
}
export declare type HashFunction = (data: ArrayBuffer) => Promise<ArrayBuffer>;
export declare class SRPParameters {
    readonly primeGroup: PrimeGroup;
    readonly H: HashFunction;
    static PrimeGroup: {
        [key: number]: PrimeGroup;
    };
    static H: {
        [key: string]: HashFunction;
    };
    readonly NBits: number;
    constructor(primeGroup?: PrimeGroup, H?: HashFunction);
}
