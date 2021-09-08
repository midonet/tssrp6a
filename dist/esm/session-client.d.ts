import { SRPRoutines } from "./routines";
export declare class SRPClientSession {
    private readonly routines;
    constructor(routines: SRPRoutines);
    step1(
    /**
     * User identity
     */
    userId: string, 
    /**
     * User password (not kept in state)
     */
    userPassword: string): Promise<SRPClientSessionStep1>;
}
export declare type SRPClientSessionStep1State = {
    I: string;
    IH: Array<number>;
};
export declare class SRPClientSessionStep1 {
    private readonly routines;
    /**
     * User identity
     */
    private readonly I;
    /**
     * User identity/password hash
     */
    readonly IH: ArrayBuffer;
    constructor(routines: SRPRoutines, 
    /**
     * User identity
     */
    I: string, 
    /**
     * User identity/password hash
     */
    IH: ArrayBuffer);
    step2(
    /**
     * Some generated salt (see createVerifierAndSalt)
     */
    salt: bigint, 
    /**
     * Server public key "B"
     */
    B: bigint): Promise<SRPClientSessionStep2>;
    toJSON(): SRPClientSessionStep1State;
    static fromState(routines: SRPRoutines, state: SRPClientSessionStep1State): SRPClientSessionStep1;
}
export declare type SRPClientSessionStep2State = {
    A: string;
    M1: string;
    S: string;
};
export declare class SRPClientSessionStep2 {
    private readonly routines;
    /**
     * Client public value "A"
     */
    readonly A: bigint;
    /**
     * Client evidence message "M1"
     */
    readonly M1: bigint;
    /**
     * Shared session key "S"
     */
    readonly S: bigint;
    constructor(routines: SRPRoutines, 
    /**
     * Client public value "A"
     */
    A: bigint, 
    /**
     * Client evidence message "M1"
     */
    M1: bigint, 
    /**
     * Shared session key "S"
     */
    S: bigint);
    step3(M2: bigint): Promise<void>;
    toJSON(): SRPClientSessionStep2State;
    static fromState(routines: SRPRoutines, state: SRPClientSessionStep2State): SRPClientSessionStep2;
}
