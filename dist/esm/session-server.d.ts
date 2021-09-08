import { SRPRoutines } from "./routines";
export declare class SRPServerSession {
    private readonly routines;
    constructor(routines: SRPRoutines);
    step1(
    /**
     * User identity
     */
    identifier: string, 
    /**
     * User salt
     */
    salt: bigint, 
    /**
     * User verifier
     */
    verifier: bigint): Promise<SRPServerSessionStep1>;
}
export declare type SRPServerSessionStep1State = {
    identifier: string;
    salt: string;
    verifier: string;
    b: string;
    B: string;
};
export declare class SRPServerSessionStep1 {
    readonly routines: SRPRoutines;
    /**
     * User identity
     */
    private readonly identifier;
    /**
     * User salt
     */
    private readonly salt;
    /**
     * User verifier
     */
    private readonly verifier;
    /**
     * Server private key "b"
     */
    private readonly b;
    /**
     * Serve public key "B"
     */
    readonly B: bigint;
    constructor(routines: SRPRoutines, 
    /**
     * User identity
     */
    identifier: string, 
    /**
     * User salt
     */
    salt: bigint, 
    /**
     * User verifier
     */
    verifier: bigint, 
    /**
     * Server private key "b"
     */
    b: bigint, 
    /**
     * Serve public key "B"
     */
    B: bigint);
    /**
     * Compute the session key "S" without computing or checking client evidence
     */
    sessionKey(
    /**
     * Client public key "A"
     */
    A: bigint): Promise<bigint>;
    step2(
    /**
     * Client public key "A"
     */
    A: bigint, 
    /**
     * Client message "M1"
     */
    M1: bigint): Promise<bigint>;
    toJSON(): SRPServerSessionStep1State;
    static fromState(routines: SRPRoutines, state: SRPServerSessionStep1State): SRPServerSessionStep1;
}
