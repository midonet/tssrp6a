var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
// Variable names match the RFC (I, IH, S, b, B, salt, b, A, M1, M2...)
export class SRPClientSession {
    constructor(routines) {
        this.routines = routines;
    }
    step1(
    /**
     * User identity
     */
    userId, 
    /**
     * User password (not kept in state)
     */
    userPassword) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!userId || !userId.trim()) {
                throw new Error("User identity must not be null nor empty");
            }
            if (!userPassword) {
                throw new Error("User password must not be null");
            }
            const IH = yield this.routines.computeIdentityHash(userId, userPassword);
            return new SRPClientSessionStep1(this.routines, userId, IH);
        });
    }
}
export class SRPClientSessionStep1 {
    constructor(routines, 
    /**
     * User identity
     */
    I, 
    /**
     * User identity/password hash
     */
    IH) {
        this.routines = routines;
        this.I = I;
        this.IH = IH;
    }
    step2(
    /**
     * Some generated salt (see createVerifierAndSalt)
     */
    salt, 
    /**
     * Server public key "B"
     */
    B) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!salt) {
                throw new Error("Salt (s) must not be null");
            }
            if (!B) {
                throw new Error("Public server value (B) must not be null");
            }
            // TODO can we run any of these promises in parallel?
            const x = yield this.routines.computeXStep2(salt, this.IH);
            const a = this.routines.generatePrivateValue();
            const A = this.routines.computeClientPublicValue(a);
            const k = yield this.routines.computeK();
            const u = yield this.routines.computeU(A, B);
            const S = this.routines.computeClientSessionKey(k, x, u, a, B);
            const M1 = yield this.routines.computeClientEvidence(this.I, salt, A, B, S);
            return new SRPClientSessionStep2(this.routines, A, M1, S);
        });
    }
    toJSON() {
        return { I: this.I, IH: Array.from(new Uint8Array(this.IH)) };
    }
    static fromState(routines, state) {
        return new SRPClientSessionStep1(routines, state.I, new Uint8Array(state.IH).buffer);
    }
}
export class SRPClientSessionStep2 {
    constructor(routines, 
    /**
     * Client public value "A"
     */
    A, 
    /**
     * Client evidence message "M1"
     */
    M1, 
    /**
     * Shared session key "S"
     */
    S) {
        this.routines = routines;
        this.A = A;
        this.M1 = M1;
        this.S = S;
    }
    step3(M2) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!M2) {
                throw new Error("Server evidence (M2) must not be null");
            }
            const computedM2 = yield this.routines.computeServerEvidence(this.A, this.M1, this.S);
            if (computedM2 !== M2) {
                throw new Error("Bad server credentials");
            }
        });
    }
    toJSON() {
        return {
            A: this.A.toString(16),
            M1: this.M1.toString(16),
            S: this.S.toString(16),
        };
    }
    static fromState(routines, state) {
        return new SRPClientSessionStep2(routines, BigInt("0x" + state.A), BigInt("0x" + state.M1), BigInt("0x" + state.S));
    }
}
//# sourceMappingURL=session-client.js.map