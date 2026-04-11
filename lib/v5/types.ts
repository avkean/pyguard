// Shared interfaces between lib/obfuscate.ts and lib/v5/assemble.ts.
// Declared here to avoid a circular import between the two modules.

export interface NameGen {
    gen(): string;
}

export interface PolyProfile {
    rounds: number;
    rkLabel: Uint8Array;
    rotLabel: Uint8Array;
    sbxLabel: Uint8Array;
    rotMod: number;
    sbxNudge: number;
    poison1: number;
    poison2: number;
    poison3: number;
}

export interface CipherLayer {
    rks: Uint8Array[];
    rotk: number[];
    sbox: number[];
    inv: number[];
}

export interface ChunkedB64 {
    decls: string;
    concat: string;
}
