/* eslint "@typescript-eslint/no-explicit-any": 0 */
/* eslint "@typescript-eslint/no-unused-vars": 0 */
declare module 'ffjavascript'
/** Declaration file generated by dts-gen */
declare module "snarkjs/src/fflonk_prove";
declare module 'snarkjs' {
  class groth16 {
    static exportSolidityCallData: any
    static fullProve(_input: any, wasmFile: any, zkeyFileName: any, logger?: any): Promise<any>
    static prove(zkeyFileName: any, witnessFileName: any, logger?: any): Promise<any>
    static verify(_vk_verifier: any, _publicSignals: any, _proof: any, logger?: any): Promise<any>
  }
  class plonk {
    exportSolidityCallData: any
    static fullProve(_input: any, wasmFile: any, zkeyFileName: any, logger?: any): Promise<any>
    static prove(zkeyFileName: any, witnessFileName: any, logger?: any): Promise<any>
    static verify(_vk_verifier: any, _publicSignals: any, _proof: any, logger?: any): Promise<any>
  }
  class fflonk {
    static exportSolidityCallData: any
    static fullProve: any
    static prove: any
    static setup: any
    static verify: any
  }
  class powersOfTau {
    beacon: any
    challengeContribute: any
    contribute: any
    convert: any
    exportChallenge: any
    exportJson: any
    importResponse: any
    newAccumulator: any
    preparePhase2: any
    truncate: any
    verify: any
  }
  class r1cs {
    exportJson: any
    info: any
    print: any
  }
  class wtns {
    calculate: any
    debug: any
    exportJson: any
  }
  class zKey {
    beacon: any
    bellmanContribute: any
    contribute: any
    exportBellman: any
    exportJson: any
    exportSolidityVerifier: any
    exportVerificationKey: any
    importBellman: any
    newZKey: any
    verifyFromInit: any
    verifyFromR1cs: any
  }
}

