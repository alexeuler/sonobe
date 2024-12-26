#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
///
/// This example performs the full flow:
/// - define the circuit to be folded
/// - fold the circuit with Nova+CycleFold's IVC
/// - generate a DeciderEthCircuit final proof
/// - generate the Solidity contract that verifies the proof
/// - verify the proof in the EVM
///
use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use noname::backends::r1cs::R1csBn254Field;

use ark_groth16::{Groth16, ProvingKey};
use ark_grumpkin::Projective as G2;

use experimental_frontends::noname::NonameFCircuit;
use folding_schemes::{
    commitment::{
        kzg::{ProverKey, KZG},
        pedersen::Pedersen,
    },
    folding::{
        nova::{
            decider_eth::{prepare_calldata, Decider as DeciderEth},
            Nova, PreprocessorParam,
        },
        traits::CommittedInstanceOps,
    },
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Decider, Error, FoldingScheme,
};
use std::time::Instant;

use solidity_verifiers::{
    evm::{compile_solidity, Evm},
    utils::get_function_selector_for_nova_cyclefold_verifier,
    verifiers::nova_cyclefold::get_decider_template_for_cyclefold_decider,
    NovaCycleFoldVerifierKey,
};

type PP<'a> = (
    ProvingKey<ark_ec::models::bn::Bn<ark_bn254::Config>>,
    ProverKey<'a, ark_ec::models::short_weierstrass::Projective<ark_bn254::g1::Config>>,
);

fn main() -> Result<(), Error> {
    const NONAME_CIRCUIT_EXTERNAL_INPUTS: &str =
        "fn main(pub ivc_inputs: [Field; 2], external_inputs: [Field; 2]) -> [Field; 2] {
    let xx = external_inputs[0] + ivc_inputs[0];
    let yy = external_inputs[1] * ivc_inputs[1];
    assert_eq(yy, xx);
    return [xx, yy];
}";

    println!("Start");
    // set the initial state
    let z_0 = vec![Fr::from(2), Fr::from(5)];

    // set the external inputs to be used at each step of the IVC, it has length of 10 since this
    // is the number of steps that we will do
    let external_inputs = vec![
        vec![Fr::from(8u32), Fr::from(2u32)],
        vec![Fr::from(40), Fr::from(5)],
    ];

    // initialize the noname circuit
    let f_circuit_params = (NONAME_CIRCUIT_EXTERNAL_INPUTS.to_owned(), 2, 2);
    let f_circuit = NonameFCircuit::<Fr, R1csBn254Field>::new(f_circuit_params)?;

    pub type N =
        Nova<G1, G2, NonameFCircuit<Fr, R1csBn254Field>, KZG<'static, Bn254>, Pedersen<G2>>;
    pub type D = DeciderEth<
        G1,
        G2,
        NonameFCircuit<Fr, R1csBn254Field>,
        KZG<'static, Bn254>,
        Pedersen<G2>,
        Groth16<Bn254>,
        N,
    >;

    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = ark_std::rand::rngs::OsRng;

    // prepare the Nova prover & verifier params
    println!("Preprocess Nova");
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit.clone());
    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params)?;

    println!("Initialize FoldingScheme");
    // initialize the folding scheme engine, in our case we use Nova
    let mut nova = N::init(&nova_params, f_circuit.clone(), z_0)?;

    println!("Generate decider params");
    // prepare the Decider prover & verifier params
    let (decider_pp, decider_vp) = D::preprocess(&mut rng, nova_params.clone(), nova.clone())?;

    let mut dpp_bytes = Vec::new();
    decider_pp.serialize_compressed(&mut dpp_bytes)?;
    println!("Bytes len: {}", dpp_bytes.len());
    let start = Instant::now();
    let dpp = PP::deserialize_compressed_unchecked(dpp_bytes.as_slice())?;
    println!("Deserialize time: {:?}", start.elapsed());
    Ok(())
}
