use ark_bn254::{Bn254, Fr, G1Projective as Projective};
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_grumpkin::Projective as Projective2;
use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen};
use folding_schemes::folding::nova::{Nova, PreprocessorParam};
use folding_schemes::FoldingScheme;
use rand::rngs::StdRng;
use rand::SeedableRng;

use vrbdecode_zk::ReceiptFCircuit;

fn receipt_step_native(poseidon_config: &PoseidonConfig<Fr>, h_prev: Fr, ext: &[Fr; 11]) -> Fr {
    let mut sponge = PoseidonSponge::<Fr>::new(poseidon_config);
    for &b in b"VRBDecode.Receipt.v1" {
        sponge.absorb(&Fr::from(b as u64));
    }
    sponge.absorb(&h_prev);
    for x in ext.iter() {
        sponge.absorb(x);
    }
    sponge.squeeze_field_elements(1)[0]
}

#[test]
#[ignore]
fn sonobe_nova_receipt_ivc_smoke() -> Result<(), folding_schemes::Error> {
    type N = Nova<
        Projective,
        Projective2,
        ReceiptFCircuit,
        KZG<'static, Bn254>,
        Pedersen<Projective2>,
        false,
    >;

    let num_steps = 3usize;
    let initial_state = vec![Fr::from(1u64)];

    let poseidon_config = ReceiptFCircuit::default_poseidon_config();
    let f_circuit = ReceiptFCircuit::new_with_poseidon_config(poseidon_config.clone());

    let mut ext_inputs: Vec<[Fr; 11]> = Vec::with_capacity(num_steps);
    for i in 0..num_steps {
        ext_inputs.push([
            Fr::from(10u64 + i as u64),
            Fr::from(20u64 + i as u64),
            Fr::from(30u64 + i as u64),
            Fr::from(40u64 + i as u64),
            Fr::from(50u64 + i as u64),
            Fr::from(60u64 + i as u64),
            Fr::from(70u64 + i as u64),
            Fr::from(80u64 + i as u64),
            Fr::from(90u64 + i as u64),
            Fr::from(100u64 + i as u64),
            Fr::from(110u64 + i as u64),
        ]);
    }

    let mut rng = StdRng::seed_from_u64(123456789u64);

    let pp = PreprocessorParam::new(poseidon_config, f_circuit.clone());
    let params = N::preprocess(&mut rng, &pp)?;

    let mut folding = N::init(&params, f_circuit, initial_state.clone())?;

    let mut expected_state = initial_state[0];
    for ext in ext_inputs.iter() {
        folding.prove_step(&mut rng, ext.clone(), None)?;
        expected_state = receipt_step_native(&ReceiptFCircuit::default_poseidon_config(), expected_state, ext);
    }

    let state = folding.state();
    assert_eq!(state.len(), 1);
    assert_eq!(state[0], expected_state);

    let proof = folding.ivc_proof();
    N::verify(params.1, proof)?;
    Ok(())
}
