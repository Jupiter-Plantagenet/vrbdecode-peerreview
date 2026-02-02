use ark_bn254::Fr;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::frontend::FCircuit;
use folding_schemes::Error;

#[derive(Clone, Debug)]
pub struct ReceiptFCircuit {
    poseidon_config: PoseidonConfig<Fr>,
}

impl ReceiptFCircuit {
    pub fn default_poseidon_config() -> PoseidonConfig<Fr> {
        crate::step_circuit::poseidon_params_bn254_rate8()
    }

    pub fn new_with_poseidon_config(poseidon_config: PoseidonConfig<Fr>) -> Self {
        Self { poseidon_config }
    }

    pub fn new_default() -> Result<Self, Error> {
        Ok(Self::new_with_poseidon_config(Self::default_poseidon_config()))
    }
}

impl FCircuit<Fr> for ReceiptFCircuit {
    type Params = PoseidonConfig<Fr>;
    type ExternalInputs = [Fr; 11];
    type ExternalInputsVar = [FpVar<Fr>; 11];

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            poseidon_config: params,
        })
    }

    fn state_len(&self) -> usize {
        1
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<Fr>,
        _i: usize,
        z_i: Vec<FpVar<Fr>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
        let mut sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &self.poseidon_config);
        for &b in b"VRBDecode.Receipt.v1" {
            sponge.absorb(&FpVar::Constant(Fr::from(b as u64)))?;
        }
        sponge.absorb(&z_i[0])?;
        for x in external_inputs {
            sponge.absorb(&x)?;
        }
        let out = sponge.squeeze_field_elements(1)?;
        Ok(vec![out[0].clone()])
    }
}
