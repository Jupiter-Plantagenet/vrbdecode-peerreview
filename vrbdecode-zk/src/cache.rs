use std::fs;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::{io, io::ErrorKind};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub fn write_compressed<T: CanonicalSerialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let f = fs::File::create(path)?;
    let mut w = BufWriter::new(f);
    value
        .serialize_compressed(&mut w)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    Ok(())
}

pub fn read_compressed<T: CanonicalDeserialize>(path: &Path) -> io::Result<T> {
    let f = fs::File::open(path)?;
    let mut r = BufReader::new(f);
    T::deserialize_compressed(&mut r).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn roundtrip_fr_compressed() {
        let mut rng = StdRng::seed_from_u64(123456789);
        let v = Fr::rand(&mut rng);

        let path = std::env::temp_dir().join(format!(
            "vrbdecode_zk_cache_roundtrip_{}_{}.bin",
            std::process::id(),
            123456789u64
        ));

        write_compressed(&path, &v).expect("write");
        let got: Fr = read_compressed(&path).expect("read");
        let _ = fs::remove_file(&path);

        assert_eq!(v, got);
    }
}
