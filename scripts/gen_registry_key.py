#!/usr/bin/env python3
"""
Generate a fresh P-256 keypair for the TrustSeal registry signer.

Run ONCE, by hand. Paste the PRIVATE PEM into the Railway secret
ZKNOT_REGISTRY_PRIVKEY_PEM. The output is NEVER committed to the repo.

    python scripts/gen_registry_key.py

Prints:
  - the private key PEM (the secret)
  - the public key as uncompressed X||Y hex (for pinning / sanity checks)

The public hex is what /v1/seal/register stores on each artifact, so a skeptic
can verify the registry signature independently against it.
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def main() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    nums = private_key.public_key().public_numbers()
    pub_hex = nums.x.to_bytes(32, "big").hex() + nums.y.to_bytes(32, "big").hex()

    print("# === ZKNOT registry signer keypair ===")
    print("# Set the private key as Railway secret ZKNOT_REGISTRY_PRIVKEY_PEM.")
    print("# DO NOT commit this output. DO NOT paste it into logs or chat.\n")
    print("ZKNOT_REGISTRY_PRIVKEY_PEM (private — keep secret):")
    print(pem)
    print("Registry public key (uncompressed X||Y hex — safe to share/pin):")
    print(pub_hex)


if __name__ == "__main__":
    main()
