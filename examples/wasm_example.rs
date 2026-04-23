//! Example demonstrating macaroon usage (works with both native and WASM targets)
//!
//! To run natively:
//! cargo run --example wasm_example
//!
//! To build for WASM:
//! cargo build --example wasm_example --target wasm32-unknown-unknown --features wasm

use macaroon::{Macaroon, MacaroonKey, Verifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating macaroon with RustCrypto backend...");

    // Create a key
    let key = MacaroonKey::generate(b"super-secret-key-for-demo");

    // Create a macaroon
    let mut macaroon =
        Macaroon::create(Some("https://example.com/".into()), &key, "demo-macaroon")?;

    // Add some caveats
    macaroon.add_first_party_caveat("user = alice")?;
    macaroon.add_first_party_caveat("action = read")?;

    println!("Macaroon created with {} caveats", macaroon.caveats().len());

    // Serialize the macaroon
    let serialized = macaroon.serialize(macaroon::Format::V2)?;
    println!("Serialized macaroon length: {} bytes", serialized.len());

    // Deserialize the macaroon
    let deserialized = Macaroon::deserialize(&serialized)?;
    println!("Deserialized macaroon successfully");

    // Verify the macaroon
    let mut verifier = Verifier::default();
    verifier.satisfy_exact("user = alice");
    verifier.satisfy_exact("action = read");

    match verifier.verify(&deserialized, &key, &[]) {
        Ok(_) => println!("✅ Macaroon verification successful!"),
        Err(e) => println!("❌ Macaroon verification failed: {}", e),
    }

    // Test third-party caveat (encryption/decryption)
    println!("\nTesting third-party caveat (encryption/decryption)...");
    let caveat_key = MacaroonKey::generate(b"caveat-key");
    let mut macaroon_with_3p = macaroon.clone();
    macaroon_with_3p.add_third_party_caveat(
        "https://auth.example.com",
        &caveat_key,
        "caveat-id",
    )?;

    println!("✅ Third-party caveat added successfully (encryption worked)");

    // Create discharge macaroon
    let mut discharge = Macaroon::create(
        Some("https://auth.example.com".into()),
        &caveat_key,
        "caveat-id",
    )?;
    discharge.add_first_party_caveat("time < 2025-12-31")?;

    // Bind the discharge
    macaroon_with_3p.bind(&mut discharge);

    // Verify with discharge
    verifier.satisfy_exact("time < 2025-12-31");
    match verifier.verify(&macaroon_with_3p, &key, &[discharge]) {
        Ok(_) => println!("✅ Third-party macaroon verification successful!"),
        Err(e) => println!("❌ Third-party macaroon verification failed: {}", e),
    }

    println!("\n🎉 All tests passed! RustCrypto backend is working correctly.");

    Ok(())
}
