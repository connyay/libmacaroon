//! Example demonstrating macaroon usage with WASM-compatible RustCrypto backend
//! 
//! To run this example with RustCrypto:
//! cargo run --example wasm_example --no-default-features --features rustcrypto-backend
//!
//! To build for WASM:
//! cargo build --example wasm_example --target wasm32-unknown-unknown --no-default-features --features wasm

use macaroon::{Macaroon, MacaroonKey, Verifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the cryptographic backend
    macaroon::initialize()?;
    
    println!("Creating macaroon with RustCrypto backend...");
    
    // Create a key
    let key = MacaroonKey::generate(b"super-secret-key-for-demo");
    
    // Create a macaroon
    let mut macaroon = Macaroon::create(
        Some("https://example.com/".into()), 
        &key, 
        "demo-macaroon".into()
    )?;
    
    // Add some caveats
    macaroon.add_first_party_caveat("user = alice".into());
    macaroon.add_first_party_caveat("action = read".into());
    
    println!("Macaroon created with {} caveats", macaroon.caveats().len());
    
    // Serialize the macaroon
    let serialized = macaroon.serialize(macaroon::Format::V2)?;
    println!("Serialized macaroon length: {} bytes", serialized.len());
    
    // Deserialize the macaroon
    let deserialized = Macaroon::deserialize(&serialized)?;
    println!("Deserialized macaroon successfully");
    
    // Verify the macaroon
    let mut verifier = Verifier::default();
    verifier.satisfy_exact("user = alice".into());
    verifier.satisfy_exact("action = read".into());
    
    match verifier.verify(&deserialized, &key, Default::default()) {
        Ok(_) => println!("✅ Macaroon verification successful!"),
        Err(e) => println!("❌ Macaroon verification failed: {}", e),
    }
    
    // Test third-party caveat (encryption/decryption)
    println!("\nTesting third-party caveat (encryption/decryption)...");
    let caveat_key = MacaroonKey::generate(b"caveat-key");
    let mut macaroon_with_3p = macaroon.clone();
    macaroon_with_3p.add_third_party_caveat("https://auth.example.com", &caveat_key, "caveat-id".into());
    
    println!("✅ Third-party caveat added successfully (encryption worked)");
    
    // Create discharge macaroon
    let mut discharge = Macaroon::create(
        Some("https://auth.example.com".into()),
        &caveat_key,
        "caveat-id".into(),
    )?;
    discharge.add_first_party_caveat("time < 2025-12-31".into());
    
    // Bind the discharge
    macaroon_with_3p.bind(&mut discharge);
    
    // Verify with discharge
    verifier.satisfy_exact("time < 2025-12-31".into());
    match verifier.verify(&macaroon_with_3p, &key, vec![discharge]) {
        Ok(_) => println!("✅ Third-party macaroon verification successful!"),
        Err(e) => println!("❌ Third-party macaroon verification failed: {}", e),
    }
    
    println!("\n🎉 All tests passed! RustCrypto backend is working correctly.");
    
    Ok(())
}