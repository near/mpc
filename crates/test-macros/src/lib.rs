use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};



#[proc_macro_attribute]
pub fn with_rng(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);
    let fn_name = &func.sig.ident;
    let fn_block = &func.block;

    // The name of the RNG variable the user gets
    let rng_ident = syn::Ident::new("rng", fn_name.span());

    // Wrap the original body
    let wrapped = quote! {
        #[test]
        fn #fn_name() {
            use rand::{RngCore, SeedableRng};
            use rand::rngs::StdRng;
            use rand::Rng;

            fn extract_seed_from_env()-> Option<[u8; 32]> {
                let Ok(val) = std::env::var("TEST_SEED") else {
                    return None
                };
                // Expected format: "71,08,70,..."
                let bytes: Vec<u8> = val
                    .split(',')
                    .map(|s| u8::from_str_radix(s.trim().trim_start_matches("0x"), 16)
                         .expect("Invalid TEST_SEED byte"))
                    .collect();
            
                assert_eq!(bytes.len(), 32, "TEST_SEED must have 32 bytes");
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                eprintln!("Using explicit TEST_SEED = {:?}", arr);
                Some(arr)
            }
            
            fn gen_seed() -> [u8; 32] {
                let mut seed = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut seed);
                seed
            }

            // Generate seed
            let seed = extract_seed_from_env().unwrap_or(gen_seed());

            // Initialize RNG
            let mut #rng_ident = StdRng::from_seed(seed);

            // Run the test body with panic capture
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                #fn_block
            }));

            if let Err(e) = result {
                eprintln!("Test failed with RNG seed: {:02x?}", seed);
                std::panic::resume_unwind(e);
            }
        }
    };

    wrapped.into()
}
