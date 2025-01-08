## mpc
This repository contains the code for the Near mpc node. It is a rewrite of [Near mpc](https://github.com/near/mpc).

### Dependencies and submodules
- **Nearcore Node**: This repository depends on the nearcore node, included as a submodule in the `/libs` directory.
- **Chain signatures**: This repository contains squashed subtrees of the `contract` and `crypto-shared` folder from [near/mpc/chain-signatures](https://github.com/near/mpc/tree/develop/chain-signatures), required for integration tests.
- **Other Dependencies**: All other dependencies are handled by Cargo.

### Testing:
- **Unit Tests**: Run with `cargo test --release` (`--release` flag is advised for performance reasons).
- **integration Test** : Located in the `/pytest` directory.


### Compilation:
This repository uses `rust-toolchain.toml` files, as some code sections may require specific compiler versions. Be aware of potential overrides from:
- Directory-specific toolchain overrides
- Environment variables  

For more information, refer to the [Rustup book on overrides](https://rust-lang.github.io/rustup/overrides.html).
