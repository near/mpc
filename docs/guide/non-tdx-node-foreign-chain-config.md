# Foreign chain config for non-TDX nodes


## Testnet example

Replace `YOUR_*` with your keys and `YOUR-SLUG` with your QuickNode endpoint name. Verify before
deploying:

```bash
cargo run -p foreign-chain-config-tester -- --config /path/to/config.yaml
```

```yaml
foreign_chains:
  bitcoin:
    timeout_sec: 30
    max_retries: 3
    expected_network_fingerprint: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    providers:
      public:
        rpc_url: "https://bitcoin-testnet-rpc.publicnode.com"
        auth:
          kind: none
  abstract:
    timeout_sec: 30
    max_retries: 3
    expected_network_fingerprint: "11124"
    providers:
      abstract-testnet:
        rpc_url: "https://api.testnet.abs.xyz"
        auth:
          kind: none
      alchemy:
        rpc_url: "https://abstract-testnet.g.alchemy.com/v2/{API_KEY}"
        auth:
          kind: path
          placeholder: "{API_KEY}"
          token:
            val: "YOUR_ALCHEMY_API_KEY"
      quicknode:
        rpc_url: "https://YOUR-SLUG.abstract-testnet.quiknode.pro/{api_key}"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            val: "YOUR_QUICKNODE_API_KEY"
  starknet:
    timeout_sec: 30
    max_retries: 3
    expected_network_fingerprint: "0x534e5f5345504f4c4941"
    providers:
      publicnode:
        rpc_url: "https://starknet-sepolia-rpc.publicnode.com"
        auth:
          kind: none
      alchemy:
        rpc_url: "https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_10/{API_KEY}"
        auth:
          kind: path
          placeholder: "{API_KEY}"
          token:
            val: "YOUR_ALCHEMY_API_KEY"
      quicknode:
        rpc_url: "https://YOUR-SLUG.strk-sepolia.quiknode.pro/{api_key}"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            val: "YOUR_QUICKNODE_API_KEY"
  aptos:
    timeout_sec: 30
    max_retries: 3
    expected_network_fingerprint: "2"
    providers:
      public:
        rpc_url: "https://fullnode.testnet.aptoslabs.com/v1"
        auth:
          kind: none
      alchemy:
        rpc_url: "https://aptos-testnet.g.alchemy.com/v2/{API_KEY}/v1"
        auth:
          kind: path
          placeholder: "{API_KEY}"
          token:
            val: "YOUR_ALCHEMY_API_KEY"
      quicknode:
        rpc_url: "https://YOUR-SLUG.aptos-testnet.quiknode.pro/{api_key}/v1"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            val: "YOUR_QUICKNODE_API_KEY"
      geomi:
        rpc_url: "https://api.testnet.aptoslabs.com/v1"
        auth:
          kind: header
          name: "Authorization"
          scheme: "Bearer"
          token:
            val: "YOUR_GEOMI_API_KEY"
  sui:
    timeout_sec: 30
    max_retries: 3
    expected_network_fingerprint: "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD"
    providers:
      public:
        rpc_url: "https://archive.testnet.sui.io"
        auth:
          kind: none
      alchemy:
        rpc_url: "https://sui-testnet.g.alchemy.com"
        auth:
          kind: header
          name: "Authorization"
          scheme: "Bearer"
          token:
            val: "YOUR_ALCHEMY_API_KEY"
      quicknode:
        rpc_url: "https://YOUR-SLUG.sui-testnet.quiknode.pro"
        auth:
          kind: header
          name: "x-token"
          token:
            val: "YOUR_QUICKNODE_API_KEY"
  solana:
    timeout_sec: 30
    max_retries: 3
    expected_network_fingerprint: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
    providers:
      alchemy:
        rpc_url: "https://solana-devnet.g.alchemy.com/v2/{API_KEY}"
        auth:
          kind: path
          placeholder: "{API_KEY}"
          token:
            val: "YOUR_ALCHEMY_API_KEY"
      quicknode:
        rpc_url: "https://YOUR-SLUG.solana-devnet.quiknode.pro/{api_key}"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            val: "YOUR_QUICKNODE_API_KEY"
      tatum:
        rpc_url: "https://solana-devnet.gateway.tatum.io"
        auth:
          kind: header
          name: "x-api-key"
          token:
            val: "YOUR_TATUM_API_KEY"
  # BSC testnet (Chapel).
  bnb:
    timeout_sec: 30
    max_retries: 3
    expected_network_fingerprint: "97"
    providers:
      alchemy:
        rpc_url: "https://bnb-testnet.g.alchemy.com/v2/{API_KEY}"
        auth:
          kind: path
          placeholder: "{API_KEY}"
          token:
            val: "YOUR_ALCHEMY_API_KEY"
      quicknode:
        rpc_url: "https://YOUR-SLUG.bsc-testnet.quiknode.pro/{api_key}"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            val: "YOUR_QUICKNODE_API_KEY"
      tatum:
        rpc_url: "https://bsc-testnet.gateway.tatum.io"
        auth:
          kind: header
          name: "x-api-key"
          token:
            val: "YOUR_TATUM_API_KEY"
  base:
    timeout_sec: 30
    max_retries: 3
    expected_network_fingerprint: "84532"
    providers:
      alchemy:
        rpc_url: "https://base-sepolia.g.alchemy.com/v2/{API_KEY}"
        auth:
          kind: path
          placeholder: "{API_KEY}"
          token:
            val: "YOUR_ALCHEMY_API_KEY"
      quicknode:
        rpc_url: "https://YOUR-SLUG.base-sepolia.quiknode.pro/{api_key}"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            val: "YOUR_QUICKNODE_API_KEY"
      tatum:
        rpc_url: "https://base-sepolia.gateway.tatum.io"
        auth:
          kind: header
          name: "x-api-key"
          token:
            val: "YOUR_TATUM_API_KEY"
  arbitrum:
    timeout_sec: 30
    max_retries: 3
    expected_network_fingerprint: "421614"
    providers:
      alchemy:
        rpc_url: "https://arb-sepolia.g.alchemy.com/v2/{API_KEY}"
        auth:
          kind: path
          placeholder: "{API_KEY}"
          token:
            val: "YOUR_ALCHEMY_API_KEY"
      quicknode:
        rpc_url: "https://YOUR-SLUG.arbitrum-sepolia.quiknode.pro/{api_key}"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            val: "YOUR_QUICKNODE_API_KEY"
      tatum:
        rpc_url: "https://arbitrum-one-sepolia.gateway.tatum.io"
        auth:
          kind: header
          name: "x-api-key"
          token:
            val: "YOUR_TATUM_API_KEY"
  polygon:
    timeout_sec: 30
    max_retries: 3
    expected_network_fingerprint: "80002"
    providers:
      alchemy:
        rpc_url: "https://polygon-amoy.g.alchemy.com/v2/{API_KEY}"
        auth:
          kind: path
          placeholder: "{API_KEY}"
          token:
            val: "YOUR_ALCHEMY_API_KEY"
      quicknode:
        rpc_url: "https://YOUR-SLUG.matic-amoy.quiknode.pro/{api_key}"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            val: "YOUR_QUICKNODE_API_KEY"
      tatum:
        rpc_url: "https://polygon-amoy.gateway.tatum.io"
        auth:
          kind: header
          name: "x-api-key"
          token:
            val: "YOUR_TATUM_API_KEY"
  avalanche:
    timeout_sec: 30
    max_retries: 3
    expected_network_fingerprint: "43113"
    providers:
      public:
        rpc_url: "https://api.avax-test.network/ext/bc/C/rpc"
        auth:
          kind: none
      quicknode:
        rpc_url: "https://YOUR-SLUG.avalanche-testnet.quiknode.pro/{api_key}/ext/bc/C/rpc"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            val: "YOUR_QUICKNODE_API_KEY"
      tatum:
        rpc_url: "https://avax-testnet.gateway.tatum.io"
        auth:
          kind: header
          name: "x-api-key"
          token:
            val: "YOUR_TATUM_API_KEY"
  hyper_evm:
    timeout_sec: 30
    max_retries: 3
    expected_network_fingerprint: "998"
    providers:
      public:
        rpc_url: "https://rpc.hyperliquid-testnet.xyz/evm"
        auth:
          kind: none
      quicknode:
        rpc_url: "https://YOUR-SLUG.hype-testnet.quiknode.pro/{api_key}/evm"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            val: "YOUR_QUICKNODE_API_KEY"
      chainstack:
        rpc_url: "https://hyperliquid-testnet.core.chainstack.com/{API_KEY}/evm"
        auth:
          kind: path
          placeholder: "{API_KEY}"
          token:
            val: "YOUR_CHAINSTACK_API_KEY"
  fogo:
    timeout_sec: 30
    max_retries: 3
    expected_network_fingerprint: "9GGSFo95raqzZxWqKM5tGYvJp5iv4Dm565S4r8h5PEu9"
    providers:
      public:
        rpc_url: "https://testnet.fogo.io"
        auth:
          kind: none
```
