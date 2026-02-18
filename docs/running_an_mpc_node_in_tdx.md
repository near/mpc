# Deploy an MPC node within a TEE

This document describes the steps to deploy an MPC node within a TEE. Its
expected audience is Near One engineers because it uses internal infrastructure.

## Steps

1. Provision a TDX server.
2. Install dstack components and start core dstack services.
3. Deploy an MPC node within dstack.
4. Observe the public data for the MPC node

### 1. Provision a TDX server

To run the MPC node within a TEE, you need a TDX-enabled server. There are
several providers to choose from, such as
[phoenixNap](https://phoenixnap.com/), [OVHcloud](https://www.ovhcloud.com/),
[openmetal](https://openmetal.io/) and
[Hivelocity](https://www.hivelocity.net/), to name a few.  

1. SSH to Near's TDX dev machine. In this case we will use `TDX_SERVER=91.134.92.20`

   ```bash
   ssh USER_NAME@TDX_SERVER
   ```

2. Add your user to the `kvm` group:

   ```bash
   sudo usermod -a -G kvm USER_NAME
   ```

### 2. Install dstack and start core services

1. Go to the data directory (`/mnt/data/` assuming you are on one of our TDX
   servers)
2. Follow the commands below

   Create a directory with a unique name for installation of dstack. For
   example, your username

   ```bash
   mkdir /mnt/data/WORKING_DIRECTORY_NAME
   ```

   Give your own user ownership of the directory

   ```bash
   sudo chown USER_NAME:USER_NAME WORKING_DIRECTORY_NAME/
   ```

   Enter directory

   ```bash
   cd WORKING_DIRECTORY_NAME/
   ```

3. Follow the instructions in
   [Dstack's Getting Started section in their README](https://github.com/Dstack-TEE/dstack?tab=readme-ov-file#-getting-started)
   until before
   [step 2](https://github.com/Dstack-TEE/dstack?tab=readme-ov-file#2-download-or-build-guest-image).
   At this point your current directory should be `WORKING_DIRECTORY_NAME/meta-dstack/build/`.
   Download the development version of the `0.5.2` by running:

   ```bash
   # This will download the guest image from the release page.
   ../build.sh dl -dev 0.5.2
   ```

4. Once it's installed you need to run `dstack-vmm` and `dstack-kms`. It's
   important these keep running persistently. You can use `tmux` for this
   purpose:

   Run Dstack key management service:

   ```bash
   # Start a new tmux session
   tmux new -s dstack
   ```

   ```bash
   # Run dstack-kms
   ./dstack-kms -c kms.toml
   ```

   Open new tmux panel with `Ctrl+B` then `%`

   Run Dstack Virtual Machine Manager:

   ```bash
   ./dstack-vmm -c vmm.toml
   ```

   Look for the log where it shows the localhost + port the VMM is running on. In
   this case `VMM_PORT=16040`. It should look something like:

   ```log
   2025-07-22T20:04:51.818701Z  INFO rocket::rkt: endpoint=http://127.0.0.1:16040
   ```

   Detach with `Ctrl+B` then `D`. To reattach later you can run:

   ```bash
   tmux attach -t dstack
   ```

   Port forward the port VMM is running on from the TDX host to your local machine.

   ```bash
   ssh -NL 8080:localhost:VMM_PORT USER_NAME@TDX_SERVER
   ```

### 3. Deploy an MPC node within dstack

1. Go to the url the `dstack-vmm` is running on `http://localhost:VMM_PORT`
2. Click `Deploy a new instance` button on the top left.
3. Fill in the form

   - name: `mpc_tee_test` (this parameter can be selected at will)
   - image: `dstack-dev-0.5.2`
   - 8 CPUs
   - 64GiB Memory
   - 200GiB Storage

4. Docker Compose File

   Modify the following variables accordingly and replace their values in the
   docker compose file template below:

   ```bash
   MPC_ACCOUNT_ID=mpc-3-barak-launch1-b654bfa0a52e.5035bf56abb0.testnet
   MPC_LOCAL_ADDRESS=127.0.0.1
   MPC_SECRET_STORE_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
   MPC_CONTRACT_ID=mpc-contract-barak-launch1-4c5e2fe1fb42.5035bf56abb0.testnet
   MPC_ENV=testnet
   MPC_HOME_DIR=/data
   RUST_BACKTRACE=full
   RUST_LOG=mpc=debug,info
   NEAR_BOOT_NODES=ed25519:9qyu1RaJ5shX6UEb7UooPQYVXCC1tNHCiDPPxJ8Pv1UJ@116.202.220.238:34567,ed25519:8mzYnfuT5zQYqV99CfYAX6XoRmNxVJ1nAZHXXW4GrFD@34.221.144.70:24567,ed25519:B87Qq34LbWadFx2dq5bwUEtB5KBgr8ZhsoEpAiSP2qVX@142.132.203.80:24567,ed25519:EufXMhFVixgFpg2bBaHGL4Zrks1DDrhAZTQYwbjRTAUX@65.109.25.109:24567,ed25519:HJJde5skATXLA4wGk8P9awvfzaW47tCU2EsRXnMoFRA9@129.150.39.19:24567,ed25519:BavpjuYrnXRFQVWjLdx9vx9vAvanit9NhhcPeM6gjAkE@95.217.198.233:24567,ed25519:81zk9MvvoxB1AzTW721o9m2NeYx3pDFDZyRJUQej65uc@195.14.6.172:24567,ed25519:E4gQXBovauvqxx85TdemezhkDDsAsqEL7ZJ4cp5Cdhsb@129.80.119.109:24567,ed25519:6cWtXFAzqpZ8D7EpLGYBmkw95oKYkzN8i99UcRgsyRMy@164.132.247.155:24567,ed25519:CLnWy9xv2GUqfgepzLwpv4bozj3H3kgzjbVREyS6wcqq@47.242.112.172:24567,ed25519:2NmT9Wy9HGBmH8sTWSq2QfaMk4R8ZHBEhk8ZH4g4f1Qk@65.109.88.175:24567,ed25519:9dhPYd1ArZ6mTMP7nnRzm8JBPwKCaBxiYontS5KfXz5h@34.239.1.54:24567,ed25519:8iiQH4vtqsqWgsm4ypCJQQwqJR3AGp9o7F69YRaCHKxA@141.95.204.11:24567,ed25519:4L97JnFFFVbfE8M3tY9bRtgV5376y5dFH8cSaoBDRWnK@5.199.170.103:24567,ed25519:DGJ91V2wJ8NFpkqZvphtSeM4CBeiLsrHGdinTugiRoFF@52.35.74.212:24567,ed25519:B9LSvCTimoEUtuUvpfu1S54an54uTetVabmkT5dELUCN@91.134.22.129:24567,ed25519:cRGmtzkkSZT6wXNjbthSXMD6dHrEgSeDtiEJAcnLLxH@15.204.213.166:24567
   IMAGE_TAG=main-f81318b-tee
   IMAGE_HASH=5ba283860c0efa3d4c3e08a76a2b77fab4725baad4f48504eac858e04af7fd64
   MPC_RESPONDER_ID=mpc-responder-2-barak-launch1-cdd0fd949a48.5035bf56abb0.testnet
   MPC_NODE_0=mpc-node-0.service.mpc.consul=35.185.233.54
   MPC_NODE_1=mpc-node-1.service.mpc.consul=34.168.117.59
   ```

   Several values in the previous file can be modified:
      - `IMAGE_TAG` and `IMAGE_HASH`: Find a docker image of the MPC node in
      [mpc-node-gcp/tags](https://hub.docker.com/r/nearone/mpc-node-gcp/tags). Images with
      suffix `-tee` are TEE enabled. The latest image should be `IMAGE_TAG=latest-tee`. To obtain the `IMAGE-HASH` execute:

      ```bash
      docker pull nearone/mpc-node-gcp:IMAGE_TAG
      docker inspect nearone/mpc-node-gcp:IMAGE_TAG | jq .[0].Id
      ```

      - `NEAR_BOOT_NODES`: can be obtained executing

      ```bash
      curl -s -X POST https://rpc.testnet.near.org -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "network_info","params": [], "id": "dontcare"}'| jq -r '.result.active_peers | unique_by(.addr) | unique_by(.id) | map("\(.id)@\(.addr)") | .[]' | paste -sd',' -
      ```

   ```yml
   services:
      mpc-node:
         image: nearone/mpc-node-gcp:$IMAGE_TAG
         container_name: mpc-node
         network_mode: "host"
         restart: unless-stopped

         volumes:
            - mpc-data:/data
            - shared-volume:/mnt/shared
            - /:/host/
            - /var/run/tappd.sock:/var/run/tappd.sock
            - /var/run/dstack.sock:/var/run/dstack.sock
         environment:
            - MPC_HOME_DIR=/data
            - MPC_ACCOUNT_ID=$MPC_ACCOUNT_ID
            - MPC_LOCAL_ADDRESS=$MPC_LOCAL_ADDRESS
            - MPC_SECRET_STORE_KEY=$MPC_SECRET_STORE_KEY
            - MPC_CONTRACT_ID=$MPC_CONTRACT_ID
            - MPC_ENV=$MPC_ENV
            - MPC_HOME_DIR=$MPC_HOME_DIR
            - NEAR_BOOT_NODES=$NEAR_BOOT_NODES
            - RUST_BACKTRACE=$RUST_BACKTRACE
            - RUST_LOG=$RUST_LOG
            - MPC_RESPONDER_ID=$MPC_RESPONDER_ID
            - IMAGE_HASH=$IMAGE_HASH
            - LATEST_ALLOWED_HASH_FILE=/mnt/shared/image-digest.bin

         extra_hosts:
            - "$MPC_NODE_0"
            - "$MPC_NODE_1"

   volumes:
      mpc-data:
      shared-volume:
   ```

   If the env variables are saved in a file as `vars.env` and the docker compose template
   as `template.yaml`, then executing the following will create the final docker compose file:

   ```bash
   set -a; source vars.env; set +a; envsubst < template.yaml > app_compose.yaml
   ```

   Upload the `app_compose.yaml` created above to the vm creator.

5. Port forwarding

   You will need to do port forwarding of port `8080` and `8090` on the VM. Port
   `8080` will be needed to forward to Find open ports on the host that can be
   mapped top the two ports `8080` and `8090` on the VM. In this example we will
   map `17190`:`8090` and `17180`:`8080` as these ports (`17190` and `17180`) were
   free. You can check if a port is free on the host with:

   ```bash
   ss -tuln | grep :PORT_NUMBER
   ```

   You will also need to port forward the host machine port to your local machine
   such that you can access them remotely. Execute this in your own machine

   ```bash
   ssh -NL 8081:localhost:17180 USER_NAME@TDX_SERVER
   # and in another shell
   ssh -NL 8090:localhost:17190 USER_NAME@TDX_SERVER
   ```

   If you want to have ssh access to the VM, you can do the same with port `22` on the VM,
   for example by adding the map `17022`:`22`. This will allow you to log into the VM from the TDX server using:

   ```bash
   ssh root@localhost -p 17022
   ```

   Once inside the VM it is possible to call the dstack curl [API endpoints](https://github.com/Dstack-TEE/dstack/blob/c41c17d465b6f0a213e091d677699181b9ba75ca/sdk/curl/api.md#endpoints), for example:

   ```bash
   curl --unix-socket /var/run/dstack.sock -X POST -H "Content-Type: application/json" -d '{}' http://localhost/Info
   ```

6. Activate features
   Only activate the following features:

   - KMS
   - Public Logs
   - Public Sysinfo
   - Public TCB Info

   In production we plan to use SGX instead of KMS

7. Encrypted Environment Variables

   We will not use them as they would require KMS.

8. Click on deploy

### 4. Observe the public data for the MPC node

Now data of the MPC node deployed can be accessed on your local machine:

1. Go to the VM list in <http://localhost:8090>. Click on the "View logs button"

2. Wait for the MPC node to start. It will take a few minutes for the near
   indexer to start, before the web endpoint is up

3. Go to <http://localhost:8081/public_data>. You now have access to all public data to the
   MPC node running in TEE
