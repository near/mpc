# Multichain Infrastructure Overview

## Environments

- Mainnet (Production)
- Testnet (Production)

## Deployment

### Mainnet/Testnet
#### Please keep in mind that this is a live environment, and any changes you make may also effect our ecosystem partners. Ensure your new changes are rigorously tested, and will not break mainnet/Testnet. This deployment is semi-automated.
### "Break Glass" Deployment of Production environment
#### **This should only be used if the environment is completely broken**
  - Deployment steps:
    1. Make sure you have [terraform installed](https://developer.hashicorp.com/terraform/install) on your local machine
    2. Navigate to the `infra` directory, and then the `partner-testnet` directory
    3. Verify the variables in both `resources.tf line 3` and `terraform-testnet-example.tfvars lines 2, 13-14` are up to date
    4. Run the `terraform init` command to initialize the infrastructure
    5. Run `terraform plan --var-file=terraform-testnet.tfvars` and ensure the changes are indeed what you want to change
    6. Run `terraform apply --var-file=terraform-testnet.tfvars`, This will replace the instance templates with new changes, and rebuild the VMs from scratch.
      - *Note: This will cause downtime, **MAKE SURE YOU ACTUALLY WANT TO DO THIS AND NOTIFY PARTNERS IN TELEGRAM CHANNEL "NEAR MPC Node Operators" If you don't have access to that telegram channel, you should probably not be doing this***
    7. Verify that the container has been started by ssh'ing to at least one of the VMs and running `docker ps`
    - *Note: use ```gcloud compute ssh multichain-testnet-partner-0``` or similar to ssh into machine, contact SRE if you have IAM issues*
*Note: [Detailed guide](https://docs.google.com/document/d/1trjDL1oP57lHN9ZdhIbSSpxKMWwUmiBUyri4XKlHiHE/edit?usp=sharing)