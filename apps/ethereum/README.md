# Safe Ethereum Contracts Deployment


## 1 Deploy Safe Singleton Factory

- Run `git clone https://github.com/MixinNetwork/safe-singleton-factory`
- Run `yarn install`
- Set `RPC` in the `.env` file for the network.
- Set `MNEMONIC` in the `.env` file
- Run `yarn estimate-compile`
- Run `yarn submit`

The deployment information will be saved in `safe-singleton-factory/artifacts/<chain_id>/deployment.json`.

To deploy safe contracts in the next step, it's better to push changes of `artifacts` folder to your own fork.


## 2 Deploy Safe Contracts

- Run `git clone https://github.com/safe-global/safe-contracts.git` 
- Run `git checkout feature/mixin-safe-guard` (contracts version: v1.4.1)
- Run `yarn install` (Do this every time before deploying contracts if `@gnosis.pm/safe-singleton-factory` in package.json is your own fork)
- Set `MNEMONIC` in the `.env` file
- Set `CUSTOM_DETERMINISTIC_DEPLOYMENT = true` in the `.env` file
- Run `rm -r deployments` if needed

### For custom network like mvm
- Set `NODE_URL` in the `.env` file for the network.
- Run `yarn deploy-all custom`

### For infura based network
- Set `INFURA_KEY` in `.env`
- Run `yarn deploy-all <network>`


For some networks or custom network, you might need to add network rpc host in the `submitSources` function of `node_modules/hardhat-deploy/dist/src/etherscan.js` in contract verification step.
```
// add mvm rpc host
case '73927':
    host = 'https://scan.mvm.dev';
    break;
```