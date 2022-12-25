import * as dotenv from 'dotenv';

import { HardhatUserConfig, task } from 'hardhat/config';
import '@nomiclabs/hardhat-etherscan';
import '@nomiclabs/hardhat-waffle';
import '@typechain/hardhat';
import 'hardhat-gas-reporter';
import 'solidity-coverage';
import "@tovarishfin/hardhat-yul";

import './tasks/deploy';
import { bufferToHex, privateToAddress, toBuffer, toChecksumAddress } from "@nomicfoundation/ethereumjs-util";

dotenv.config();

// This is a sample Hardhat task. To learn how to create your own go to https://hardhat.org/guides/create-task.html
task('accounts', 'Prints the list of accounts', async (taskArgs, hre) => {
  const accounts = await hre.ethers.getSigners();

  for (const account of accounts) {
    const bal = await account.getBalance();
    console.log(account.address + ':' + bal);
    console.log();
  }
});


task("bqeth-deploy", "Deploys BqETH , get wallets, and outputs files", async (taskArgs, hre) => {
  // We get the contract to deploy
  const BqETH = await hre.ethers.getContractFactory("BqETH");
  const bqeth = await BqETH.deploy();

  // Await deployment
  await bqeth.deployed();

  // Get address
  const contractAddress = bqeth.address;

  // Write file
  //fs.writeFileSync('./.contract', contractAddress);

  // Get generated signer wallets
  const accounts = await hre.ethers.getSigners();

  // Get the first wallet address
  const walletAddress = accounts[0].address;

  // Write file
  //fs.writeFileSync('./.wallet', walletAddress);
});

// You need to export an object to set up your config
// Go to https://hardhat.org/config/ to learn more

const config: HardhatUserConfig = {
  solidity: '0.8.8',
  paths: {
    artifacts: './artifacts'
  },
  networks: {
    hardhat: {
      chainId: 1337,
      allowUnlimitedContractSize: true
    },
    ropsten: {
      url: process.env.ROPSTEN_URL || '',
      accounts:
        process.env.TEST_ETH_ACCOUNT_PRIVATE_KEY !== undefined
          ? [process.env.TEST_ETH_ACCOUNT_PRIVATE_KEY]
          : []
    }
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS !== undefined,
    currency: 'USD'
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY
  }
};

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  solidity: '0.8.4',
  networks: {
    hardhat: {
      chainId: 1337,
      allowUnlimitedContractSize: true
    },
  },
};

export default config;
