// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// You can also run a script with `npx hardhat run <script>`. If you do that, Hardhat
// will compile your contracts, add the Hardhat Runtime Environment's members to the
// global scope, and execute the script.
const hre = require("hardhat");
const { BigNumber } = require("ethers");

async function main() {
    const [signer] = await hre.ethers.getSigners();
    console.log("got the signer: ", signer.address)

    const Token = await hre.ethers.getContractFactory("Token");
    const token = await Token.deploy(BigNumber.from(10 ** 12).mul(BigNumber.from(10 ** 6)));
    const contract = await token.deployed();
    console.log("deployed contract address: ", contract.address);

}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });