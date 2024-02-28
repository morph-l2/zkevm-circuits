const { BigNumber } = require("ethers")
const { ethers } = require('ethers');
const Token_Artifact = require("../src/abi/Token.json");

// This is a script for deploying your contracts. You can adapt it to deploy
// yours, or create new ones.
async function main() {

    ///prepare deployer
    // let privateKey = "0x1212121212121212121212121212121212121212121212121212121212121212";
    // let customHttpProvider = new ethers.providers.JsonRpcProvider(
    //     "http://localhost:6688"
    // );

    let privateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let customHttpProvider = new ethers.providers.JsonRpcProvider(
        "http://localhost:8545"
    );

    const signer = new ethers.Wallet(privateKey, customHttpProvider);
    console.log("signer.address: " + signer.address);


    ///deploy ERC20 Token
    let token = new ethers.Contract("0x70997970C51812dc3A010C7d01b50e0d17dc79C8", Token_Artifact.abi, signer);
    let tx = await token.transfer("0xa8c5B5E6b05589976887f9BCd37E6bbdDd8cd6b5", 10);
    console.log("tx: " + JSON.stringify(tx));

    await tx.wait();

    console.log("==============================");
    let receipt = await customHttpProvider.getTransactionReceipt(tx.hash);
    console.log("receipt: " + JSON.stringify(receipt));

    console.log("==============================");
    let balance = await token.balanceOf("0xa8c5B5E6b05589976887f9BCd37E6bbdDd8cd6b5");


    console.log("balance: " + balance);

}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
