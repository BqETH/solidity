import ethers from 'ethers';

const provider = new ethers.providers.JsonRpcProvider('http://localhost:8545'); // Hardhat

// Given an address and a range of blocks, query the Ethereum blockchain for the ETH balance across the range
async function getBalanceInRange(address, startBlock, endBlock) {
    // Number of points to fetch between block range
    var pointCount = 50;

    // Calculate the step size given the range of blocks and the number of points we want
    var step = Math.floor((endBlock - startBlock) / pointCount)
    // Make sure step is at least 1
    if (step < 1) {
        step = 1;
    }

    // Store the final result here
    var balances = []

    // Loop over the blocks, using the step value
    for (let i = startBlock; i <= endBlock; i = i + step) {
        // Get the ETH value at that block
        let wei = await provider.getBalance(address, i);
        let ether = parseFloat(wei/ethers.constants.WeiPerEther);
        let bl = await provider.getBlock(i);
        // Add result to final output 
        balances.push({
            block: i,
            balance: ether,
	    time: bl.timestamp
        });
    }

    return balances;
}

// Main function
async function graphBalance() {
    // Ethereum Address we want to look at
    var address = "0xBcd4042DE499D14e55001CcbB24a551F3b954096"

    // Find the initial range, from first block to current block
    // var startBlock = parseInt(await getFirstBlock(address));
    var startBlock = 0;
    var endBlock = await provider.getBlockNumber();

    var balances = await getBalanceInRange(address, startBlock, endBlock);
    console.log(balances)
}

graphBalance();

