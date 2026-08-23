/**
 * Deployment script for BridgeLock and BridgeRelease
 * Usage:
 *   npx hardhat run deploy.js --network acquire-settlement
 *   npx hardhat run deploy.js --network mainnet
 */

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  const network = await ethers.provider.getNetwork();
  console.log("Network:", network.name, "Chain ID:", network.chainId);

  // Deploy BridgeLock on private chain (Acquire Settlement)
  if (network.chainId === 31338) {
    console.log("\n=== Deploying BridgeLock on Acquire Settlement ===");
    const BridgeLock = await ethers.getContractFactory("BridgeLock");
    const bridgeLock = await BridgeLock.deploy(deployer.address);
    await bridgeLock.deployed();
    console.log("BridgeLock deployed to:", bridgeLock.address);
    return { bridgeLock: bridgeLock.address };
  }

  // Deploy BridgeRelease on mainnet
  if (network.chainId === 1) {
    console.log("\n=== Deploying BridgeRelease on Ethereum Mainnet ===");
    
    // IMPORTANT: Replace with your actual relay address (the Go relay operator)
    const relayAddress = process.env.RELAY_ADDRESS || deployer.address;
    console.log("Relay address:", relayAddress);

    const BridgeRelease = await ethers.getContractFactory("BridgeRelease");
    const bridgeRelease = await BridgeRelease.deploy(relayAddress, deployer.address);
    await bridgeRelease.deployed();
    console.log("BridgeRelease deployed to:", bridgeRelease.address);
    return { bridgeRelease: bridgeRelease.address };
  }

  console.error("Unsupported chain ID:", network.chainId);
  process.exit(1);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
