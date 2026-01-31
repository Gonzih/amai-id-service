// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "../AMAIIdentity.sol";

contract DeployAMAIIdentity is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("BASE_WALLET_PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        AMAIIdentity identity = new AMAIIdentity();

        console.log("AMAIIdentity deployed at:", address(identity));

        vm.stopBroadcast();
    }
}
