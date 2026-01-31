// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../AMAIIdentity.sol";

contract AMAIIdentityTest is Test {
    AMAIIdentity public identity;
    address public owner;
    address public oracle;
    address public agent1;
    address public agent2;

    function setUp() public {
        owner = address(this);
        oracle = makeAddr("oracle");
        agent1 = makeAddr("agent1");
        agent2 = makeAddr("agent2");

        identity = new AMAIIdentity();
    }

    // ============ Deployment Tests ============

    function test_Deployment() public view {
        assertEq(identity.name(), "AMAI Agent Identity");
        assertEq(identity.symbol(), "AMAI");
        assertEq(identity.owner(), owner);
    }

    function test_ContractVersion() public view {
        assertEq(identity.CONTRACT_VERSION(), "1.0.0");
        assertEq(identity.CONTRACT_VERSION_NUMBER(), 1_000_000);
    }

    function test_Constants() public view {
        assertEq(identity.TRUST_PRECISION(), 100);
        assertEq(identity.MAX_TRUST_SCORE(), 10000);
        assertEq(identity.INITIAL_TRUST_SCORE(), 5000);
    }

    // ============ Minting Tests ============

    function test_MintAgent() public {
        uint256 tokenId = identity.mintAgent(agent1, "TestAgent", "https://agent.example.com");

        assertEq(tokenId, 1);
        assertEq(identity.ownerOf(tokenId), agent1);
        assertEq(identity.totalAgents(), 1);

        AMAIIdentity.AgentMetadata memory agent = identity.getAgent(tokenId);
        assertEq(agent.name, "TestAgent");
        assertEq(agent.serviceEndpoint, "https://agent.example.com");
        assertEq(agent.trustScore, 5000); // Initial trust
        assertEq(agent.actionCount, 0);
        assertEq(agent.confirmedCount, 0);
        assertTrue(agent.isActive);
        assertEq(agent.registrationVersion, 1_000_000);
    }

    function test_MintAgent_EmitsEvent() public {
        vm.expectEmit(true, true, false, true);
        emit AMAIIdentity.AgentMinted(1, agent1, "TestAgent", "https://agent.example.com", 1_000_000);

        identity.mintAgent(agent1, "TestAgent", "https://agent.example.com");
    }

    function test_MintAgent_RevertIfDuplicate() public {
        identity.mintAgent(agent1, "Agent1", "https://a.com");

        vm.expectRevert("Address already has an agent");
        identity.mintAgent(agent1, "Agent2", "https://b.com");
    }

    function test_MintAgent_RevertIfNotOwner() public {
        vm.prank(agent1);
        vm.expectRevert();
        identity.mintAgent(agent2, "Test", "https://test.com");
    }

    function test_MintAgent_RevertIfNameEmpty() public {
        vm.expectRevert("Invalid name length");
        identity.mintAgent(agent1, "", "https://test.com");
    }

    function test_MintAgent_RevertIfNameTooLong() public {
        string memory longName = "This is a very long name that exceeds the sixty four character limit for agent names";
        vm.expectRevert("Invalid name length");
        identity.mintAgent(agent1, longName, "https://test.com");
    }

    // ============ Soulbound Tests ============

    function test_Soulbound_NoTransfer() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");

        vm.prank(agent1);
        vm.expectRevert("AMAIIdentity: soulbound token cannot be transferred");
        identity.transferFrom(agent1, agent2, 1);
    }

    function test_Soulbound_NoApprove() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");

        vm.prank(agent1);
        vm.expectRevert("AMAIIdentity: soulbound token cannot be approved");
        identity.approve(agent2, 1);
    }

    function test_Soulbound_NoApprovalForAll() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");

        vm.prank(agent1);
        vm.expectRevert("AMAIIdentity: soulbound token cannot be approved");
        identity.setApprovalForAll(agent2, true);
    }

    // ============ Oracle Tests ============

    function test_AuthorizeOracle() public {
        identity.authorizeOracle(oracle);
        assertTrue(identity.authorizedOracles(oracle));
    }

    function test_RevokeOracle() public {
        identity.authorizeOracle(oracle);
        identity.revokeOracle(oracle);
        assertFalse(identity.authorizedOracles(oracle));
    }

    function test_AuthorizeOracle_RevertIfNotOwner() public {
        vm.prank(agent1);
        vm.expectRevert();
        identity.authorizeOracle(oracle);
    }

    // ============ Trust Score Tests ============

    function test_UpdateTrustScore() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");
        identity.authorizeOracle(oracle);

        vm.prank(oracle);
        identity.updateTrustScore(1, 7500, "platform_confirm");

        assertEq(identity.getTrustScore(1), 7500);
    }

    function test_UpdateTrustScore_EmitsEvent() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");
        identity.authorizeOracle(oracle);

        vm.expectEmit(true, false, false, true);
        emit AMAIIdentity.TrustScoreUpdated(1, 5000, 7500, "test");

        vm.prank(oracle);
        identity.updateTrustScore(1, 7500, "test");
    }

    function test_UpdateTrustScore_RevertIfNotOracle() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");

        vm.prank(agent1);
        vm.expectRevert("Not authorized oracle");
        identity.updateTrustScore(1, 7500, "unauthorized");
    }

    function test_UpdateTrustScore_RevertIfExceedsMax() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");
        identity.authorizeOracle(oracle);

        vm.prank(oracle);
        vm.expectRevert("Score exceeds maximum");
        identity.updateTrustScore(1, 10001, "too_high");
    }

    // ============ Trust Delta Tests ============

    function test_ApplyTrustDelta_Positive() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");
        identity.authorizeOracle(oracle);

        // Starting at 5000, delta +1000 with logistic curve
        // headroom = 10000 - 5000 = 5000
        // scaled = 1000 * 5000 / 10000 = 500
        // new = 5000 + 500 = 5500
        vm.prank(oracle);
        identity.applyTrustDelta(1, 1000, "good_action");

        assertEq(identity.getTrustScore(1), 5500);
    }

    function test_ApplyTrustDelta_Negative() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");
        identity.authorizeOracle(oracle);

        // Starting at 5000, delta -1000 with logistic curve
        // scaled = 1000 * 5000 / 10000 = 500
        // new = 5000 - 500 = 4500
        vm.prank(oracle);
        identity.applyTrustDelta(1, -1000, "bad_action");

        assertEq(identity.getTrustScore(1), 4500);
    }

    function test_ApplyTrustDelta_HighScore_HarderToGain() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");
        identity.authorizeOracle(oracle);

        // Set to 9000
        vm.prank(oracle);
        identity.updateTrustScore(1, 9000, "setup");

        // At 9000, delta +1000:
        // headroom = 10000 - 9000 = 1000
        // scaled = 1000 * 1000 / 10000 = 100
        // new = 9000 + 100 = 9100
        vm.prank(oracle);
        identity.applyTrustDelta(1, 1000, "good_action");

        assertEq(identity.getTrustScore(1), 9100);
    }

    // ============ Action Recording Tests ============

    function test_RecordAction() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");
        identity.authorizeOracle(oracle);

        vm.prank(oracle);
        identity.recordAction(1);

        AMAIIdentity.AgentMetadata memory agent = identity.getAgent(1);
        assertEq(agent.actionCount, 1);
    }

    function test_RecordConfirmation() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");
        identity.authorizeOracle(oracle);

        vm.prank(oracle);
        identity.recordConfirmation(1);

        AMAIIdentity.AgentMetadata memory agent = identity.getAgent(1);
        assertEq(agent.confirmedCount, 1);
    }

    function test_ConfirmationRate() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");
        identity.authorizeOracle(oracle);

        // 4 actions, 3 confirmed = 75%
        vm.startPrank(oracle);
        identity.recordAction(1);
        identity.recordAction(1);
        identity.recordAction(1);
        identity.recordAction(1);
        identity.recordConfirmation(1);
        identity.recordConfirmation(1);
        identity.recordConfirmation(1);
        vm.stopPrank();

        // 3/4 = 0.75 = 7500 (scaled by 10000)
        assertEq(identity.getConfirmationRate(1), 7500);
    }

    // ============ Version Tests ============

    function test_GetContractInfo() public view {
        (
            string memory version,
            uint256 versionNumber,
            uint256 chainId,
            address contractAddress,
            string memory tokenName,
            string memory tokenSymbol
        ) = identity.getContractInfo();

        assertEq(version, "1.0.0");
        assertEq(versionNumber, 1_000_000);
        assertTrue(chainId > 0);
        assertEq(contractAddress, address(identity));
        assertEq(tokenName, "AMAI Agent Identity");
        assertEq(tokenSymbol, "AMAI");
    }

    function test_IsLatestVersion() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");
        assertTrue(identity.isLatestVersion(1));
    }

    function test_GetAgentWithVersionInfo() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");

        (
            AMAIIdentity.AgentMetadata memory agent,
            uint256 currentVersion,
            uint256 versionsBehind
        ) = identity.getAgentWithVersionInfo(1);

        assertEq(agent.name, "TestAgent");
        assertEq(currentVersion, 1_000_000);
        assertEq(versionsBehind, 0);
    }

    // ============ Deactivation Tests ============

    function test_DeactivateAgent() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");
        identity.deactivateAgent(1);

        AMAIIdentity.AgentMetadata memory agent = identity.getAgent(1);
        assertFalse(agent.isActive);
    }

    function test_DeactivateAgent_RevertIfNotOwner() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");

        vm.prank(agent1);
        vm.expectRevert();
        identity.deactivateAgent(1);
    }

    function test_DeactivateAgent_RevertIfAlreadyInactive() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");
        identity.deactivateAgent(1);

        vm.expectRevert("Already inactive");
        identity.deactivateAgent(1);
    }

    function test_UpdateTrustScore_RevertIfInactive() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");
        identity.authorizeOracle(oracle);
        identity.deactivateAgent(1);

        vm.prank(oracle);
        vm.expectRevert("Agent is not active");
        identity.updateTrustScore(1, 7500, "should_fail");
    }

    // ============ Token URI Tests ============

    function test_TokenURI() public {
        identity.mintAgent(agent1, "TestAgent", "https://test.com");

        string memory uri = identity.tokenURI(1);
        assertTrue(bytes(uri).length > 0);
        // Should be a data URI
        assertTrue(bytes(uri).length > 30);
    }
}
