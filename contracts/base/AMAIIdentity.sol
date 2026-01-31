// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

/**
 * @title AMAIIdentity
 * @dev Soulbound Token (SBT) for AMAI agent identities with on-chain trust scores
 * @notice Non-transferable NFTs representing agent identity and reputation
 *
 * Trust Score Mechanics:
 * - Score range: 0-100 (scaled by 100 for precision, so 0-10000)
 * - Initial score: 50.00 (5000)
 * - Updated by authorized oracles based on platform confirmations
 * - Logistic curve prevents gaming (harder to gain at extremes)
 *
 * Versioning:
 * - Contract version tracked for upgrade compatibility
 * - Each agent records the contract version at registration time
 * - Agents can query current vs their registration version
 */
contract AMAIIdentity is ERC721, Ownable, ReentrancyGuard {
    using Strings for uint256;

    // Contract versioning
    string public constant CONTRACT_VERSION = "1.0.0";
    uint256 public constant CONTRACT_VERSION_NUMBER = 1_000_000; // 1.0.0 = 1_000_000

    // Trust score precision (2 decimal places)
    uint256 public constant TRUST_PRECISION = 100;
    uint256 public constant MAX_TRUST_SCORE = 100 * TRUST_PRECISION; // 10000 = 100.00
    uint256 public constant INITIAL_TRUST_SCORE = 50 * TRUST_PRECISION; // 5000 = 50.00

    // Agent metadata
    struct AgentMetadata {
        string name;
        string serviceEndpoint;  // URL to agent's API
        uint256 trustScore;      // 0-10000 (0.00-100.00)
        uint256 actionCount;     // Total actions recorded
        uint256 confirmedCount;  // Actions confirmed by platforms
        uint256 createdAt;
        uint256 lastActive;
        bool isActive;
        uint256 registrationVersion; // Contract version at time of registration
    }

    // Trust score update event
    struct TrustUpdate {
        int256 delta;           // Change in trust score
        string reason;          // "platform_confirm", "oracle_discrepancy", "admin_adjustment"
        uint256 timestamp;
    }

    // Storage
    mapping(uint256 => AgentMetadata) public agents;
    mapping(address => uint256) public ownerToAgent;
    mapping(address => bool) public authorizedOracles;

    uint256 private _nextTokenId;
    string private _baseTokenURI;

    // Events
    event AgentMinted(uint256 indexed tokenId, address indexed owner, string name, string serviceEndpoint, uint256 contractVersion);
    event TrustScoreUpdated(uint256 indexed tokenId, uint256 oldScore, uint256 newScore, string reason);
    event ActionRecorded(uint256 indexed tokenId, uint256 actionCount);
    event ActionConfirmed(uint256 indexed tokenId, uint256 confirmedCount);
    event AgentDeactivated(uint256 indexed tokenId);
    event OracleAuthorized(address indexed oracle);
    event OracleRevoked(address indexed oracle);

    constructor() ERC721("AMAI Agent Identity", "AMAI") Ownable(msg.sender) {
        _nextTokenId = 1;
    }

    // ============ MODIFIERS ============

    modifier onlyOracle() {
        require(authorizedOracles[msg.sender] || msg.sender == owner(), "Not authorized oracle");
        _;
    }

    modifier agentExists(uint256 tokenId) {
        require(_ownerOf(tokenId) != address(0), "Agent does not exist");
        _;
    }

    // ============ ORACLE MANAGEMENT ============

    function authorizeOracle(address oracle) external onlyOwner {
        authorizedOracles[oracle] = true;
        emit OracleAuthorized(oracle);
    }

    function revokeOracle(address oracle) external onlyOwner {
        authorizedOracles[oracle] = false;
        emit OracleRevoked(oracle);
    }

    // ============ MINTING ============

    /**
     * @dev Mint a new agent identity SBT
     * @param to Address that will own the agent
     * @param name Display name of the agent
     * @param serviceEndpoint URL to agent's service (e.g., https://agent.example.com)
     * @return tokenId The minted token ID
     */
    function mintAgent(
        address to,
        string memory name,
        string memory serviceEndpoint
    ) external onlyOwner nonReentrant returns (uint256) {
        require(ownerToAgent[to] == 0, "Address already has an agent");
        require(bytes(name).length > 0 && bytes(name).length <= 64, "Invalid name length");

        uint256 tokenId = _nextTokenId++;
        _mint(to, tokenId);

        agents[tokenId] = AgentMetadata({
            name: name,
            serviceEndpoint: serviceEndpoint,
            trustScore: INITIAL_TRUST_SCORE,
            actionCount: 0,
            confirmedCount: 0,
            createdAt: block.timestamp,
            lastActive: block.timestamp,
            isActive: true,
            registrationVersion: CONTRACT_VERSION_NUMBER
        });

        ownerToAgent[to] = tokenId;

        emit AgentMinted(tokenId, to, name, serviceEndpoint, CONTRACT_VERSION_NUMBER);
        emit TrustScoreUpdated(tokenId, 0, INITIAL_TRUST_SCORE, "initial");

        return tokenId;
    }

    // ============ TRUST SCORE MANAGEMENT ============

    /**
     * @dev Update trust score (oracle only)
     * @param tokenId Agent token ID
     * @param newScore New trust score (0-10000)
     * @param reason Reason for update
     */
    function updateTrustScore(
        uint256 tokenId,
        uint256 newScore,
        string memory reason
    ) external onlyOracle agentExists(tokenId) {
        require(newScore <= MAX_TRUST_SCORE, "Score exceeds maximum");
        require(agents[tokenId].isActive, "Agent is not active");

        uint256 oldScore = agents[tokenId].trustScore;
        agents[tokenId].trustScore = newScore;
        agents[tokenId].lastActive = block.timestamp;

        emit TrustScoreUpdated(tokenId, oldScore, newScore, reason);
    }

    /**
     * @dev Record an action (increments action count)
     * @param tokenId Agent token ID
     */
    function recordAction(uint256 tokenId) external onlyOracle agentExists(tokenId) {
        require(agents[tokenId].isActive, "Agent is not active");

        agents[tokenId].actionCount++;
        agents[tokenId].lastActive = block.timestamp;

        emit ActionRecorded(tokenId, agents[tokenId].actionCount);
    }

    /**
     * @dev Record a platform confirmation (increments confirmed count)
     * @param tokenId Agent token ID
     */
    function recordConfirmation(uint256 tokenId) external onlyOracle agentExists(tokenId) {
        require(agents[tokenId].isActive, "Agent is not active");

        agents[tokenId].confirmedCount++;
        agents[tokenId].lastActive = block.timestamp;

        emit ActionConfirmed(tokenId, agents[tokenId].confirmedCount);
    }

    /**
     * @dev Apply trust delta using logistic curve
     * @param tokenId Agent token ID
     * @param delta Trust change (positive or negative, scaled by TRUST_PRECISION)
     * @param reason Reason for adjustment
     */
    function applyTrustDelta(
        uint256 tokenId,
        int256 delta,
        string memory reason
    ) external onlyOracle agentExists(tokenId) {
        require(agents[tokenId].isActive, "Agent is not active");

        uint256 oldScore = agents[tokenId].trustScore;
        uint256 newScore;

        if (delta >= 0) {
            // Positive delta - harder to gain at high scores
            uint256 headroom = MAX_TRUST_SCORE - oldScore;
            uint256 scaledDelta = (uint256(delta) * headroom) / MAX_TRUST_SCORE;
            newScore = oldScore + scaledDelta;
        } else {
            // Negative delta - harder to lose at low scores
            uint256 absoDelta = uint256(-delta);
            uint256 scaledDelta = (absoDelta * oldScore) / MAX_TRUST_SCORE;
            newScore = oldScore > scaledDelta ? oldScore - scaledDelta : 0;
        }

        agents[tokenId].trustScore = newScore;
        agents[tokenId].lastActive = block.timestamp;

        emit TrustScoreUpdated(tokenId, oldScore, newScore, reason);
    }

    // ============ AGENT MANAGEMENT ============

    /**
     * @dev Update agent service endpoint
     * @param tokenId Agent token ID
     * @param newEndpoint New service endpoint URL
     */
    function updateServiceEndpoint(uint256 tokenId, string memory newEndpoint) external {
        require(ownerOf(tokenId) == msg.sender, "Not the agent owner");
        require(agents[tokenId].isActive, "Agent is not active");

        agents[tokenId].serviceEndpoint = newEndpoint;
        agents[tokenId].lastActive = block.timestamp;
    }

    /**
     * @dev Deactivate an agent (admin only)
     * @param tokenId Agent token ID
     */
    function deactivateAgent(uint256 tokenId) external onlyOwner agentExists(tokenId) {
        require(agents[tokenId].isActive, "Already inactive");

        agents[tokenId].isActive = false;
        emit AgentDeactivated(tokenId);
    }

    // ============ VIEW FUNCTIONS ============

    /**
     * @dev Get agent metadata
     */
    function getAgent(uint256 tokenId) external view agentExists(tokenId) returns (AgentMetadata memory) {
        return agents[tokenId];
    }

    /**
     * @dev Get trust score (human-readable format with 2 decimals)
     * @return score Trust score (0-10000 representing 0.00-100.00)
     */
    function getTrustScore(uint256 tokenId) external view agentExists(tokenId) returns (uint256) {
        return agents[tokenId].trustScore;
    }

    /**
     * @dev Get confirmation rate (percentage, 2 decimals)
     * @return rate Confirmation rate (0-10000 representing 0.00-100.00%)
     */
    function getConfirmationRate(uint256 tokenId) external view agentExists(tokenId) returns (uint256) {
        if (agents[tokenId].actionCount == 0) return 0;
        return (agents[tokenId].confirmedCount * MAX_TRUST_SCORE) / agents[tokenId].actionCount;
    }

    /**
     * @dev Get agent by owner address
     */
    function getAgentByOwner(address owner) external view returns (uint256) {
        return ownerToAgent[owner];
    }

    /**
     * @dev Get total agents minted
     */
    function totalAgents() external view returns (uint256) {
        return _nextTokenId - 1;
    }

    // ============ VERSION & CONTRACT INFO ============

    /**
     * @dev Get agent's registration version
     * @param tokenId Agent token ID
     * @return version The contract version number at time of registration
     */
    function getAgentVersion(uint256 tokenId) external view agentExists(tokenId) returns (uint256) {
        return agents[tokenId].registrationVersion;
    }

    /**
     * @dev Check if agent was registered on current contract version
     * @param tokenId Agent token ID
     * @return isLatest True if agent was registered on current version
     */
    function isLatestVersion(uint256 tokenId) external view agentExists(tokenId) returns (bool) {
        return agents[tokenId].registrationVersion == CONTRACT_VERSION_NUMBER;
    }

    /**
     * @dev Get contract info for agents - provides all info needed to interact with contract
     * @return version Human-readable version string
     * @return versionNumber Numeric version for comparison
     * @return chainId Chain ID where contract is deployed
     * @return contractAddress Address of this contract
     * @return tokenName Token name
     * @return tokenSymbol Token symbol
     */
    function getContractInfo() external view returns (
        string memory version,
        uint256 versionNumber,
        uint256 chainId,
        address contractAddress,
        string memory tokenName,
        string memory tokenSymbol
    ) {
        return (
            CONTRACT_VERSION,
            CONTRACT_VERSION_NUMBER,
            block.chainid,
            address(this),
            name(),
            symbol()
        );
    }

    /**
     * @dev Get full registration info for an agent including version delta
     * @param tokenId Agent token ID
     * @return agent The agent metadata
     * @return currentVersion Current contract version
     * @return versionsBehind How many versions behind the agent is (0 = current)
     */
    function getAgentWithVersionInfo(uint256 tokenId) external view agentExists(tokenId) returns (
        AgentMetadata memory agent,
        uint256 currentVersion,
        uint256 versionsBehind
    ) {
        agent = agents[tokenId];
        currentVersion = CONTRACT_VERSION_NUMBER;
        // Version numbers are MAJOR * 1_000_000 + MINOR * 1_000 + PATCH
        // So version delta = (current - registration) / 1_000_000 for major versions
        versionsBehind = (CONTRACT_VERSION_NUMBER - agent.registrationVersion) / 1_000_000;
    }

    // ============ TOKEN URI ============

    function setBaseURI(string memory baseURI) external onlyOwner {
        _baseTokenURI = baseURI;
    }

    function tokenURI(uint256 tokenId) public view override agentExists(tokenId) returns (string memory) {
        AgentMetadata memory agent = agents[tokenId];

        // Return on-chain JSON metadata with version info
        return string(
            abi.encodePacked(
                "data:application/json;base64,",
                _encodeBase64(
                    abi.encodePacked(
                        '{"name":"', agent.name,
                        '","description":"AMAI Agent Identity - Trust Score: ', (agent.trustScore / TRUST_PRECISION).toString(), '.', (agent.trustScore % TRUST_PRECISION).toString(),
                        '","external_url":"', agent.serviceEndpoint,
                        '","attributes":[',
                        '{"trait_type":"Trust Score","value":', agent.trustScore.toString(), ',"max_value":10000},',
                        '{"trait_type":"Actions","value":', agent.actionCount.toString(), '},',
                        '{"trait_type":"Confirmations","value":', agent.confirmedCount.toString(), '},',
                        '{"trait_type":"Status","value":"', agent.isActive ? "Active" : "Inactive", '"},',
                        '{"trait_type":"Registration Version","value":', agent.registrationVersion.toString(), '},',
                        '{"trait_type":"Current Version","value":', CONTRACT_VERSION_NUMBER.toString(), '}',
                        ']}'
                    )
                )
            )
        );
    }

    // ============ SOULBOUND OVERRIDES ============

    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address from = _ownerOf(tokenId);
        // Allow minting (from == 0) and burning (to == 0), but not transfers
        if (from != address(0) && to != address(0)) {
            revert("AMAIIdentity: soulbound token cannot be transferred");
        }
        return super._update(to, tokenId, auth);
    }

    function approve(address, uint256) public pure override {
        revert("AMAIIdentity: soulbound token cannot be approved");
    }

    function setApprovalForAll(address, bool) public pure override {
        revert("AMAIIdentity: soulbound token cannot be approved");
    }

    // ============ BASE64 ENCODING ============

    function _encodeBase64(bytes memory data) internal pure returns (string memory) {
        bytes memory base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        uint256 len = data.length;
        if (len == 0) return "";

        uint256 encodedLen = 4 * ((len + 2) / 3);
        bytes memory result = new bytes(encodedLen);

        uint256 j = 0;
        for (uint256 i = 0; i < len; i += 3) {
            uint256 b0 = uint8(data[i]);
            uint256 b1 = i + 1 < len ? uint8(data[i + 1]) : 0;
            uint256 b2 = i + 2 < len ? uint8(data[i + 2]) : 0;

            uint256 combined = (b0 << 16) | (b1 << 8) | b2;

            result[j++] = base64chars[(combined >> 18) & 63];
            result[j++] = base64chars[(combined >> 12) & 63];
            result[j++] = i + 1 < len ? base64chars[(combined >> 6) & 63] : bytes1("=");
            result[j++] = i + 2 < len ? base64chars[combined & 63] : bytes1("=");
        }

        return string(result);
    }
}
