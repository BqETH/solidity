pragma solidity >=0.8.0 <0.9.0;
//SPDX-License-Identifier: MIT

import "./BigNumbers.sol";
import "hardhat/console.sol";
uint64 constant Y3K = 32503680000000;
import './PietrzakVerifier.sol';

// Creator H1=Hash(S1), X2=Hash(Salt+S1), H3=Hash(X2+H1) -> publishes H3
// Claimer:  Publishes H1, X2
// Verifier: Verify Hash(H1,X2) = H3  accept the lock
// Reward claim: S1, Proof p 
// Verifier: Check Proof is valid for S1, CHeck that H1=Hash(S1), X2=Hash(Salt+S1), and H3=Hash(X2+H1)

/// @title BqETH Contract
contract BqETH is PietrzakVerifier {

  string public name = "BqETH Contract version 0.1";
  bytes32 constant salt = "BqETH";
  address owner;  
  // TODO: store claimblock in the puzzle, so multiple puzzles can be claimed in the same block
  uint256 public claimBlockNumber; 

  constructor() payable {
    console.log("Deploying BqETH Contract with version:", name);
    owner =  msg.sender;
  }

  function version() public view
        returns (string memory) {
        return name;
  }

  struct Puzzle {
    address creator;    // The user who registered the puzzle
    address payable farmer;     // Last farmer to claim
    bytes N;            // The modulus
    bytes x;            // The start value
    uint256 t;          // The time parameter
    uint256 sdate;      // The start date or next pid in chain
    bytes32 h3;         // H3 Hash value of the solution
    uint256 reward;     // The amount that should be dispensed
    string phi;         // The encrypted phi
    uint256 head;       // Chain head pid
  }

  struct ActivePolicy {
    address creator;      // The user who registered the puzzle
    uint256 pid;          // The puzzle id which issued the policy
    string messageKit;    // The encrypted secret
    string encryptedTreasureMap; 
    string revocationKit;
    string aliceVerifyingKey;
    string policyEncryptingKey;
  }

  // In the white paper we suggest using y0=2^(x0^t) mod N and y1=2^(x1^t) mod N 
  // by generating a random x0, x1, then publishing x0 and x1'=enc(x1) with
  // x1' being x1 encrypted with y0.  It is actually easier and just as secure,
  // to generate a random x1' and deriving x1 from it as x1=y0^x1' mod N . 
  // We can then simply publish a new Puzzle with the same data but x1' 
  // instead of x1. The re-encryption policy can be linked to the last puzzle.

  // We're storing the creator in the puzzle, indexing puzzles by their hash
  mapping(uint256 => Puzzle) public userPuzzles;
  mapping(address => uint) public escrow_balances;
  mapping(address => ActivePolicy) public activePolicies;
  mapping(address => uint256) public activePuzzles;   // Only the first puzzle of a chain

  event NewPuzzleRegistered(address sender, uint256 pid, bool ready);
  event PuzzleInactive(
    uint256 pid,  
    bytes solution, 
    string verifyingKey, 
    string messageKit,  
    uint256 sdate, 
    string treasureMap, 
    string policyEncryptingKey
    );
  event RewardClaimed(uint256 pid, bytes y, uint256 sdate, uint256 reward);
  event NewPolicyRegistered(    
    string id,
    string label,
    string policyEncryptingKey,
    string encryptedTreasureMap,
    string aliceVerifyingKey,
    string size,
    string startTimestamp,
    string endTimestamp
    );

  modifier onlyContractOwner()
  {
      require(msg.sender == owner);
      _;
  }

  modifier onlyContractCustomer(uint256 _pid)
  {
      Puzzle memory puzzle = userPuzzles[_pid];
      require(msg.sender == puzzle.creator);
      _;
  }

  // Some unique key for each puzzle
  function puzzleKey(bytes memory _N, bytes memory _x, uint256 _t) public pure returns (uint256) 
  {
    return uint(keccak256(abi.encodePacked(_N, _x, _t)));
  }

struct ChainData {
    bytes x;        // The start value
    uint256 t;          // The time parameter
    uint256 pid;        // The next pid
    bytes32 h3;         // H3 Hash value of the solution
    uint256 reward;     // The amount that should be dispensed
}

struct PolicyData {
    string id;
    string label; 
    string policyEncryptingKey; 
    string encryptedTreasureMap; 
    string revocationKit;
    string aliceVerifyingKey; 
    string size;
    string startTimestamp; 
    string endTimestamp;
}
  /// @notice Registers a user Puzzle Chain
  /// @dev This registration creates an entry per puzzle in the userPuzzles map. The parameters completely and uniquely define the puzzle
  /// and may be repeated across multiple puzzles since (N,φ) will be re-used until N has decayed. 
  /// @param _N bytes  The prime composite modulus
  /// @param _c[] ChainData  The puzzle initial challenges
  /// @param _phi string  This is the encrypted value of phi, encrypted for the caller's public key
  /// @param _sdate uint256  The start date (UTC) or the next puzzle hash in the chain
  /// @param _policy PolicyData  The details of the NuCypher policy covering this
  /// @param _messageKit string The encrypted payload
  /// @return ph uint256 Returns the puzzle hash key of the first puzzle
  function registerPuzzleChain(
    bytes memory _N, 
    ChainData[] memory _c, 
    string memory _phi,
    uint256 _sdate,
    PolicyData memory _policy,
    string memory _messageKit
    ) public payable 
  returns (uint256) 
  {
      uint256 ph = 0;
      uint256 reward_total = 0;
      uint256 first_pid = 0;
      uint256 head = puzzleKey(_N, _c[0].x, _c[0].t);

      for(uint i = 0; i < _c.length; i++){

        ph = puzzleKey(_N, _c[i].x, _c[i].t);
        address payable _farmer;
        // TODO: Check that the puzzle did not already exist:

        //Store the puzzle
        Puzzle memory pz;
        pz.creator = msg.sender;
        pz.farmer = _farmer;
        pz.N = _N;
        pz.x = _c[i].x;
        pz.t = _c[i].t;
        pz.sdate = (i == _c.length-1)? _sdate : _c[i].pid;  // Only last puzzle gets sdate
        pz.h3 = _c[i].h3;
        pz.reward = _c[i].reward;
        pz.phi = (i == 0 || i == _c.length-1)? _phi : '' ;  // Only first and last puzzle get encrypted phi
        pz.head = head;

        userPuzzles[ph] = pz;

        reward_total += _c[i].reward;

        if (i == 0) {
          activePuzzles[msg.sender] = ph;
          first_pid = ph;
        }
        console.log("Registered puzzle with Hash :'%s'", ph);
        // Send the Event
        emit NewPuzzleRegistered(msg.sender, ph,
                                (i==0) ? true:false);   // First puzzle in a chain is read-to-work
      }
      // TODO msg.value better be more than the sum of puzzle chain rewards
      // require(msg.value >= reward_total);

      // Add to the escrow total for the creator's address.
      escrow_balances[msg.sender] += msg.value;

      activePolicies[msg.sender] = ActivePolicy( msg.sender, first_pid, _messageKit, 
          _policy.encryptedTreasureMap,
          _policy.revocationKit,
          _policy.aliceVerifyingKey,
          _policy.policyEncryptingKey
        );

      emit NewPolicyRegistered(    
          _policy.id,
          _policy.label,
          _policy.policyEncryptingKey, 
          _policy.encryptedTreasureMap,
          _policy.aliceVerifyingKey,
          _policy.size,
          _policy.startTimestamp,
          _policy.endTimestamp
      );

      return first_pid;
  }

  /// @notice Registers a flipped user Puzzle
  /// @dev This registration creates an entry per puzzle in the userPuzzles map. The parameters completely and uniquely define the puzzle
  /// and may be repeated across multiple puzzles since (N,φ) will be re-used until N has decayed. 
  /// @param _N bytes  The prime composite modulus
  /// @param _c[] ChainData  The puzzle initial challenges
  /// @param _phi string  This is the value of phi, encrypted for the caller's public key
  /// @param _sdate uint256  The start date (UTC) or the next puzzle hash in the chain
  /// @param _policy PolicyData  The details of the NuCypher policy covering this
  /// @return ph uint256 Returns the puzzle hash key
  function registerFlippedPuzzle(
    bytes memory _N, 
    ChainData[] memory _c, 
    string memory _phi, 
    uint256 _sdate, 
    PolicyData memory _policy
    ) public payable 
  returns (uint256) 
  {
      uint256 prev = activePuzzles[msg.sender];
      // Puzzle memory previous = userPuzzles[prev];
      // Puzzle flip restricted to creator of the previous puzzle
      require(msg.sender == userPuzzles[prev].creator);
      uint256 reward_total = 0;
      uint256 first_pid = 0;
      uint256 head = puzzleKey(_N, _c[0].x, _c[0].t);

      for(uint i = 0; i < _c.length; i++){

        uint256 ph = puzzleKey(_N, _c[i].x, _c[i].t);
        address payable _farmer;
        // TODO Check that the puzzle did not already exist:
        // Puzzle memory puzzle = userPuzzles[ph];
        // require(puzzle.N != 0, "Puzzle already registered");   // We cannot afford a collision 

        //Store the puzzle
        Puzzle memory pz;
        pz.creator = msg.sender;
        pz.farmer = _farmer;
        pz.N = _N;
        pz.x = _c[i].x;
        pz.t = _c[i].t;
        pz.sdate = (i == _c.length-1)? _sdate : _c[i].pid;  // Only last puzzle gets sdate
        pz.h3 = _c[i].h3;
        pz.reward = _c[i].reward;
        pz.phi = (i == 0 || i == _c.length-1)? _phi : '' ;  // Only first and last puzzle get encrypted phi
        pz.head = head;

        userPuzzles[ph] = pz;

        reward_total += _c[i].reward;

        if (i == 0) {
          activePuzzles[msg.sender] = ph;
          first_pid = ph;
        }
        console.log("Registered puzzle with Hash :'%s'", ph);
        // Send the Event
        emit NewPuzzleRegistered(msg.sender, ph, 
                                (i==0) ? true:false);   // First puzzle in a chain is read-to-work
      }
      // TODO msg.value better be more than the sum of puzzle chain rewards
      // require(msg.value >= reward_total);

      // Add to the escrow total for the creator's address.
      escrow_balances[msg.sender] += msg.value;

      // Look up the active policy object and just change the treasuremap
      ActivePolicy storage policy = activePolicies[userPuzzles[prev].creator];
      // Only these 3 things change
      policy.pid = first_pid;
      policy.encryptedTreasureMap = _policy.encryptedTreasureMap;
      policy.revocationKit = _policy.revocationKit;


    emit NewPolicyRegistered(    
          _policy.id,
          _policy.label,
          _policy.policyEncryptingKey, 
          _policy.encryptedTreasureMap,
          _policy.aliceVerifyingKey,
          _policy.size,
          _policy.startTimestamp,
          _policy.endTimestamp
      );
      return first_pid;
  }

  function getActiveChain(address _user) public view 
      returns (Puzzle[] memory chain,     // The Puzzle chain
              string memory verifyingKey, // The verifying key
              string memory messageKit,   // The secret
              string memory treasureMap   // The associated NuCypher policy treasuremap
              )
  {
      // This is now always the first puzzle of a chain
      uint256 ph = activePuzzles[_user];  
      Puzzle memory puzzle = userPuzzles[ph];

      // Count the puzzles in the chain
      uint idx = 1;
      while (puzzle.sdate > Y3K)
      {
        puzzle = userPuzzles[puzzle.sdate];
        idx++;
      }

      Puzzle[] memory puzzles = new Puzzle[](idx);
      puzzle = userPuzzles[ph];
      uint i = 0;
      while (puzzle.sdate > Y3K) {
        puzzles[i] = puzzle;
        puzzle = userPuzzles[puzzle.sdate];
        i++;
      }
      puzzles[i] = puzzle;  // Save the final puzzle
      
      ActivePolicy memory policy = activePolicies[puzzle.creator];

      return (puzzles,                    // The puzzle chain
              policy.aliceVerifyingKey,   // The verifying key
              policy.messageKit,          // The secret
              policy.encryptedTreasureMap // The associated NuCypher policy treasuremap
              );
  }

  function getActivePuzzle(address _user) public view 
      returns (uint256 pid,       // The puzzle key
              address creator,    // The puzzle creator
              bytes memory N,           // The modulus
              bytes memory x,           // The start value
              uint256 t,           // The time parameter
              bytes32 h3,          // H3 Hash value of the solution
              uint256 reward,      // The amount that should be dispensed
              string memory verifyingKey, // The verifying key
              string memory messageKit,   // The secret
              string memory treasureMap,  // The associated NuCypher policy treasuremap
              string memory encryptedPhi, // The encrypted value for Phi
              uint256 sdate
              )
  {
    // This is now always the first puzzle of a chain as long as the chain is active
      uint256 ph = activePuzzles[_user];
      return getPuzzle(ph);
  }

  /// @notice Performs a formal request for all of a puzzle's data
  /// @param _pid uint256 The puzzle hash
  function getPuzzle(uint256 _pid) public view 
      returns (
        uint256 pid,       // The puzzle key
        address creator,    // The puzzle creator
        bytes memory N,           // The modulus
        bytes memory x,           // The start value
        uint256 t,           // The time parameter
        bytes32 h3,          // H3 Hash value of the solution
        uint256 reward,      // The amount that should be dispensed
        string memory verifyingKey, // The verifying key
        string memory messageKit,   // The secret
        string memory treasureMap,   // The associated NuCypher policy treasuremap
        string memory phi,
        uint256 sdate
      )
  {
      Puzzle memory puzzle = userPuzzles[_pid];
      ActivePolicy memory policy = activePolicies[puzzle.creator];

      return (_pid,
              puzzle.creator,               // The puzzle creator
              puzzle.N,                     // The modulus
              puzzle.x,                     // The start value
              puzzle.t,                     // The time parameter
              puzzle.h3,                    // H3 Hash value of the solution
              puzzle.reward,                // The amount that should be dispensed
              policy.aliceVerifyingKey,     // The verifying key
              policy.messageKit,            // The secret
              policy.encryptedTreasureMap,  // The associated NuCypher policy treasuremap
              puzzle.phi,                   // The encrypted phi
              puzzle.sdate                  // The start date or next puzzle pid
      );
  }

  // Claim: Publish H1, X2
  // Verifier: Verify Hash(H1,X2) = H3  accept the lock
  function claimPuzzle(address payable _farmer, uint256 _pid, bytes32 _h1, bytes32 _x2) public 
  returns (uint256)
  {
    // Force execution of claimPuzzle and claimReward to happen in different blocks
    require(claimBlockNumber < block.number);
    claimBlockNumber = block.number;
    // Look up the puzzle
    Puzzle storage puzzle = userPuzzles[_pid];
    
    // Accept a claim only if farmer can demonstrate they know H1 and X2 which hash to H3
    bytes memory b = abi.encode(_x2, _h1);
    require(sha256(b) == puzzle.h3, "Commitment must match puzzle stamp.");
    // Record the farmer who has committed to the solution hash
    puzzle.farmer = _farmer;
    return _pid;
  }

  // Reward claim: S1, Proof p 
  // Verifier: Check Proof is valid for S1, Check that H1=Hash(S1), X2=Hash(Salt+S1), and H3=Hash(X2+H1)
  function claimReward(address payable _farmer, uint256 _pid, bytes memory _y, bytes[] calldata _proof) public 
  returns (uint256)
  {
    // Force execution of claimPuzzle and claimReward to happen in different blocks
    require(claimBlockNumber < block.number);
    claimBlockNumber = block.number;
    // Look up the puzzle
    Puzzle storage puzzle = userPuzzles[_pid];
    if (!BigNumbers.isZero(puzzle.x)) {   // Valid and active puzzle
      // Must be the same farmer that committed the solution first
      require(puzzle.farmer == _farmer, "Original farmer required");
      // The solution submitted must match the commitment
      bytes32 h1 = sha256(abi.encode(_y));
      bytes32 x2 = sha256(abi.encode(salt,_y));
      require(sha256(abi.encode(x2,h1)) == puzzle.h3, "Solution must match commitment.");

      // Now we can bother to verify
      uint256 d = log2(puzzle.t)-1;
      if (verifyProof(puzzle.N, puzzle.x, d, _y, 0, _proof)) 
      {
            puzzle.farmer.transfer(puzzle.reward);
            escrow_balances[puzzle.creator] -= puzzle.reward;
            puzzle.x = "";     // Set puzzle to inactive
            ActivePolicy memory policy = activePolicies[puzzle.creator];
            emit PuzzleInactive(_pid, // Puzzle Hash
                _y,                         // The solution
                policy.aliceVerifyingKey,   // The verifying key
                policy.messageKit,          // The secret
                puzzle.sdate,       
                policy.encryptedTreasureMap,  // The associated policy treasuremap
                policy.policyEncryptingKey
            );
            emit RewardClaimed(_pid, _y, puzzle.sdate, puzzle.reward);
            // This only deletes the key
            if (puzzle.sdate < Y3K) {    // last puzzle in the chain ->
              uint256 chain_head = puzzle.head;  // Find our chain head
              uint256 pid_to_clear = chain_head;
              do {  // Clear puzzle chain 
                uint256 next_pid = userPuzzles[pid_to_clear].sdate;
                delete userPuzzles[pid_to_clear];
                pid_to_clear = next_pid;
              }
              while (pid_to_clear > Y3K);
                // clear out the puzzle if no new one took its place
              if (activePuzzles[puzzle.creator] == chain_head) {
                delete activePuzzles[puzzle.creator];
              }
            }
      }
      return _pid;
    }
    else {
      console.log("Puzzle already claimed");
      return 0;
    }
  }

  // to support receiving ETH by default
  receive() external payable {}
  fallback() external payable {}
}
