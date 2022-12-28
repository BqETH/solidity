//SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "./BigNumbers.sol";

abstract contract PietrzakVerifier {

  // Fast and low gas log base2 
  function log2(uint256 x) public pure returns(uint8) {
    uint8 n = 0;

    if (x >= 2**128) { x >>= 128; n += 128; }
    if (x >= 2**64) { x >>= 64; n += 64; }
    if (x >= 2**32) { x >>= 32; n += 32; }
    if (x >= 2**16) { x >>= 16; n += 16; }
    if (x >= 2**8) { x >>= 8; n += 8; }
    if (x >= 2**4) { x >>= 4; n += 4; }
    if (x >= 2**2) { x >>= 2; n += 2; }
    if (x >= 2**1) { /* x >>= 1; */ n += 1; }
    return n;
  }

 function r_value(BigNumber memory _x, BigNumber memory _y, BigNumber memory _u) public pure returns (uint128) {
      // Farmers use sha256 (Sha-2) and so do we
      // And they use the proper big endian byte configuration of the integers
      // s = (x.to_bytes(int_size, "big", signed=False) + y.to_bytes(int_size, "big", signed=False) + μ.to_bytes(int_size, "big", signed=False))
      // b = hashlib.sha256(s).digest()
      // return int.from_bytes(b[:16], "big")

      // We chop off the hash at 16 bytes because that's all we need for r
      bytes memory p = abi.encodePacked(_x.val,_y.val, _u.val);
      bytes32 s = sha256(p);
      bytes16[2] memory b = [bytes16(0),0];
      assembly {
          mstore(b, s)
          mstore(add(b, 16), s)
      }
      uint128 r = uint128(b[0]);
      return r;
  }

  // This is called externally by modules that don't know 
  // anything about the BigNumber data type, and therefore pass large integers as bytes
  function verifyProof(
    bytes memory N, 
    bytes memory xi,  
    uint256 d, 
    bytes memory yi, 
    uint8 index, 
    bytes[] memory p) internal view returns (bool) 
  {
      // We must also check that input params are valid: x,y are square roots mod N and that the values match the puzzle's data
      // assert (math.gcd(puzzle[PUZZLE_X] - 1, puzzle[PUZZLE_MODULUS]) == 1)
      // assert (math.gcd(puzzle[PUZZLE_X] + 1, puzzle[PUZZLE_MODULUS]) == 1)

    // Make Bignumbers out of everything
    BigNumber memory bnN =  BigNumbers.init(N, false);
    BigNumber memory bnxi = BigNumbers.init(xi, false);
    BigNumber memory bnyi = BigNumbers.init(yi, false);
    BigNumber[] memory proof;
    for(uint i = 0; i < p.length; i++){
      proof[i] = BigNumbers.init(p[i], false);
    }

    return verifyProof(bnN, bnxi, d, bnyi, index, proof);
  }


  // This method verifies that proof p correctly asserts that xi^t mod N = yi 
  function verifyProof(
    BigNumber memory N, 
    BigNumber memory xi,  
    uint256 d, 
    BigNumber memory yi, 
    uint8 index, 
    BigNumber[] memory p) private view returns (bool) 
  {
      BigNumber memory ui = p[index];
      BigNumber memory ri = BigNumbers.mod(BigNumbers.init(r_value(xi, yi, ui), false), N);
      xi = BigNumbers.modmul(BigNumbers.modexp(xi, ri, N), ui, N);
      yi = BigNumbers.modmul(BigNumbers.modexp(ui, ri, N), yi, N);

      // Recursion
      if (index+1 != p.length)
          return verifyProof(N, xi, d-1, yi, index+1, p);

      // When there are no more entries in the proof 
      
      uint256 e = 2**(2**d);            // Note: This is a problem, if d is >=8
      BigNumber memory bne = BigNumbers.init(e, false);
      if (BigNumbers.eq(yi, BigNumbers.modexp(xi, bne, N))) {
          // console.log("Proof is Valid");
          return true;
      }
      else {
          // console.log("Proof is invalid");
          return false;
      }
  }
}
