pragma solidity >=0.8.0 <0.9.0;
//SPDX-License-Identifier: MIT
  // Some functions copied from https://github.com/kilic/evmvdf 
  // Some functions copied from 0x: https://github.com/0xProject/VDF/blob/master/contracts/Verifier.sol
import './ModMath.sol';

abstract contract PietrzakVerifier is ModMath {

  function r_value(bytes memory _x, bytes memory _y, bytes memory _u) public pure returns (bytes16 result)
  {
      // Farmers use sha256 (Sha-2) and so do we
      // And they use the proper big endian byte configuration of the integers
      // s = (x.to_bytes(int_size, "big", signed=False) + y.to_bytes(int_size, "big", signed=False) + μ.to_bytes(int_size, "big", signed=False))
      // b = hashlib.sha256(s).digest()
      // return int.from_bytes(b[:16], "big")
      
      bytes memory p = abi.encode(_x,_y, _u);
      bytes32 s = sha256(p);
      bytes16[2] memory b = [bytes16(0),0];
      assembly {
          mstore(b, s)
          mstore(add(b, 16), s)   // This copies the second 16 bytes word, which we discard anyway 
      }
      // We chop off the hash at 16 bytes because that's all we need for r
      // Note: Most Fiat Shamir transforms will use 1 bit for each interaction, but we're not doing 
      // 128 rounds so it makes sense to maintain the unpredictability by using 16 bits for each level. 
      return b[0]; // returns 16 bytes
  }

  // Fast and low gas log base2 
  function log2(uint256 x) public pure returns(uint8) 
  {
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

  // This method verifies that proof p correctly asserts that xi^t mod N = yi 
  function verifyProof(bytes memory N, bytes memory xi,  uint256 d, bytes memory yi, uint8 index, bytes[] memory p) internal returns (bool) 
  {
      bytes memory ui = p[index];
      bytes16 ri = r_value(xi, yi, ui);      // This will be 16 bytes
      uint256 exp = uint256(bytes32(ri));
      xi = ModMath.big_mulmod(ModMath.bignum_expmod(xi, exp, N), ui, N);
      yi = ModMath.big_mulmod(ModMath.bignum_expmod(ui, exp, N), yi, N);

      // Recursion
      if (index+1 != p.length)
          return verifyProof(N, xi, d-1, yi, index+1, p);

      // When there are no more entries in the proof 
      uint256 e = 2**(2**d);            // Note: This is a problem, if d is >=8
      if (ModMath.big_equal(yi,ModMath.bignum_expmod(xi, e, N))) {
          // console.log("Proof is Valid");
          return true;
      }
      else {
          // console.log("Proof is invalid");
          return false;
      }
  }

  // // assert (gcd(x - 1, n) == 1)
  // // assert (gcd(x + 1, n) == 1)
  // function isGroupElement(bytes memory x, bytes memory n) internal pure returns (bool isElement) {
  //   if (x.length != 256) {
  //     return false;
  //   }
  // ....
  // }
}
