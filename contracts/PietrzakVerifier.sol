pragma solidity >=0.8.0 <0.9.0;
//SPDX-License-Identifier: MIT

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
  
  // b^e mod m  (base, exponent, modulus)
  function expmod(uint base, uint e, uint m) public view returns (uint o) {
    assembly {
    // define pointer
    let p := mload(0x40)
    // store data assembly-favouring ways
    mstore(p, 0x20)             // Length of Base
    mstore(add(p, 0x20), 0x20)  // Length of Exponent
    mstore(add(p, 0x40), 0x20)  // Length of Modulus
    mstore(add(p, 0x60), base)  // Base
    mstore(add(p, 0x80), e)     // Exponent
    mstore(add(p, 0xa0), m)     // Modulus
    if iszero(staticcall(sub(gas(), 2000), 0x05, p, 0xc0, p, 0x20)) {
      revert(0, 0)
    }
    // data
    o := mload(p)
  }}

 function r_value(uint256 _x, uint256 _y, uint256 _u) public pure returns (uint128) {
      // Farmers use sha256
      // We chop off the hash at 16 bytes because that's all we need for r
      bytes memory p = abi.encode(_x,_y, _u);
      bytes32 s = sha256(p);
      bytes16[2] memory b = [bytes16(0),0];
      assembly {
          mstore(b, s)
          mstore(add(b, 16), s)
      }
      uint128 r = uint128(b[0]);
      return r;
  }

  // This method verifies that proof p correctly asserts that xi^t mod N = yi 
  function verifyProof(uint256 N, uint256 xi,  uint256 d, uint256 yi, uint8 index, uint256[] memory p) internal returns (bool) 
  {
      uint256 ui = p[index];
      uint256 ri = r_value(xi, yi, ui) % N;
      xi = mulmod(expmod(xi, ri, N), ui, N);
      yi = mulmod(expmod(ui, ri, N), yi, N);

      // Recursion
      if (index+1 != p.length)
          return verifyProof(N, xi, d-1, yi, index+1, p);

      // When there are no more entries in the proof 
      
      uint256 e = 2**(2**d);            // Note: This is a problem, if d is >=8
      if (yi == expmod(xi, e, N)) {
          // console.log("Proof is Valid");
          return true;
      }
      else {
          // console.log("Proof is invalid");
          return false;
      }
  }
}
