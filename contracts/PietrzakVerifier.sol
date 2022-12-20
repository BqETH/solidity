pragma solidity >=0.8.0 <0.9.0;
//SPDX-License-Identifier: MIT
  // Some functions copied from https://github.com/kilic/evmvdf 
  // Some functions copied from 0x: https://github.com/0xProject/VDF/blob/master/contracts/Verifier.sol

abstract contract PietrzakVerifier {

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

  // // Fast modexp knowing values are 2048 bits base^exponent % modulus
  // function modexp2048(bytes memory base, uint256 exponent, bytes memory modulus) internal view returns (bytes memory res) 
  // {
  //   assembly {
  //     let mem := mload(0x40)

  //     mstore(mem, 256)              // <length_of_BASE> = 256 in bytes (2048 bits)
  //     mstore(add(mem, 0x20), 0x20)  // <length_of_EXPONENT> = 32 (256 bits)
  //     mstore(add(mem, 0x40), 256)   // <length_of_MODULUS> = 256 (2048 bits)

  //     mstore(add(mem, 0x60), mload(add(base, 0x20)))
  //     mstore(add(mem, 0x80), mload(add(base, 0x40)))
  //     mstore(add(mem, 0xa0), mload(add(base, 0x60)))
  //     mstore(add(mem, 0xc0), mload(add(base, 0x80)))
  //     mstore(add(mem, 0xe0), mload(add(base, 0xa0)))
  //     mstore(add(mem, 0x100), mload(add(base, 0xc0)))
  //     mstore(add(mem, 0x120), mload(add(base, 0xe0)))
  //     mstore(add(mem, 0x140), mload(add(base, 0x100)))

  //     mstore(add(mem, 0x160), exponent)

  //     mstore(add(mem, 0x180), mload(add(modulus, 0x20)))
  //     mstore(add(mem, 0x1a0), mload(add(modulus, 0x40)))
  //     mstore(add(mem, 0x1c0), mload(add(modulus, 0x60)))
  //     mstore(add(mem, 0x1e0), mload(add(modulus, 0x80)))
  //     mstore(add(mem, 0x200), mload(add(modulus, 0xa0)))
  //     mstore(add(mem, 0x220), mload(add(modulus, 0xc0)))
  //     mstore(add(mem, 0x240), mload(add(modulus, 0xe0)))
  //     mstore(add(mem, 0x260), mload(add(modulus, 0x100)))

  //     let success := staticcall(sub(gas(), 2000), 5, mem, 0x280, add(mem, 0x20), 256)
  //     switch success
  //       case 0 {
  //         revert(0x0, 0x0)
  //       }
  //     // update free mem pointer
  //     mstore(0x40, add(mem, 0x120))  // 0x20 bytes for length (32) + 0x100 bytes for the number (256 bytes)
  //     res := mem
  //   }
  // }

  // Some Functions below copied from the 0x Wesolowski VDF verification contract

  function trim(bytes memory data) internal pure returns(bytes memory) {
      uint256 msb = 0;
      while (data[msb] == 0) {
          msb ++;
          if (msb == data.length) {
              return hex"";
          }
      }
      
      if (msb > 0) {
          // We don't want to copy data around, so we do the following assembly manipulation:
          // Move the data pointer forward by msb, then store in the length slot (current length - msb)
          assembly {
              let current_len := mload(data)
              data := add(data, msb)
              mstore(data, sub(current_len, msb))
          }
      }
      return data;
  }

  // Expmod for bignum operands (encoded as bytes, only base and modulus) 
  function bignum_expmod(bytes memory base, uint256 e, bytes memory m) public view returns (bytes memory o) {
      assembly {
          // Get free memory pointer
          let p := mload(0x40)

          // Get base length in bytes
          let bl := mload(base)
          // Get modulus length in bytes
          let ml := mload(m)

          // Store parameters for the Expmod (0x05) precompile
          mstore(p, bl)               // Length of Base
          mstore(add(p, 0x20), 0x20)  // Length of Exponent
          mstore(add(p, 0x40), ml)    // Length of Modulus
          // Use Identity (0x04) precompile to memcpy the base
          if iszero(staticcall(10000, 0x04, add(base, 0x20), bl, add(p, 0x60), bl)) {
              revert(0, 0)
          }
          mstore(add(p, add(0x60, bl)), e) // Exponent
          // Use Identity (0x04) precompile to memcpy the modulus
          if iszero(staticcall(10000, 0x04, add(m, 0x20), ml, add(add(p, 0x80), bl), ml)) {
              revert(0, 0)
          }
          
          // Call 0x05 (EXPMOD) precompile
          if iszero(staticcall(sub(gas(), 2000), 0x05, p, add(add(0x80, bl), ml), add(p, 0x20), ml)) {
              revert(0, 0)
          }

          // Update free memory pointer
          mstore(0x40, add(add(p, ml), 0x20))

          // Store correct bytelength at p. This means that with the output
          // of the Expmod precompile (which is stored as p + 0x20)
          // there is now a bytes array at location p
          mstore(p, ml)

          // Return p
          o := p
      }
  }

  // Uses the mod const in the contract and assumes that a < Mod, b < Mod
  // Ie that the inputs are already modular group memembers.
  function modular_add(bytes memory a, bytes memory b, bytes memory modulus) internal view returns (bytes memory) {
      bytes memory result = big_add(a, b);
      if (lte(result, modulus) && !big_equal(result, modulus)) {
          return result;
      } else {
          // NOTE a + b where a < MOD, b < MOD => a+b < 2 MOD => a+b % mod = a+b - MOD
          return big_sub(result, modulus);
      }
  }

  function modular_sub(bytes memory a, bytes memory b, bytes memory modulus) internal view returns(bytes memory) {
      if (lte(b, a)) {
          return big_sub(a, b);
      } else {
          return (big_sub(modulus, big_sub(b, a)));
      }
  }

  // Returns (a <= b);
  // Requires trimmed inputs
  function lte(bytes memory a, bytes memory b) internal pure returns (bool) {
      if (a.length < b.length) {
          return true;
      }
      if (a.length > b.length) {
          return false;
      }

      for (uint i = 0; i < a.length; i++) {
          // If the current byte of a is less than that of b then a is less than b
          if (a[i] < b[i]) {
              return true;
          }
          // If it's strictly more then b is greater
          if (a[i] > b[i]) {
              return false;
          }
      }
      // We hit this condition if a == b
      return true;
  }

  uint mask = 0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
  // This big add function has performance on the order of the limb version, but
  // it worse because it chunks out limbs for as long as it can from the bytes and
  // when there isn't enough data for a 31 bit limb in either a or b it goes byte by byte
  // Preformance degrades to byte by byte when adding a full 2048 bit number to a small number.
  // It is best when adding two full sized 2048 bit numbers
  function big_add(bytes memory a, bytes memory b) internal view returns(bytes memory) {
      // a + b < 2*max(a, b) so this can't have more bytes than the max length + 1
      bytes memory c = new bytes(max(a.length, b.length) + 1);
      // The index from the back of the data arrays [since this is Big endian]
      uint current_index = 0;
      uint8 carry = 0;
      // This loop grabs large numbers from the byte array for as long as we can
      while (a.length - current_index > 31 && b.length - current_index > 31) {
          // Will have 31 bytes of a's next digits
          uint a_data;
          // Will have 31 bytes of b's next digits
          uint b_data;
          assembly {
              //Load from memory at the data location of a + a.length - (current_index - 32)
              // This can load a bit of extra data which will be masked off.
              a_data := mload(add(add(a, 0x20), sub(mload(a), add(current_index, 32))))
              //Load from memory at the data location of b + b.length - (current_index - 32)
              b_data := mload(add(add(b, 0x20), sub(mload(b), add(current_index, 32))))
          }
          a_data = a_data & mask;
          b_data = b_data & mask;
          // Add the input data and the carried data.
          // TODO - Limb overflow checks the implementation may break on a+b > 2^31*8 with carry != 0
          uint sum =  a_data + b_data + carry;
          // Coerce solidity into giving me the first byte as a small number;
          carry = uint8(bytes1(bytes32(sum)));
          // Slice off the carry
          sum = sum & mask;
          // Store the sum-ed digits
          assembly {
              mstore(add(add(c, 0x20), sub(mload(c), add(current_index, 32))), sum)
          }
          current_index += 31;
      }
      
      // Now we go byte by byte
      while (current_index < max(a.length, b.length)) {
          uint16 a_data;
          if (current_index < a.length) {
              a_data = uint16(uint8(a[a.length - current_index-1]));
          } else {
              a_data = 0;
          }
          
          uint16 b_data;
          if (current_index < b.length) {
              b_data = uint16(uint8(b[b.length - current_index-1]));
          } else {
              b_data = 0;
          }

          uint16 sum = a_data + b_data + carry;
          c[c.length - current_index-1] = bytes1(uint8(sum));
          carry = uint8(sum >> 8);
          current_index++;
      }
      c[0] = bytes1(carry);
      c = trim(c);
      return c;
  }

  // This extra digit allows us to preform the subtraction without underflow
  uint max_set_digit = 0x0100000000000000000000000000000000000000000000000000000000000000;
  // This function reverts on underflows, and expects trimed data
  function big_sub(bytes memory a, bytes memory b) internal view returns(bytes memory) {
      require(a.length >= b.length, "Subtraction underflow");
      // a - b =< a so this can't have more bytes than a
      bytes memory c = new bytes(a.length);
      // The index from the back of the data arrays [since this is Big endian]
      uint current_index = 0;
      uint8 carry = 0;
      // This loop grabs large numbers from the byte array for as long as we can
      while (a.length - current_index > 31 && b.length - current_index > 31) {
          // Will have 31 bytes of a's next digits
          uint a_data;
          // Will have 31 bytes of b's next digits
          uint b_data;
          assembly {
              //Load from memory at the data location of a + a.length - (current_index - 32)
              // This can load a bit of extra data which will be masked off.
              a_data := mload(add(add(a, 0x20), sub(mload(a), add(current_index, 32))))
              //Load from memory at the data location of b + b.length - (current_index - 32)
              b_data := mload(add(add(b, 0x20), sub(mload(b), add(current_index, 32))))
          }
          a_data = a_data & mask;
          b_data = b_data & mask;
          uint sub_digit;
          // We now check if we can sub b_data + carry from a_data
          if (a_data >= b_data + carry) {
              sub_digit = a_data - (b_data + carry);
              carry = 0;
          } else {
              // If not we add a one digit at the top of a, then sub
              sub_digit = (a_data + max_set_digit) - (b_data + carry);
              carry = 1;
          }

          // Store the sum-ed digits
          assembly {
              mstore(add(add(c, 0x20), sub(mload(c), add(current_index, 32))), sub_digit)
          }
          current_index += 31;
      }
      
      // Now we go byte by byte through the bytes of a
      while (current_index < a.length) {
          uint16 a_data = uint16(uint8(a[a.length - current_index-1]));
          
          // Since tighly packed this may implicly be zero without being set
          uint16 b_data;
          if (current_index < b.length) {
              b_data = uint16(uint8(b[b.length - current_index-1]));
          } else {
              b_data = 0;
          }

          uint sub_digit;
          // We now check if we can sub b_data + carry from a_data
          if (a_data >= b_data + carry) {
              sub_digit = a_data - (b_data + carry);
              carry = 0;
          } else {
              // If not we add a one digit at the top of a, then sub
              sub_digit = (a_data + 0x0100) - (b_data + carry);
              carry = 1;
          }

          c[c.length - current_index-1] = bytes1(uint8(sub_digit));
          current_index++;
      }
      require(carry == 0, "Underflow error");
      c = trim(c);
      return c;
  }

  function max(uint a, uint b) internal pure returns (uint) {
      return a > b ? a : b;
  }

  // Copied from https://github.com/kilic/evmvdf  
  function big_equal(bytes memory a, bytes memory b) internal pure returns (bool res) 
  {
    uint256 len = a.length;
    if (len == 0) {
      return false;
    }
    if (len % 32 != 0) {
      return false;
    }
    if (len != b.length) {
      return false;
    }
    uint256 i = 0;
    res = true;
    assembly {
      for {
        let ptr := 32
      } lt(ptr, add(len, 1)) {
        ptr := add(ptr, 32)
      } {
        i := add(i, 1)
        res := and(res, eq(mload(add(a, ptr)), mload(add(b, ptr))))
      }
    }
  }

// 0xC7970CEEDCC3B0754490201A7AA613CD73911081C790F5F1A8726F463550BB5B7FF0DB8E1EA1189EC72F93D1650011BD721AEEACC2ACDE32A04107F0648C2813A31F5B0B7765FF8B44B4B6FFC93384B646EB09C7CF5E8592D40EA33C80039F35B4F14A04B51F7BFD781BE4D1673164BA8EB991C2C4D730BBBE35F592BDEF524AF7E8DAEFD26C66FC02C479AF89D64D373F442709439DE66CEB955F3EA37D5159F6135809F85334B5CB1813ADDC80CD05609F10AC6A95AD65872C909525BDAD32BC729592642920F24C61DC5B3C3B7923E56B16A4D9D373D8721F24A3FC0F1B3131F55615172866BCCC30F95054C824E733A5EB6817F7BC16399D48C6361CC7E5
// Python: res=hex(0xC7970CEEDCC3B0754490201A7AA613CD73911081C790F5F1A8726F463550BB5B7FF0DB8E1EA1189EC72F93D1650011BD721AEEACC2ACDE32A04107F0648C2813A31F5B0B7765FF8B44B4B6FFC93384B646EB09C7CF5E8592D40EA33C80039F35B4F14A04B51F7BFD781BE4D1673164BA8EB991C2C4D730BBBE35F592BDEF524AF7E8DAEFD26C66FC02C479AF89D64D373F442709439DE66CEB955F3EA37D5159F6135809F85334B5CB1813ADDC80CD05609F10AC6A95AD65872C909525BDAD32BC729592642920F24C61DC5B3C3B7923E56B16A4D9D373D8721F24A3FC0F1B3131F55615172866BCCC30F95054C824E733A5EB6817F7BC16399D48C6361CC7E5>>2)
// res 0x31e5c33bb730ec1d512408069ea984f35ce4442071e43d7c6a1c9bd18d542ed6dffc36e387a84627b1cbe4f45940046f5c86bbab30ab378ca81041fc19230a04e8c7d6c2ddd97fe2d12d2dbff24ce12d91bac271f3d7a164b503a8cf2000e7cd6d3c52812d47deff5e06f93459cc592ea3ae6470b135cc2eef8d7d64af7bd492bdfa36bbf49b19bf00b11e6be275934dcfd109c250e7799b3ae557cfa8df54567d84d6027e14cd2d72c604eb772033415827c42b1aa56b5961cb2425496f6b4caf1ca564990a483c93187716cf0ede48f95ac5a93674dcf61c87c928ff03c6cc4c7d558545ca19af330c3e5415320939cce97ada05fdef058e6752318d8731f9

  // Divide by 4, i.e. shift right by 2 bits
  function big_shr2(bytes memory a) internal pure returns (bytes memory res) 
  {
    // Result is same length as input
    bytes memory c = new bytes(a.length);
    uint current_index = 0;
    uint8 a_carry = 0;
    // Now we go byte by byte
    while (current_index < a.length) {
      uint8 a_byte = uint8(a[current_index]);
      uint8 a_store = a_byte >> 2;
      uint8 next_carry = a_byte << 6;
      if (a_carry > 0) {
        a_store = a_store + a_carry;
      }
      c[current_index] = bytes1(a_store);
      current_index++;
      a_carry = next_carry;
    }
    return c;
  }

  // Vitalik said modmul can be done without a precompile via a * b = ((a + b)**2 - (a - b)**2) / 4.  
  // So this function does that math
  function big_mulmod(bytes memory a, bytes memory b, bytes memory mod) internal view returns(bytes memory c) {
      bytes memory part1 = bignum_expmod(modular_add(a, b, mod), 2, mod);
      bytes memory part2 = bignum_expmod(modular_sub(a, b, mod), 2, mod);
      bytes memory part3 = modular_sub(part1, part2, mod);  // part3 = (a+b)^2 - (a-b)^2 = 4ab % N, 
      bytes memory result = big_shr2(part3);    // then result is part3 >>2 = part3 / 4
      return result;
  }

  // This method verifies that proof p correctly asserts that xi^t mod N = yi 
  function verifyProof(bytes memory N, bytes memory xi,  uint256 d, bytes memory yi, uint8 index, bytes[] memory p) internal returns (bool) 
  {
      bytes memory ui = p[index];
      bytes16 ri = r_value(xi, yi, ui);      // This will be 16 bytes
      uint256 exp = uint256(bytes32(ri));
      xi = big_mulmod(bignum_expmod(xi, exp, N), ui, N);
      yi = big_mulmod(bignum_expmod(ui, exp, N), yi, N);

      // Recursion
      if (index+1 != p.length)
          return verifyProof(N, xi, d-1, yi, index+1, p);

      // When there are no more entries in the proof 
      uint256 e = 2**(2**d);            // Note: This is a problem, if d is >=8
      if (big_equal(yi,bignum_expmod(xi, e, N))) {
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
