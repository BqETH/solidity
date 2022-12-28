pragma solidity >=0.8.0 <0.9.0;
//SPDX-License-Identifier: MIT
  // Some functions copied from https://github.com/kilic/evmvdf 
  // Some functions copied from 0x: https://github.com/0xProject/VDF/blob/master/contracts/Verifier.sol
import "hardhat/console.sol";

abstract contract ModMath {

  // Fast modexp knowing values are 2048 bits base^exponent % modulus
  // Copied from https://github.com/kilic/evmvdf 
  function modexp2048(bytes memory base, uint256 exponent, bytes memory modulus) internal view returns (bytes memory res) 
  {
    assembly {
      let mem := mload(0x40)

      mstore(mem, 256)              // <length_of_BASE> = 256 in bytes (2048 bits)
      mstore(add(mem, 0x20), 0x20)  // <length_of_EXPONENT> = 32 (256 bits)
      mstore(add(mem, 0x40), 256)   // <length_of_MODULUS> = 256 (2048 bits)

      mstore(add(mem, 0x60), mload(add(base, 0x20)))
      mstore(add(mem, 0x80), mload(add(base, 0x40)))
      mstore(add(mem, 0xa0), mload(add(base, 0x60)))
      mstore(add(mem, 0xc0), mload(add(base, 0x80)))
      mstore(add(mem, 0xe0), mload(add(base, 0xa0)))
      mstore(add(mem, 0x100), mload(add(base, 0xc0)))
      mstore(add(mem, 0x120), mload(add(base, 0xe0)))
      mstore(add(mem, 0x140), mload(add(base, 0x100)))

      mstore(add(mem, 0x160), exponent)

      mstore(add(mem, 0x180), mload(add(modulus, 0x20)))
      mstore(add(mem, 0x1a0), mload(add(modulus, 0x40)))
      mstore(add(mem, 0x1c0), mload(add(modulus, 0x60)))
      mstore(add(mem, 0x1e0), mload(add(modulus, 0x80)))
      mstore(add(mem, 0x200), mload(add(modulus, 0xa0)))
      mstore(add(mem, 0x220), mload(add(modulus, 0xc0)))
      mstore(add(mem, 0x240), mload(add(modulus, 0xe0)))
      mstore(add(mem, 0x260), mload(add(modulus, 0x100)))

      let success := staticcall(sub(gas(), 2000), 5, mem, 0x280, add(mem, 0x20), 256)
      switch success
        case 0 {
          revert(0x0, 0x0)
        }
      // update free mem pointer
      mstore(0x40, add(mem, 0x120))  // 0x20 bytes for length (32) + 0x100 bytes for the number (256 bytes)
      res := mem
    }
  }

  // From 0x: Function below copied from the 0x Wesolowski VDF verification contract
  function trim(bytes memory data) internal pure returns(bytes memory) 
  {
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

  // From 0x: Expmod for bignum operands (encoded as bytes, only base and modulus) 
//   function bignum_expmod(bytes memory base, uint256 e, bytes memory m) public view returns (bytes memory o) 
//   {
//       assembly {
//           // Get free memory pointer
//           let p := mload(0x40)

//           // Get base length in bytes
//           let bl := mload(base)
//           // Get modulus length in bytes
//           let ml := mload(m)

//           // Store parameters for the Expmod (0x05) precompile
//           mstore(p, bl)               // Length of Base
//           mstore(add(p, 0x20), 0x20)  // Length of Exponent
//           mstore(add(p, 0x40), ml)    // Length of Modulus
//           // Use Identity (0x04) precompile to memcpy the base
//           if iszero(staticcall(10000, 0x04, add(base, 0x20), bl, add(p, 0x60), bl)) {
//               revert(0, 0)
//           }
//           mstore(add(p, add(0x60, bl)), e) // Exponent
//           // Use Identity (0x04) precompile to memcpy the modulus
//           if iszero(staticcall(10000, 0x04, add(m, 0x20), ml, add(add(p, 0x80), bl), ml)) {
//               revert(0, 0)
//           }
          
//           // Call 0x05 (EXPMOD) precompile
//           if iszero(staticcall(sub(gas(), 2000), 0x05, p, add(add(0x80, bl), ml), add(p, 0x20), ml)) {
//               revert(0, 0)
//           }

//           // Update free memory pointer
//           mstore(0x40, add(add(p, ml), 0x20))

//           // Store correct bytelength at p. This means that with the output
//           // of the Expmod precompile (which is stored as p + 0x20)
//           // there is now a bytes array at location p
//           mstore(p, ml)

//           // Return p
//           o := p
//       }
//   }

  // From 0x: Returns (a <= b);
  // Requires trimmed inputs
  function lte(bytes memory a, bytes memory b) internal pure returns (bool) 
  {
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

  // This extra digit allows us to preform the subtraction without underflow
  uint max_set_digit = 0x0100000000000000000000000000000000000000000000000000000000000000;
  uint mask = 0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

  function big_add(bytes memory a, bytes memory b) internal view returns(bytes memory) 
  {
      // a + b < 2*max(a, b) so this can't have more bytes than the max length + 1
      bytes memory c = new bytes(max(a.length, b.length) + 1);
      // The index from the back of the data arrays [since this is Big endian]
      uint current_index = 0;
      uint8 carry = 0;
      
      // // This loop grabs large numbers from the byte array for as long as we can
      // while (a.length - current_index > 31 && b.length - current_index > 31) {
      //     // Will have 31 bytes of a's next digits
      //     uint a_data;
      //     // Will have 31 bytes of b's next digits
      //     uint b_data;
      //     assembly {
      //         //Load from memory at the data location of a + a.length - (current_index - 32)
      //         // This can load a bit of extra data which will be masked off.
      //         a_data := mload(add(add(a, 0x20), sub(mload(a), add(current_index, 32))))
      //         //Load from memory at the data location of b + b.length - (current_index - 32)
      //         b_data := mload(add(add(b, 0x20), sub(mload(b), add(current_index, 32))))
      //     }
      //     a_data = a_data & mask;
      //     b_data = b_data & mask;
      //     // Add the input data and the carried data.
      //     // TODO - Limb overflow checks the implementation may break on a+b > 2^31*8 with carry != 0
      //     uint sum =  a_data + b_data + carry;
      //     // Coerce solidity into giving me the first byte as a small number;
      //     carry = uint8(bytes1(bytes32(sum)));
      //     // Slice off the carry
      //     sum = sum & mask;
      //     // Store the sum-ed digits
      //     assembly {
      //         mstore(add(add(c, 0x20), sub(mload(c), add(current_index, 32))), sum)
      //     }
      //     current_index += 31;
      // }

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

  function big_sub(bytes memory a, bytes memory b) public view returns(bytes memory) 
  {
      require(a.length >= b.length, "Subtraction underflow");
      // a - b =< a so this can't have more bytes than a
      bytes memory c = new bytes(a.length);
      // The index from the back of the data arrays [since this is Big endian]
      uint current_index = 0;
      uint8 carry = 0;
      
      // This loop grabs large numbers from the byte array for as long as we can
      // while (a.length - current_index > 31 && b.length - current_index > 31) {
      //     // Will have 31 bytes of a's next digits
      //     uint a_data;
      //     // Will have 31 bytes of b's next digits
      //     uint b_data;
      //     assembly {
      //         //Load from memory at the data location of a + a.length - (current_index - 32)
      //         // This can load a bit of extra data which will be masked off.
      //         a_data := mload(add(add(a, 0x20), sub(mload(a), add(current_index, 32))))
      //         //Load from memory at the data location of b + b.length - (current_index - 32)
      //         b_data := mload(add(add(b, 0x20), sub(mload(b), add(current_index, 32))))
      //     }
      //     a_data = a_data & mask;
      //     b_data = b_data & mask;
      //     uint sub_digit;
      //     // We now check if we can sub b_data + carry from a_data
      //     if (a_data >= b_data + carry) {
      //         sub_digit = a_data - (b_data + carry);
      //         carry = 0;
      //     } else {
      //         // If not we add a one digit at the top of a, then sub
      //         sub_digit = (a_data + max_set_digit) - (b_data + carry);
      //         carry = 1;
      //     }

      //     // Store the sum-ed digits
      //     assembly {
      //         mstore(add(add(c, 0x20), sub(mload(c), add(current_index, 32))), sub_digit)
      //     }
      //     current_index += 31;
      // }

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

  // If we just want the absolute difference
  function abs_sub(bytes memory a, bytes memory b) internal view returns(bytes memory) 
  {
    if (lte(a,b)) {
        return big_sub(b,a);
    }
    else {
        return big_sub(a,b);
    }
  }

  // Copied from https://github.com/kilic/evmvdf 
  function mul2048(bytes memory a, bytes memory b) internal pure returns (bytes memory res) 
  {
    assembly {
      let mem := mload(64)
      mstore(mem, 512)
      mstore(64, add(mem, 576))

      let r := not(0)
      let u1
      let u2
      let u3
      let mm
      let ai

      // a0 * bj
      {
        ai := mload(add(a, 256)) // a0
        u1 := mload(add(b, 256)) // b0

        // a0 * b0
        mm := mulmod(ai, u1, r)
        u1 := mul(ai, u1) // La0b0
        u2 := sub(sub(mm, u1), lt(mm, u1)) // Ha0b0

        // store z0 = La0b0
        mstore(add(mem, 512), u1)
        // u1, u3 free, u2: Ha0b0

        for {
          let ptr := 224
        } gt(ptr, 0) {
          ptr := sub(ptr, 32)
        } {
          // a0 * bj
          u1 := mload(add(b, ptr))
          {
            mm := mulmod(ai, u1, r)
            u1 := mul(ai, u1) // La0bj
            u3 := sub(sub(mm, u1), lt(mm, u1)) // Ha0bj
          }

          u1 := add(u1, u2) // zi = La0bj + Ha0b_(j-1)
          u2 := add(u3, lt(u1, u2)) // Ha0bj = Ha0bj + c
          mstore(add(mem, add(ptr, 256)), u1) // store zi
          // carry u2 to next iter
        }
      }

      mstore(add(256, mem), u2) // store z_(i+8)

      // ai
      // i from 1 to 7
      for {
        let optr := 224
      } gt(optr, 0) {
        optr := sub(optr, 32)
      } {
        mstore(add(add(optr, mem), 32), u2) // store z_(i+8)
        ai := mload(add(a, optr)) // ai
        u1 := mload(add(b, 256)) // b0
        {
          // ai * b0
          mm := mulmod(ai, u1, r)
          u1 := mul(ai, u1) // La1b0
          u2 := sub(sub(mm, u1), lt(mm, u1)) // Haib0
        }

        mm := add(mem, add(optr, 256))
        u3 := mload(mm) // load zi
        u1 := add(u1, u3) // zi = zi + Laib0
        u2 := add(u2, lt(u1, u3)) // Haib0' = Haib0 + c
        mstore(mm, u1) // store zi
        // u1, u3 free, u2: Haib0

        // bj, j from 1 to 7
        for {
          let iptr := 224
        } gt(iptr, 0) {
          iptr := sub(iptr, 32)
        } {
          u1 := mload(add(b, iptr)) // bj
          {
            // ai * bj
            mm := mulmod(ai, u1, r)
            u1 := mul(ai, u1) // Laibj
            u3 := sub(sub(mm, u1), lt(mm, u1)) // Haibj
          }
          u1 := add(u1, u2) // Laibj + Haib0
          u3 := add(u3, lt(u1, u2)) // Haibj' = Haibj + c
          mm := add(mem, add(iptr, optr))
          u2 := mload(mm) // zi
          u1 := add(u1, u2) // zi = zi + (Laibj + Haib0)
          u2 := add(u3, lt(u1, u2)) // Haibj' = Ha1bj + c
          mstore(mm, u1) // store zi
          // carry u2 to next iter
        }
      }
      mstore(add(32, mem), u2) // store z15
      res := mem
    }
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

  // Vitalik said modmul can be done without a precompile via 
  // (a * b) %N = [((a + b)**2 - (a - b)**2) // 4] % N.  
  // So this function does that math
  function big_mulmod(bytes memory a, bytes memory b, bytes memory mod) public view returns(bytes memory c) {
      console.log("a:");console.logBytes(abi.encodePacked(a));
      console.log("b:");console.logBytes(abi.encodePacked(b));
      bytes memory apb = big_add(a, b);
      console.log("apb:");console.logBytes(abi.encodePacked(apb));
      bytes memory apb2 = mul2048(apb, apb);    // 4069 bits
      console.log("apb2:");console.logBytes(abi.encodePacked(apb2));
      bytes memory amb = abs_sub(a, b);
      console.log("amb:");console.logBytes(abi.encodePacked(amb));
      bytes memory amb2 = mul2048(amb, amb);    // 4096 bits
      console.log("amb2:");console.logBytes(abi.encodePacked(amb2));
      bytes memory apb2amb2 = big_sub(apb2, amb2);  // apb2amb2 = (a+b)^2 - (a-b)^2 = 4ab % N
      bytes memory result = big_shr2(apb2amb2);    // then result is part3 >>2 = part3 / 4
      if (lte(result,mod)) {
        return trim(result);
      }
      else {
        return trim(big_sub(result,mod));
      }
  }

}
