/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, Signer, utils } from "ethers";
import { Provider } from "@ethersproject/providers";
import type {
  PietrzakVerifier,
  PietrzakVerifierInterface,
} from "../PietrzakVerifier";

const _abi = [
  {
    inputs: [
      {
        internalType: "uint256",
        name: "x",
        type: "uint256",
      },
    ],
    name: "log2",
    outputs: [
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
    ],
    stateMutability: "pure",
    type: "function",
  },
  {
    inputs: [
      {
        components: [
          {
            internalType: "bytes",
            name: "val",
            type: "bytes",
          },
          {
            internalType: "bool",
            name: "neg",
            type: "bool",
          },
          {
            internalType: "uint256",
            name: "bitlen",
            type: "uint256",
          },
        ],
        internalType: "struct BigNumber",
        name: "_x",
        type: "tuple",
      },
      {
        components: [
          {
            internalType: "bytes",
            name: "val",
            type: "bytes",
          },
          {
            internalType: "bool",
            name: "neg",
            type: "bool",
          },
          {
            internalType: "uint256",
            name: "bitlen",
            type: "uint256",
          },
        ],
        internalType: "struct BigNumber",
        name: "_y",
        type: "tuple",
      },
      {
        components: [
          {
            internalType: "bytes",
            name: "val",
            type: "bytes",
          },
          {
            internalType: "bool",
            name: "neg",
            type: "bool",
          },
          {
            internalType: "uint256",
            name: "bitlen",
            type: "uint256",
          },
        ],
        internalType: "struct BigNumber",
        name: "_u",
        type: "tuple",
      },
    ],
    name: "r_value",
    outputs: [
      {
        internalType: "uint128",
        name: "",
        type: "uint128",
      },
    ],
    stateMutability: "pure",
    type: "function",
  },
];

export class PietrzakVerifier__factory {
  static readonly abi = _abi;
  static createInterface(): PietrzakVerifierInterface {
    return new utils.Interface(_abi) as PietrzakVerifierInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): PietrzakVerifier {
    return new Contract(address, _abi, signerOrProvider) as PietrzakVerifier;
  }
}