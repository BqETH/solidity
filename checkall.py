# import the following dependencies
import json
import os
import queue
import signal
import sys

from web3 import Web3
from typing import cast

import ujson
from web3.contract import ContractEvent
from web3.exceptions import TimeExhausted

from web3.providers import JSONBaseProvider
from web3.types import RPCResponse, EventData

import asyncio
import hashlib
import math
# Setting up the Queue  (threading for network bound, multiprocessing for cpu bound)
from multiprocessing import Process, Queue, Lock, Manager
# logger = multiprocessing.log_to_stderr()
# logger.setLevel(multiprocessing.SUBDEBUG)

# Some global defaults here

chain_url = 'http://localhost:8545'

web3 = Web3(Web3.HTTPProvider(chain_url))
# web3.provider.request_counter = itertools.count(start=1)  # Does this fix my parser problems ?

wallet_addr = '0xBcd4042DE499D14e55001CcbB24a551F3b954096'

# This is unique for each ABI
contract_address = '0x5fbdb2315678afecb367f032d93f642f64180aa3'
contract_abi = ''
abi = open('./artifacts/contracts/BqETH.sol/BqETH.json')
contract_json = json.loads(abi.read())
checksum_address = Web3.toChecksumAddress(contract_address)
contract = web3.eth.contract(checksum_address, abi=contract_json["abi"])

last_block_checked = 1

old_gas_cost = 0
new_gas_cost = 0
mod_exp = 0

SDATELEN = len('0x182ff5fda61')    # Start Date String Length, to distinguish from a pid.
CORES = 4

# Multiprocessing data structures
# Create the Queue object
queue = Queue(maxsize=0)
# Store intermediate puzzles
manager = Manager()
puzzles = manager.dict()
working = manager.dict()
# Create a lock object to synchronize resource access
lock = Lock()

def _fast_decode_rpc_response(raw_response: bytes) -> RPCResponse:
    decoded = ujson.loads(raw_response)
    return cast(RPCResponse, decoded)


def patch_provider(provider: JSONBaseProvider):
    """Monkey-patch web3.py provider for faster JSON decoding.

    Call this on your provider after construction.

    This greatly improves JSON-RPC API access speeds, when fetching
    multiple and large responses.
    """
    provider.decode_rpc_response = _fast_decode_rpc_response


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ResetAll = "\033[0m"
    Bold = "\033[1m"
    Dim = "\033[2m"
    Underlined = "\033[4m"
    Blink = "\033[5m"
    Reverse = "\033[7m"
    Hidden = "\033[8m"
    ResetBold = "\033[21m"
    ResetDim = "\033[22m"
    ResetUnderlined = "\033[24m"
    ResetBlink = "\033[25m"
    ResetReverse = "\033[27m"
    ResetHidden = "\033[28m"
    Default = "\033[39m"
    Black = "\033[30m"
    Red = "\033[31m"
    Green = "\033[32m"
    Yellow = "\033[33m"
    Blue = "\033[34m"
    Magenta = "\033[35m"
    Cyan = "\033[36m"
    LightGray = "\033[37m"
    DarkGray = "\033[90m"
    LightRed = "\033[91m"
    LightGreen = "\033[92m"
    LightYellow = "\033[93m"
    LightBlue = "\033[94m"
    LightMagenta = "\033[95m"
    LightCyan = "\033[96m"
    White = "\033[97m"
    BackgroundDefault = "\033[49m"
    BackgroundBlack = "\033[40m"
    BackgroundRed = "\033[41m"
    BackgroundGreen = "\033[42m"
    BackgroundYellow = "\033[43m"
    BackgroundBlue = "\033[44m"
    BackgroundMagenta = "\033[45m"
    BackgroundCyan = "\033[46m"
    BackgroundLightGray = "\033[47m"
    BackgroundDarkGray = "\033[100m"
    BackgroundLightRed = "\033[101m"
    BackgroundLightGreen = "\033[102m"
    BackgroundLightYellow = "\033[103m"
    BackgroundLightBlue = "\033[104m"
    BackgroundLightMagenta = "\033[105m"
    BackgroundLightCyan = "\033[106m"
    BackgroundWhite = "\033[107m"


# define function to handle events and print to the console
def handle_claimedPuzzleEvent(event):

    try:
        receipt = web3.eth.waitForTransactionReceipt(event['transactionHash'], timeout=120)
    except TimeExhausted:
        print("Time Exhausted")
        pass    # Just catching this error for large payloads, not critical to get receipt here.

    pid = event.args.pid
    y = event.args.y
    sdate = event.args.sdate
    reward = event.args.reward

    with lock:
        print(f"{bcolors.Cyan} Puzzle claimed event with hash: {hex(pid)[:8]} Reward:  {Web3.fromWei(reward, 'wei')/1000000000000000000} ... removing {bcolors.ENDC}")
        if pid in puzzles:
            del puzzles[pid]
        if pid in working:
            print(f"Process: {working[pid]} might still be busy claiming puzzle {hex(pid)[:8]}, or should give up.")

    # with lock:
    #     for k in puzzles.keys():
    #         print(f"Puzzle {hex(k)[:8]} still in Puzzles. -> {hex(puzzles[k][10])[:8]}")
    #     print("\n")

    with lock:
        if len(hex(sdate)) > SDATELEN:
            next_pid = sdate
            # If we can work on this puzzle, and are not already working on it
            if next_pid in puzzles and next_pid not in working:
                # print(f"Next puzzle found, with pid: {hex(next_pid)}")
                next_puzzle = puzzles[next_pid]
                # print(f"Changing next puzzle challenge from {next_puzzle[2]} ")
                # print(f" to pow({y}, {next_puzzle[2]}, {next_puzzle[1]}) = {pow(y, next_puzzle[2], next_puzzle[1])}")
                next_puzzle[2] = pow(y, next_puzzle[2], next_puzzle[1])  # x1=y0^rnd1 mod N
                if next_pid:
                    queue.put(next_pid)


async def event_loop(queue, lock, poll_interval):

    ignore_method: ContractEvent = getattr(contract.events, 'RewardClaimed')
    # Remove the event filter crap because nodes like hardhat, or web3.py tend to forget them
    # causing this code to crash when it can't find it after 5 minutes
    global last_block_checked
    while True:

        with lock:
            block = web3.eth.get_block('latest')
        bn = block.number
        # with lock:
        #     print(f"Current Block Number: {bn}, last_block_checked: {last_block_checked}")
        try:
            if bn > last_block_checked:
                claimed: list[EventData] = []
                # Let's make sure the RPC request won't be too large
                while bn > last_block_checked:
                    last_block_checked += 1
                    claimed.extend(ignore_method.getLogs(fromBlock=last_block_checked, toBlock=last_block_checked))

                for entry in claimed:
                    handle_claimedPuzzleEvent(entry)
        except ValueError:
            print("Unable to parse response from getLogs. Trying Later.")

        return 

def main():

    print(f"This dumb Puzzle farmer listens to the BqETH contract events for Puzzle Creation")
    print(f"solves every puzzle, and claims its prize, sequentially")

    balance = web3.eth.getBalance(wallet_addr)/1000000000000000000
    print(f"Farmer ETH balance: {balance}\n")

    patch_provider(web3)

    if __name__ == '__main__':

        consumers = []

        # Remove the original signal handler
        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Redefine the signal handler so children will inherit it.
        signal.signal(signal.SIGINT, original_sigint_handler)

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            asyncio.gather(
                event_loop(queue, lock, 2))
        )  # 2 Seconds
    except KeyboardInterrupt:
        sys.stdout.write('\b\b\b')
        print("Caught KeyboardInterrupt, terminating workers")
        for c in consumers:
            c.terminate()

    except ConnectionError:
        print("Remote chain stopped responding. Aborting...")

    finally:
        # close loop to free up system resources
        loop.close()


if __name__ == "__main__":
    main()
