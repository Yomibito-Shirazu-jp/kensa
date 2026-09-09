#!/usr/bin/env bash
set -e
# Self-node (anvil) default; override with ETH_RPC_URL to use a different node.
export ETH_RPC_URL="${ETH_RPC_URL:-http://192.168.2.103:8545/}"
forge test --match-contract LagoonFreeChain -vv
