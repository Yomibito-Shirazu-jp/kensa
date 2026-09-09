// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
// BatchUmbraSender.sol
//
// Batch sender for Umbra stealth address payments.
// Deploys on L1, receives full lockbox amount, then sends
// 1 ETH to each stealth address in batches of ~500 per tx
// to stay within the 30M gas limit.
//
// Gas estimate per sendEth call: ~50,000 gas
// Batch size: 500 addresses -> ~25M gas (within 30M limit)
// Total batches for 199,815 addresses: ~400 txs
// At 12s/block: ~80 minutes for all batches
// ============================================================

interface IUmbra {
    function sendEth(
        address payable _receiver,
        uint256 _tollCommitment,
        bytes32 _pkx,
        bytes32 _ciphertext
    ) external payable;

    function toll() external view returns (uint256);
}

contract BatchUmbraSender {
    address public constant UMBRA = 0xFb2dc580Eed955B528407b4d36FfaFe3da685401;
    uint256 public constant BATCH_SIZE = 500;

    IUmbra public immutable umbra = IUmbra(UMBRA);
    uint256 public immutable toll;

    // Track how many stealth addresses have been funded
    uint256 public totalSent;
    uint256 public totalEthDistributed;

    event BatchSent(uint256 indexed batchIndex, uint256 count, uint256 totalSent);
    event Funded(address indexed sender, uint256 amount);

    constructor() {
        toll = umbra.toll();
    }

    // ============================================================
    // Receive ETH from the attacker (post-bridge)
    // ============================================================

    receive() external payable {
        emit Funded(msg.sender, msg.value);
    }

    // ============================================================
    // Batch send: 1 ETH to each stealth address
    //
    // @param _stealthAddrs  Array of stealth address (ERC-5564 derived)
    // @param _pkxs          Array of ephemeral public key x-coordinates
    // @param _ciphertexts   Array of encrypted payloads
    // @param _perSend       ETH amount per stealth address (1 ether)
    // ============================================================

    function batchSendEth(
        address payable[] calldata _stealthAddrs,
        bytes32[] calldata _pkxs,
        bytes32[] calldata _ciphertexts,
        uint256 _perSend
    ) external {
        uint256 len = _stealthAddrs.length;
        require(len == _pkxs.length && len == _ciphertexts.length, "array length mismatch");
        require(len <= BATCH_SIZE, "batch too large - exceeds gas limit");

        uint256 totalCost = (_perSend + toll) * len;
        require(address(this).balance >= totalCost, "insufficient balance for batch");

        for (uint256 i = 0; i < len; i++) {
            umbra.sendEth{value: _perSend + toll}(
                _stealthAddrs[i],
                toll,
                _pkxs[i],
                _ciphertexts[i]
            );
        }

        totalSent += len;
        totalEthDistributed += _perSend * len;

        emit BatchSent(totalSent / BATCH_SIZE, len, totalSent);
    }

    // ============================================================
    // Withdraw remaining ETH (for remainder handling)
    // ============================================================

    function withdraw(address payable _to) external {
        uint256 bal = address(this).balance;
        (bool ok,) = _to.call{value: bal}("");
        require(ok, "withdraw failed");
    }

    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
