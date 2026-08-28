// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title SafeVault
/// @notice `VulnerableVault` 的修補版本，示範兩層防禦（defense in depth）：
///
/// 1. **CEI（Checks-Effects-Interactions）**：在 `withdraw()` 裡，
///    先做檢查（Checks）、再更新狀態（Effects：把餘額歸零），
///    最後才做外部呼叫（Interactions：真正轉帳）。
///    這樣即使呼叫者在 `receive()` 裡遞迴呼叫 `withdraw()`，
///    這時候 `balances[msg.sender]` 已經是 0，`require(amount > 0)`
///    會直接 revert，攻擊在第一次遞迴就被擋下。
///
/// 2. **OpenZeppelin `ReentrancyGuard`**：`nonReentrant` modifier
///    用一個鎖（storage 變數）確保同一個函式不能在還沒執行完之前
///    被重新進入。就算未來改動程式碼不小心破壞了 CEI 順序，
///    這一層還是能擋下 reentrancy。
///
/// 業界標準做法是「兩者都用」，不是二選一：CEI 是免費的（不用額外
/// gas 或依賴），ReentrancyGuard 則是保險，兩者互為備援。
contract SafeVault is ReentrancyGuard {
    mapping(address => uint256) public balances;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice 領出呼叫者存入的全部 ETH（已修補 reentrancy）
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "SafeVault: nothing to withdraw");

        // --- Effect 在 Interaction 之前：符合 CEI ---
        balances[msg.sender] = 0;

        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "SafeVault: transfer failed");

        emit Withdrawn(msg.sender, amount);
    }

    function vaultBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
