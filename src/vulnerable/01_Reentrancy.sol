// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableVault
/// @notice 教學用漏洞合約 —— 刻意違反 Checks-Effects-Interactions (CEI) 模式。
///
/// @dev 漏洞說明：
/// `withdraw()` 的執行順序是「先轉帳、後更新狀態」：
///   1. 用 `.call{value: amount}("")` 把 ETH 轉給呼叫者（Interaction）
///   2. 轉帳成功後才把 `balances[msg.sender]` 歸零（Effect）
///
/// 如果呼叫者是一個合約，`.call` 會觸發它的 `receive()` / `fallback()`，
/// 而此時 `balances[msg.sender]` 都還沒被清空 —— 呼叫者可以在自己的
/// `receive()` 裡「遞迴」再呼叫一次 `withdraw()`，因為狀態還沒更新，
/// require 檢查依然會通過，於是可以在同一筆交易裡把整個 Vault 的
/// ETH 全部領光。這就是經典的 single-function reentrancy，
/// 也是 2016 年 The DAO 事件的核心漏洞模式。
///
/// 正確做法（見 `src/fixed/01_Reentrancy_Fixed.sol`）：
///   - 遵循 CEI：先更新狀態，最後才做外部呼叫
///   - 或使用 OpenZeppelin 的 `ReentrancyGuard`（`nonReentrant` modifier）
///   - 理想上兩者一起用，屬於防禦性寫法（defense in depth）
contract VulnerableVault {
    mapping(address => uint256) public balances;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    /// @notice 存入 ETH，記錄在呼叫者名下
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice 領出呼叫者存入的全部 ETH
    /// @dev 漏洞點：外部呼叫（轉帳）發生在狀態更新（歸零餘額）之前
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "VulnerableVault: nothing to withdraw");

        // --- Interaction 在 Effect 之前，違反 CEI，這就是漏洞 ---
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "VulnerableVault: transfer failed");

        // 攻擊者的 receive() 會在上面這行 .call 執行期間被觸發，
        // 此時下面這行還沒跑到，balances[msg.sender] 仍是舊值。
        balances[msg.sender] = 0;
    }

    /// @notice 查詢合約目前持有的 ETH 總額，方便測試斷言
    function vaultBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
