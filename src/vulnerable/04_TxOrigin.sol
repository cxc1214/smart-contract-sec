// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VulnerableTxOriginWallet {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    function deposit() external payable {}

    // 漏洞：用 tx.origin 判斷身分，而不是 msg.sender。
    // tx.origin 是「整條呼叫鏈最源頭的那個帳戶」，就算 owner 是被中間的
    // 惡意合約騙去呼叫，tx.origin 仍然是 owner，這個檢查照樣會過。
    function transfer(address payable to, uint256 amount) public {
        require(tx.origin == owner, "VulnerableTxOriginWallet: not owner");
        to.transfer(amount);
    }

    receive() external payable {}
}
