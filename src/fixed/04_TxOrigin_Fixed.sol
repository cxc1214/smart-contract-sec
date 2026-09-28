// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SafeTxOriginWallet {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    function deposit() external payable {}

    // 修補：改用 msg.sender，也就是「直接呼叫這個函式的地址」。
    // 如果 owner 是透過中間的惡意合約間接觸發這次呼叫，
    // msg.sender 會是那個中間合約，不會是 owner 本人，檢查會失敗。
    function transfer(address payable to, uint256 amount) public {
        require(msg.sender == owner, "SafeTxOriginWallet: not owner");
        to.transfer(amount);
    }

    receive() external payable {}
}
