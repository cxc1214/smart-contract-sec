// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SafeToken {
    mapping(address => uint256) public balances;

    constructor() {
        balances[msg.sender] = 1000;
    }

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "SafeToken: insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
