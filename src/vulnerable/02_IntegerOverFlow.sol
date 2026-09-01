// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract VulnerableToken{
    mapping(address => uint)public balances;

    constructor(){
        balances[msg.sender] = 1000;

    }

    function transfer(address to ,uint amount) public {
        balances[msg.sender] -= amount;
        balances[to] +=amount;
    }


}