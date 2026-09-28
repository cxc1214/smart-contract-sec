// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract SafeAccessControl is Ownable {
    mapping(address => uint256) public balances;

    constructor() Ownable(msg.sender) {}

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // 換所有權要用 OpenZeppelin Ownable 內建、已經受 onlyOwner 保護的
    // transferOwnership()，不再自己手刻一個沒有檢查的 setOwner()
    function withdrawAll() public onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }
}
