// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VulnerableAccessControl {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // 漏洞：這個函式沒有任何權限檢查，任何人都能呼叫，
    // 把自己設成 owner，進而取得所有 onlyOwner 功能的控制權
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    function withdrawAll() public {
        require(msg.sender == owner, "VulnerableAccessControl: not owner");
        payable(owner).transfer(address(this).balance);
    }
}
