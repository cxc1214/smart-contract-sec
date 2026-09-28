// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VulnerableDelegatecallWallet {
    // owner 必須是這個合約的第一個 state variable（storage slot 0），
    // 這是這個漏洞能成立的關鍵前提，稍後解釋
    address public owner;
    address public helper;

    constructor(address _helper) payable {
        owner = msg.sender;
        helper = _helper;
    }

    // 漏洞：任何人都能指定「要 delegatecall 去哪個地址、帶什麼資料」。
    // delegatecall 執行的是目標合約的程式碼，但用的是「呼叫者自己」的
    // storage、msg.sender、msg.value——等於讓外部程式碼在自己家裡跑。
    function execute(address target, bytes calldata data) public {
        (bool success,) = target.delegatecall(data);
        require(success, "VulnerableDelegatecallWallet: delegatecall failed");
    }

    function withdrawAll() public {
        require(msg.sender == owner, "VulnerableDelegatecallWallet: not owner");
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}
