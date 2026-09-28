// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SafeDelegatecallWallet {
    address public owner;
    // 修補：helper 改成 immutable，部署當下就固定死，之後任何人
    // （包括 owner 自己）都無法再指定 delegatecall 要打去哪個地址
    address public immutable helper;

    constructor(address _helper) payable {
        owner = msg.sender;
        helper = _helper;
    }

    // 修補：只有 owner 能觸發，而且目標一定是部署時就選定、
    // 經過稽核的 helper，不再接受任意地址
    function execute(bytes calldata data) public {
        require(msg.sender == owner, "SafeDelegatecallWallet: not owner");
        (bool success,) = helper.delegatecall(data);
        require(success, "SafeDelegatecallWallet: delegatecall failed");
    }

    function withdrawAll() public {
        require(msg.sender == owner, "SafeDelegatecallWallet: not owner");
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}
