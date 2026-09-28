# 漏洞 #3：Access Control（權限控管缺陷）

> 對應程式碼：
> - 漏洞版：[`src/vulnerable/03_AccessControl.sol`](../../src/vulnerable/03_AccessControl.sol)
> - 修補版：[`src/fixed/03_AccessControl_Fixed.sol`](../../src/fixed/03_AccessControl_Fixed.sol)
> - 測試：[`test/exploits/03_AccessControl.t.sol`](../../test/exploits/03_AccessControl.t.sol)

## 漏洞原理

`VulnerableAccessControl` 是一個有 `owner` 概念的簡易金庫：`owner` 可以呼叫 `withdrawAll()` 把合約裡所有人存的錢一次領走。問題出在換所有權的這個函式：

```solidity
address public owner;

// 漏洞：這個函式沒有任何權限檢查
function setOwner(address newOwner) public {
    owner = newOwner;
}

function withdrawAll() public {
    require(msg.sender == owner, "VulnerableAccessControl: not owner");
    payable(owner).transfer(address(this).balance);
}
```

`withdrawAll()` 本身有檢查 `msg.sender == owner`，看起來沒問題；但決定「誰是 owner」的 `setOwner()` 卻完全沒有檢查呼叫者身分——任何人都能呼叫它，把自己設成新的 owner。這是 Access Control 漏洞最典型的樣貌：**不是忘記寫權限檢查，而是把檢查放在錯的地方**——保護了「動作」卻沒保護「授權」本身。

這不是憑空想像的風險。2017 年 7 月的 [Parity 多簽錢包事件](https://www.parity.io/blog/a-postmortem-on-the-parity-multi-sig-library-self-destruct/) 就是同一種漏洞模式：一個共用的錢包函式庫合約，其初始化函式 `initWallet()` 沒有限制只能被呼叫一次或只能被特定人呼叫，攻擊者直接呼叫它把自己設成 owner，接著呼叫函式庫的 `kill()` 把整個函式庫合約自毀，導致所有依賴這個函式庫的錢包（合計約 51.3 萬顆 ETH，當時價值超過 1.5 億美元）永久凍結，至今無法動用。

## 攻擊流程

`test_Exploit_AnyoneCanHijackOwnershipAndDrain` 示範了完整過程：

1. 一般使用者 alice 存入 1 ETH。
2. 攻擊者直接呼叫 `setOwner(attacker)`——不需要任何權限，這一步就成功了。
3. 攻擊者現在是 `owner`，呼叫 `withdrawAll()`，`require(msg.sender == owner)` 檢查通過，把 alice 存的錢全部領走。

```
[PASS] test_Exploit_AnyoneCanHijackOwnershipAndDrain() (gas: 134996)
```

攻擊者全程不需要原本的 owner 簽署或洩漏任何私鑰，純粹是利用「設定所有權」這個動作本身沒有被保護。

## 修補方式：`SafeAccessControl`

不是自己手刻一個「加上 `require(msg.sender == owner)` 的 `setOwner()`」，而是直接繼承 OpenZeppelin 的 `Ownable`：

```solidity
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract SafeAccessControl is Ownable {
    mapping(address => uint256) public balances;

    constructor() Ownable(msg.sender) {}

    function withdrawAll() public onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }
}
```

換所有權改用 `Ownable` 內建、本來就掛了 `onlyOwner` 修飾詞的 `transferOwnership()`，不再自己重新發明一個容易漏掉檢查的版本。這跟 Week 1（CEI + ReentrancyGuard）、Week 2（內建溢位保護 + 明確 `require`）是同一個原則：**手寫的邏輯負責解決問題本身，但凡是「誰有權限做這件事」這種跟安全直接相關的機制，優先用經過大量稽核的函式庫，而不是自己重新刻一份。**

## 修補驗證

```
[PASS] test_Patched_SafeAccessControl_BlocksUnauthorizedOwnershipChange() (gas: 98396)
[PASS] test_NormalFlow_OwnerCanWithdraw() (gas: 94344)
```

- `test_Patched_SafeAccessControl_BlocksUnauthorizedOwnershipChange`：攻擊者呼叫 `transferOwnership(attacker)`，直接被 `onlyOwner` 擋下，丟出 OpenZeppelin 定義的 `OwnableUnauthorizedAccount` 錯誤；owner 身分跟 alice 存的錢完全未受影響。
- `test_NormalFlow_OwnerCanWithdraw`：真正的 owner 呼叫 `withdrawAll()` 依然正常運作，證明修補沒有破壞既有功能。

## 小結

Access Control 漏洞的本質往往不是「少了一個 `require`」這麼單純，而是**權限檢查被放在錯誤的位置**——保護了看起來敏感的函式（如提款），卻漏掉了真正決定「誰有資格」的那個環節（如換所有權、初始化）。稽核這類漏洞時，不能只看「這個函式有沒有檢查權限」，還要往上追問「決定這個權限的機制本身，是不是也一樣被保護著」。Parity 事件證明了這個疏忽的代價可以有多大——被凍結的資金至今仍未解凍。
