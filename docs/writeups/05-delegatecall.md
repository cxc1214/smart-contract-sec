# 漏洞 #5：Delegatecall Storage Hijack（delegatecall 儲存空間劫持）

> 對應程式碼：
> - 漏洞版：[`src/vulnerable/05_Delegatecall.sol`](../../src/vulnerable/05_Delegatecall.sol)
> - 修補版：[`src/fixed/05_Delegatecall_Fixed.sol`](../../src/fixed/05_Delegatecall_Fixed.sol)
> - 測試：[`test/exploits/05_Delegatecall.t.sol`](../../test/exploits/05_Delegatecall.t.sol)

## 漏洞原理

一般的 `call` 呼叫另一個合約時，對方的程式碼是在**對方自己的** storage、以對方自己的身分執行；`delegatecall` 則相反——執行的是對方的程式碼，但用的卻是**呼叫者自己**的 storage、`msg.sender`、`msg.value`。這個機制原本是為了讓合約能像「共用邏輯庫」一樣被重複使用，但如果 delegatecall 的目標可以被任何人指定，等於讓外部人的程式碼在自己家（自己的 storage）裡執行：

```solidity
address public owner;   // slot 0
address public helper;  // slot 1

function execute(address target, bytes calldata data) public {
    (bool success,) = target.delegatecall(data);
    require(success, "VulnerableDelegatecallWallet: delegatecall failed");
}
```

`execute()` 沒有任何權限檢查，任何人都能呼叫，而且 `target` 是呼叫者自己決定的——等於任何人都能讓任意程式碼在這個合約的 storage 裡執行。

## 攻擊流程

攻擊合約 `DelegatecallAttacker` 只有一個 state variable：

```solidity
contract DelegatecallAttacker {
    address public owner;  // 同樣落在 slot 0

    function pwn() external {
        owner = msg.sender;
    }
}
```

`test_Exploit_DelegatecallHijacksOwnerSlot` 示範了完整過程：

1. 攻擊者部署 `DelegatecallAttacker`，它的 `owner` 變數同樣位於 slot 0——這不是巧合，是攻擊者刻意讓它跟目標錢包的 storage layout 對齊。
2. 攻擊者呼叫 `vulnerable.execute(address(attackerContract), abi.encodeWithSignature("pwn()"))`。
3. `delegatecall` 執行 `pwn()` 的程式碼，但寫入的 `owner = msg.sender` 實際上寫進的是 `vulnerable` 合約自己的 slot 0——也就是 `vulnerable.owner`。`msg.sender` 在 delegatecall 情境下維持不變，仍然是攻擊者本人。
4. `vulnerable.owner` 被覆寫成攻擊者的地址，完全不需要原本 owner 的任何簽署。
5. 攻擊者現在是 owner，呼叫 `withdrawAll()` 把資金領走。

```
[PASS] test_Exploit_DelegatecallHijacksOwnerSlot() (gas: 96815)
```

這正是 2017 年 11 月 [Parity 多簽錢包函式庫遭自毀事件](https://www.parity.io/blog/a-postmortem-on-the-parity-multi-sig-library-selfdestruct/) 的核心機制：大量錢包合約把自己的邏輯 `delegatecall` 到同一個共用函式庫合約，一旦這個函式庫本身可以被任何人取得控制權（並非透過本篇示範的 storage 對齊手法，而是函式庫自己從未被初始化），攻擊者呼叫函式庫的 `selfdestruct`，所有依賴它的錢包（約 587 個，合計約 15 萬顆 ETH）瞬間全部失去邏輯合約、資金永久凍結至今。這起事件與本篇（連同 [Week 3 的 writeup](03-access-control.md) 引用的 2017 年 7 月事件）同屬 Parity 多簽錢包一系列事故，共同點都是：**把關鍵邏輯或控制權放進一個外部可觸及的執行路徑，卻沒有嚴格限制誰能觸發它。**

## 修補方式：`SafeDelegatecallWallet`

兩個獨立的限制疊在一起：

```solidity
address public immutable helper;  // 部署後無法再更改

function execute(bytes calldata data) public {
    require(msg.sender == owner, "SafeDelegatecallWallet: not owner");
    (bool success,) = helper.delegatecall(data);
    require(success, "SafeDelegatecallWallet: delegatecall failed");
}
```

**第一層：目標不再是任意地址**——`helper` 改成 `immutable`，部署當下就寫死，之後任何人都無法再指定 delegatecall 要打去哪裡，等於從根本上排除了「攻擊者提供惡意合約」這個攻擊面。

**第二層：呼叫者身分檢查**——就算未來需要讓 `execute()` 的行為可以被觸發，也只有 `owner` 才能呼叫，一般攻擊者連嘗試的資格都沒有。

## 修補驗證

```
[PASS] test_Patched_SafeDelegatecallWallet_BlocksUnauthorizedExecute() (gas: 45562)
[PASS] test_NormalFlow_OwnerCanUseFixedHelper() (gas: 82421)
```

- `test_Patched_SafeDelegatecallWallet_BlocksUnauthorizedExecute`：攻擊者呼叫 `execute()` 直接被 `onlyOwner` 檢查擋下，`owner` 這個 slot 完全未被寫入、資金也毫髮無傷。
- `test_NormalFlow_OwnerCanUseFixedHelper`：owner 呼叫 `execute()` 使用固定、經過稽核的 `helper`，功能正常運作，也證明只要 helper 本身不宣告任何會跟呼叫者 storage 對齊的變數，就不會有意外覆寫的風險。

## 小結

Delegatecall 的危險不在於這個操作碼本身，而在於它把「執行程式碼」跟「決定用誰的 storage 執行」這兩件事綁在一起——一旦目標地址可以被外部操控，攻擊者不需要找傳統的邏輯漏洞，只要讓自己的變數跟受害合約的 storage slot 對齊，就能直接覆寫任何一個 state variable，包括最關鍵的 `owner`。稽核任何使用 delegatecall 的合約時，第一個該問的問題永遠是：**這個 delegatecall 的目標，是誰決定的？**
