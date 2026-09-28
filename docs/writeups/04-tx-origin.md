# 漏洞 #4：tx.origin Phishing（用 tx.origin 判斷身分）

> 對應程式碼：
> - 漏洞版：[`src/vulnerable/04_TxOrigin.sol`](../../src/vulnerable/04_TxOrigin.sol)
> - 修補版：[`src/fixed/04_TxOrigin_Fixed.sol`](../../src/fixed/04_TxOrigin_Fixed.sol)
> - 測試：[`test/exploits/04_TxOrigin.t.sol`](../../test/exploits/04_TxOrigin.t.sol)

## 漏洞原理

`msg.sender` 跟 `tx.origin` 都能拿到「呼叫者」的地址，但意義完全不同：

- `msg.sender`：**直接呼叫目前這個函式的地址**。每經過一層合約轉呼叫，`msg.sender` 就會換成上一層的地址。
- `tx.origin`：**整條呼叫鏈最源頭、發起這筆交易的外部帳戶（EOA）**。不管中間繞了幾層合約，`tx.origin` 全程不變。

`VulnerableTxOriginWallet` 拿 `tx.origin` 來判斷「是不是 owner 本人」：

```solidity
function transfer(address payable to, uint256 amount) public {
    require(tx.origin == owner, "VulnerableTxOriginWallet: not owner");
    to.transfer(amount);
}
```

這個檢查隱含一個錯誤假設：以為「這筆交易是 owner 發起的」就等於「owner 本人同意這次操作」。但 owner 發起交易，不代表 owner 知道或同意交易鏈路中每一步實際做了什麼——如果 owner 呼叫的是一個惡意合約，這個惡意合約可以在背地裡去呼叫目標合約，而 `tx.origin` 依然是 owner，這個檢查照樣會通過。

## 攻擊流程

`test_Exploit_OwnerTrickedIntoPhishingContract_DrainsWallet` 示範了完整過程：

1. owner 存入 1 ETH 到 `VulnerableTxOriginWallet`。
2. owner 被誘導去呼叫一個看似無害的合約 `TxOriginPhisher`（例如偽裝成某個 dApp 的合約）的 `phish()` 函式。
3. `phish()` 內部悄悄呼叫 `vulnerable.transfer(attacker, ...)`——這次呼叫的 `msg.sender` 是 `TxOriginPhisher`，但 `tx.origin` 仍然是 owner，因為整條鏈最源頭就是 owner 發起的交易。
4. `require(tx.origin == owner)` 通過，資金被轉去攻擊者手上。

```
[PASS] test_Exploit_OwnerTrickedIntoPhishingContract_DrainsWallet() (gas: 81533)
```

owner 全程只做了一件事——呼叫一個看起來無害的合約，就在不知情的狀況下把錢包淨空了。

## 修補方式：`SafeTxOriginWallet`

把判斷依據從 `tx.origin` 換成 `msg.sender`：

```solidity
function transfer(address payable to, uint256 amount) public {
    require(msg.sender == owner, "SafeTxOriginWallet: not owner");
    to.transfer(amount);
}
```

`msg.sender` 只反映「直接呼叫這個函式的是誰」。owner 被騙去呼叫 `TxOriginPhisher` 之後，`TxOriginPhisher` 再去呼叫 `SafeTxOriginWallet.transfer()` 時，`msg.sender` 是 `TxOriginPhisher` 合約的地址，不是 owner——檢查會正確失敗。這也是 [Solidity 官方文件的安全建議](https://docs.soliditylang.org/en/latest/security-considerations.html#tx-origin)：權限判斷一律用 `msg.sender`，`tx.origin` 幾乎沒有安全上的正當用途。

## 修補驗證

```
[PASS] test_Patched_SafeTxOriginWallet_BlocksPhishing() (gas: 50205)
[PASS] test_NormalFlow_OwnerCanTransferDirectly() (gas: 71345)
```

- `test_Patched_SafeTxOriginWallet_BlocksPhishing`：同樣的釣魚手法打修補版，`transfer()` 直接 revert，owner 的資金完全未受影響。
- `test_NormalFlow_OwnerCanTransferDirectly`：owner 直接呼叫 `transfer()`（沒有中間合約）依然正常運作，證明修補沒有破壞既有功能。

## 小結

這個漏洞的關鍵不在於 `tx.origin` 本身有 bug，而在於它回答的問題（「這筆交易是誰發起的」）跟開發者實際想問的問題（「現在是誰在呼叫我」）不一樣。只要合約之間可以互相呼叫，`tx.origin` 就永遠沒辦法可靠地代表「使用者本人同意了這個動作」，任何用它做權限判斷的合約，都可能被一個看似無害的中間合約當成跳板。
