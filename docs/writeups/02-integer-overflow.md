# 漏洞 #2：Integer Overflow / Underflow（整數溢位／下溢）

> 對應程式碼：
> - 漏洞版：[`src/vulnerable/02_IntegerOverFlow.sol`](../../src/vulnerable/02_IntegerOverFlow.sol)（`pragma solidity ^0.7.6`）
> - 修補版：[`src/fixed/02_IntegerOverflow_Fixed.sol`](../../src/fixed/02_IntegerOverflow_Fixed.sol)（`pragma solidity ^0.8.24`）
> - 測試：[`test/exploits/02_IntegerOverFlow.t.sol`](../../test/exploits/02_IntegerOverFlow.t.sol)

## 漏洞原理

`VulnerableToken` 是一個最陽春的代幣合約，用 `mapping(address => uint) balances` 記錄每個地址的餘額：

```solidity
pragma solidity ^0.7.6;

function transfer(address to, uint amount) public {
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

問題在於 `transfer()` 完全沒有檢查「餘額夠不夠轉」就直接做減法。Solidity 0.8.0 之前的版本，`uint256` 的加減乘沒有內建的溢位／下溢保護——當結果超出型別能表示的範圍時，並不會 revert，而是像時鐘指針一樣繞一圈，用**模運算（modular arithmetic）**回到範圍內：

$$\text{balances[attacker]} = 0 - 1 \equiv 2^{256} - 1 \pmod{2^{256}}$$

也就是說，一個餘額原本是 0 的帳戶，只要呼叫 `transfer(to, 1)`，`balances[msg.sender] -= 1` 這一步就會直接下溢到 `uint256` 能表示的最大值，而不是被擋下來。

## 攻擊流程

`test_Underflow_CreatesHugeBalance` 示範了完整過程：

1. `attacker` 從沒收過任何代幣，`balances[attacker]` 一開始是 `0`。
2. `attacker` 呼叫 `transfer(address(this), 1)`——轉出比自己實際擁有的還多。
3. 因為沒有 `require` 檢查餘額，`balances[attacker] -= 1` 直接執行下去。
4. `0 - 1` 在無保護的 `uint256` 運算下溢位，變成 `2^256 - 1`。

```
[PASS] test_Underflow_CreatesHugeBalance() (gas: 84611)
Logs:
  attacker balance after underflow: 115792089237316195423570985008687907853269984665640564039457584007913129639935
```

這個數字就是 `type(uint256).max`（$2^{256}-1$）。攻擊者只用一次呼叫，就讓自己的帳本餘額從 0 變成天文數字——不是「真的」ETH 增加了，而是這個合約自己維護的記帳系統（ledger）被污染了。如果這個 `balances` 之後被拿去計算能領多少 ETH、能轉出多少代幣，攻擊者就能拿這個假餘額去掏空合約或在交易所大量拋售。

這類漏洞不是理論上的風險：2018 年 4 月，[BeautyChain（BEC）代幣](https://www.certik.com) 的 `batchTransfer()` 函式因為乘法溢位，讓攻擊者鑄造出天文數字的代幣，導致該代幣在各大交易所被緊急下架，是真實世界因整數溢位造成重大損失的代表案例。

## 修補方式：`SafeToken`

```solidity
pragma solidity ^0.8.24;

function transfer(address to, uint256 amount) public {
    require(balances[msg.sender] >= amount, "SafeToken: insufficient balance");
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

疊了兩層防禦：

**第一層：語言內建保護**——Solidity 0.8.0 開始，`+`、`-`、`*` 這些運算子本身就內建溢位／下溢檢查，一旦結果超出範圍就會自動 revert（`Panic(0x11)`），不需要額外程式碼就已經比 0.7.x 安全。單純把 pragma 從 `^0.7.6` 升到 `^0.8.24`，不改任何函式邏輯，這個 underflow 就已經擋得住。

**第二層：明確的 `require` 檢查**——即便語言本身已經有保護，仍然額外寫出 `require(balances[msg.sender] >= amount, ...)`。原因跟 Week 1 的「CEI + ReentrancyGuard 兩層防禦」是同一種思路：內建保護是最後一道防線，但把「餘額必須夠」這條業務規則明確寫進程式碼，一來錯誤訊息更清楚（`"insufficient balance"` 比一個沒有訊息的 `Panic` 好懂），二來不會因為日後改動（例如包進 `unchecked{}` 區塊）而不小心失去保護。

## 修補驗證

- `test_Patched_SafeToken_BlocksUnderflow`：同樣手法打 `SafeToken`，`require` 直接 revert，`balances[attacker]` 維持在 `0`，沒有任何異常餘額被創造出來。
- `test_NormalFlow_SafeToken`：一般轉帳流程（餘額足夠的情況）正常運作，證明修補沒有破壞既有功能。

```
Ran 3 tests for test/exploits/02_IntegerOverFlow.t.sol:IntegerOverflowTest
[PASS] test_NormalFlow_SafeToken() (gas: 77037)
[PASS] test_Patched_SafeToken_BlocksUnderflow() (gas: 47826)
[PASS] test_Underflow_CreatesHugeBalance() (gas: 84611)
```

## 技術筆記：跨編譯器版本測試

`VulnerableToken`（`^0.7.6`）跟這個測試檔案、`SafeToken`（都是 `^0.8.24`）版本不相容，而 Solidity 規定「同一個 import 圖裡的所有檔案必須用同一個編譯器版本」，所以測試檔不能直接 `import` 舊版合約。解法是宣告一個版本無關的 `interface`，再用 Foundry 的 `vm.getCode("路徑:合約名")` cheatcode 把獨立編譯好的 0.7.6 bytecode 抓出來，透過內聯組合語言的 `create` 自己部署：

```solidity
bytes memory bytecode = vm.getCode("src/vulnerable/02_IntegerOverFlow.sol:VulnerableToken");
address deployed;
assembly {
    deployed := create(0, add(bytecode, 0x20), mload(bytecode))
}
```

這樣兩個版本各自獨立編譯，只在部署後透過 `interface` 溝通，不會產生版本衝突。這是 Foundry 專案裡刻意保留舊版易受攻擊合約、同時用新版寫測試時的標準做法。

## 小結

Integer Overflow/Underflow 的本質是「運算結果超出型別能表示的範圍，卻沒有被攔截，反而繞回合法範圍內的另一個值」。Solidity 0.8.0 把這個防線內建進語言本身，是這類漏洞在新專案裡已大幅減少的主因；但只要程式碼裡出現 `unchecked{}` 區塊，或專案還在用 0.8.0 之前的版本，這個古老的漏洞就會原封不動地復活——這也是為什麼稽核舊合約、或是稽核使用 `unchecked{}` 做 gas 優化的新合約時，這仍然是必查項目之一。
