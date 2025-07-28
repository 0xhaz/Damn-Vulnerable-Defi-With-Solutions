### [H-1] `UnstoppableVault::flashLoan` Invariant Enforcement Bypass via External ERC20 Transfers

**Description:**  
The conditions in `UnstoppableVault::flashLoan` can be broken if someone transfers tokens directly to the vault without calling `deposit()`. This is critical because the ERC4626 vault does not track external deposits — the vault’s internal accounting is updated only when someone deposits using `deposit()` or `mint()`.

There is no logic in the vault to sanitize or ignore direct ERC20 transfers. As a result, `totalAssets()` can become higher than expected while `convertToShares(totalSupply)` remains unchanged, leading to an invariant violation and permanent denial of service on the `flashLoan()` function.

<details>
<summary>Code</summary>

```javascript
function flashLoan(
    IERC3156FlashBorrower receiver,
    address _token,
    uint256 amount,
    bytes calldata data
) external returns (bool) {
    if (amount == 0) revert InvalidAmount(0); // fail early
    if (address(asset) != _token) revert UnsupportedCurrency(); // enforce ERC3156 requirement
    uint256 balanceBefore = totalAssets();

@>  // @audit - balanceBefore reflects the externally increased balance
@>  // @audit - convertToShares(totalSupply) remains unchanged
    if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // enforce ERC4626 requirement

    // transfer tokens out + execute callback on receiver
    ERC20(_token).safeTransfer(address(receiver), amount);

    // callback must return magic value, otherwise assume it failed
    uint256 fee = flashFee(_token, amount);
    if (
        receiver.onFlashLoan(msg.sender, address(asset), amount, fee, data)
            != keccak256("IERC3156FlashBorrower.onFlashLoan")
    ) {
        revert CallbackFailed();
    }

    // pull amount + fee from receiver, then pay the fee to the recipient
    ERC20(_token).safeTransferFrom(address(receiver), address(this), amount + fee);
    ERC20(_token).safeTransfer(feeRecipient, fee);

    return true;
}
```

</details>

**Impact:**
If someone transfers tokens directly to the vault (i.e. via plain `ERC20.transfer()`), the vault’s `totalAssets()` increases while `convertToShares(totalSupply)` stays the same. This breaks the assumption enforced by the `flashLoan()` invariant check, causing it to revert permanently.

During the grace period, flashloans are free:

<details>
<summary>Code</summary>

```javascript
/// excerpt from flashFee snippets
if (block.timestamp < end && _amount < maxFlashLoan(_token)) {
  return 0;
}
```

</details>

An attacker can exploit this flow as follows:

1. Front-run the grace period (free flashloans)
2. Deposit a small amount using `deposit()` to receive shares
3. Send a large amount directly to the contract (manipulating `totalAssets()`)
4. Now `convertToShares(totalSupply) != totalAssets()`
5. The vault bricks itself: every call to `flashLoan()` reverts due to `InvalidBalance`
6. The attacker calls `redeem()` to get their funds back:
   1. No restrictions are placed on `redeem()` based on internal/external asset mismatch
   2. So attacker still gets all their token back
7. Final outcome:
   1. The Vault is permanently bricked for flashloan
   2. Tokens sent directly are stuck
   3. Fee logic is broken
   4. Future usage of the vault becomes impossible unless the owner takes manual action

**Proof of Concept:** Add the following to the `Unstoppable.t.sol` test file

<details>
<summary>Code</summary>

```javascript
    function test_unstoppable() public checkSolvedByPlayer {
            token.transfer(address(vault), 1);
    }

```

</details>

**Recommended Mitigation:**
To fix this vulnerability, the contract should enforce the following in
`UnstoppableVault:afterDeposit`

<details>
<summary>Code</summary>

```javascript
 function afterDeposit(uint256 assets, uint256 shares) internal override nonReentrant whenNotPaused {
    require(convertToAssets(totalSupply) == asset.balanceOf(address(this)),
    "Asset/share mismatch"
    );
 }

```

</details>

**Other Mitigation Options:**
Use an `internalAssets` variable that is only updated in `deposit()` or `withdraw()`, and use it in place
of `totalAssets()` inside `flashLoan()`

<details>
<summary>Code</summary>

```javascript
    uint256 public internalAssets;

    function afterDeposit(uint256 assets, uint256 shares) internal override {
        internalAssets += assets;
    }

    function beforeWithdraw(uint256 assets, uint256 shares) internal override {
        internalAssets -= assets;
    }

```

</details>

## Likelihood & Impact:

- Impact: HIGH
- Likelihood: LOW (requires intentional behavior and knowledge of vault logic)
- Severity: HIGH

```

```
