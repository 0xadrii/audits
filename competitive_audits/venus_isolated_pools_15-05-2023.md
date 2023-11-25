# Venus Protocol Isolated Pools

[Venus](https://app.venus.io/) is a decentralized finance (DeFi) algorithmic money market protocol on BNB Chain.

## Findings summary

| ID | Description | Severity |
| --- | --- | --- |
| [M-01](#m-01---dos-in-shortfall-if-convertiblebaseasset-is-set-to-be-an-erc777-token) | DoS in shortfall if convertibleBaseAsset is set to be an ERC777 token | Medium |
| [M-02](#m-02---it-is-possible-to-bypass-liquidateaccount-execution-restrictions-due-to-missing-rates-and-assets-prices-updates) | It is possible to bypass `liquidateAccount()` execution restrictions due to missing rates and asset's prices updates | Medium |

## **Detailed Findings**

## [M-01] - DoS in shortfall if `convertibleBaseAsset` is set to be an ERC777 token

### Lines of code

https://github.com/code-423n4/2023-05-venus/blob/main/contracts/Shortfall/Shortfall.sol#L248

### Vulnerability details

Users can place bids through the placeBid() function by passing the `comptroller` they want to bid for and a `bidBps` amount which will be considered as the amount to bid. The auction will be tracked by the `auctions` mapping, which maps the `comptroller` address to the auction metadata (which means that if an auction is currently being executed for a specific `comptroller`, the auction must finish in order to be able to start new auctions for that `comptroller`).

Any time a user places a "better" bid than the current `highestBidder` (better bid meaning passing a higher `bidBps` value than the current `highestBidBps` if `auctionType` is `LARGE_POOL_DEBT`, or lower `bidBps` value than the current `highestBidBps` if `auctionType` is `LARGE_RISK_FUND`) , the user will become the `highestBidder`, and will receive a `convertibleBaseAsset` amount when the auction is finished by triggering `closeAuction()`.

The protocol documentation does not specify what type of token `convertibleBaseAsset` will be. If the `convertibleBaseAsset` (token to be sent to `highestBidder` in `closeAuction()`) is an ERC777 token or similar token (tokens which call receiver's hook after receiving it), a malicious user that has become the `highestBidder` can take advantage of the ERC777's receiver's hook in order to DoS the `closeAuction()` function by using the hook to always revert when receiving the `convertibleBaseAsset` tokens. This will make it impossible for the auction to be closed if the `bidBps` amount set by the `highestBidder` is in the limit amount bps configured in the protocol (`bidBps` being 0 if `auctionType` is `LARGE_RISK_FUND`, or `bidBps` being 10000 if `auctionType` is `LARGE_POOL_DEBT`), remaining in a permanent `AuctionStatus.STARTED` state forever.

It is relevant to note that the only way of "unblocking" an auction when the closing process can be triggered is by actually closing it.  All the other methods that modify auction state require specific conditions that can never be fulfilled if the auction is valid to be closed:

- `startAuction()` can never be called because the auction is [required to be `NOT_STARTED` or `ENDED`](https://github.com/code-423n4/2023-05-venus/blob/main/contracts/Shortfall/Shortfall.sol#L364-L368)
- `restartAuction()` can never be called because the auction is [required to be stale](https://github.com/code-423n4/2023-05-venus/blob/main/contracts/Shortfall/Shortfall.sol#L279)
- `placeBid()` can never be called because the attacker's `bidBps` bid is in the limit bps amount [not possible to bid more than 10000 in `LARGE_POOL_DEBT`](
https://github.com/code-423n4/2023-05-venus/blob/main/contracts/Shortfall/Shortfall.sol#L166) and [not possible to bid less than 0 in `LARGE_RISK_FUND`](https://github.com/code-423n4/2023-05-venus/blob/main/contracts/Shortfall/Shortfall.sol#L169)

- `closeBid()` is Dos'ed due to the attacker always reverting the transaction

This effectively blocks the current auction, and prevents any future auction to take place for the current `comptroller`, which prevents it from auctioning bad debt and potentially mitigating protocol losses.

### Impact

Medium. A DoS takes place in `closeAuction()`, effectively preventing closing the current auction for that specific Comptroller, and avoiding the creation of any future auction due to the auction status never being changed to `AuctionStatus.ENDED`

### Tools used

Manual review

### Recommended mitigation steps

This issue could be tackled in several ways. One possible mitigation could be transferring the `convertibleBaseAsset` to the malicious user via `call`, and handling the return value, which would be a trustable way to prevent the DoS and verify if the assets were actually transferred without stopping the function execution.

Another possible mitigation could be adding the functionality to cancel an auction. This would revert the auction state to `NOT_STARTED`, clearing the auction data and going back to an initial state where the auction did not exist.

## [M-02] - It is possible to bypass `liquidateAccount()` execution restrictions due to missing rates and asset's prices updates

### Lines of code

https://github.com/code-423n4/2023-05-venus/blob/main/contracts/Comptroller.sol#L644

https://github.com/code-423n4/2023-05-venus/blob/main/contracts/Comptroller.sol#L651-L659

### Vulnerability details

Comptroller's `liquidateAccount()` function is restricted to only being called if two specific circumstances are true:

- The borrower's `totalCollateral` does not surpass the Comptroller's configured `minLiquidatableCollateral`, which is done in the following way:

```solidity
if (snapshot.totalCollateral > minLiquidatableCollateral) {
         // You should use the regular vToken.liquidateBorrow(...) call
           revert CollateralExceedsThreshold(minLiquidatableCollateral, snapshot.totalCollateral);
}
```

- The collateral seized will cover all borrows of the borrower, as well as the liquidation incentive:

```solidity
if (collateralToSeize >= snapshot.totalCollateral) {
           // There is not enough collateral to seize. Use healBorrow to repay some part of the borrow
           // and record bad debt.
           revert InsufficientCollateral(collateralToSeize, snapshot.totalCollateral);
}
```

However, unlike in most of the protocol's main entry point functions, the protocol fails to update both the collateral's prices and the borrow index prior to realizing any check or computation, which leads to the checks being susceptible of being surpassed and the protocol incurring bad debt due to the collateral not being able to cover the seize amount.

### Proof of concept

`liquidateAccount()`'s first action is to perform the checks mentioned in the previous section:

```solidity
// Comptroller.sol

function liquidateAccount(address borrower, LiquidationOrder[] calldata orders) external {
       // We will accrue interest and update the oracle prices later during the liquidation

       // @audit if interest rates are not updated, liquidity snapshot will return a wrong totalCollateral
       AccountLiquiditySnapshot memory snapshot = _getCurrentLiquiditySnapshot(borrower, _getLiquidationThreshold);

       // This is the first check mentioned
       if (snapshot.totalCollateral > minLiquidatableCollateral) {
           // You should use the regular vToken.liquidateBorrow(...) call
           revert CollateralExceedsThreshold(minLiquidatableCollateral, snapshot.totalCollateral);
       }

       uint256 collateralToSeize = mul_ScalarTruncate(
           Exp({ mantissa: liquidationIncentiveMantissa }),
           snapshot.borrows
       );

       // This is the second check mentioned
       if (collateralToSeize >= snapshot.totalCollateral) {
           // There is not enough collateral to seize. Use healBorrow to repay some part of the borrow
           // and record bad debt.
           revert InsufficientCollateral(collateralToSeize, snapshot.totalCollateral);
       }
       ...
}
```

As we can see, prior to performing the checks, the borrower's liquidity snapshot is fetched via `_getCurrentLiquiditySnapshot()`, which internally calls `_getHypotheticalLiquiditySnapshot()`. This liquidity snapshot contains two important values: `snapshot.totalCollateral` and `snapshot.borrows`:

```solidity
// Comptroller.sol

function _getHypotheticalLiquiditySnapshot(
       address account,
       VToken vTokenModify,
       uint256 redeemTokens,
       uint256 borrowAmount,
       function(VToken) internal view returns (Exp memory) weight
   ) internal view returns (AccountLiquiditySnapshot memory snapshot) {
      ...

       for (uint256 i; i < assetsCount; ++i) {
           VToken asset = assets[i];

           // Read the balances and exchange rate from the vToken. This is the first step mentioned below
           (uint256 vTokenBalance, uint256 borrowBalance, uint256 exchangeRateMantissa) = _safeGetAccountSnapshot(
               asset,
               account
           );

           // Get the normalized price of the asset. This is the second step mentioned below
           Exp memory oraclePrice = Exp({ mantissa: _safeGetUnderlyingPrice(asset) });
           // Pre-compute conversion factors from vTokens -> usd
           Exp memory vTokenPrice = mul_(Exp({ mantissa: exchangeRateMantissa }), oraclePrice);
         ...
}
```

`_getHypotheticalLiquiditySnapshot()` performs two important steps that return important data to Comptroller's `liquidateAccount()` function:

1. Fetching the user's `borrowBalance`, which in the end will be returned and stored in the `borrows` field in the `snapshot` struct. `snapshot.borrows` is used in `liquidateAccount()` in order to compute the user's `collateralToSeize`. The previous code block shows how `borrowBalance` is obtained by calling `_safeGetAccountSnapshot()`. This function internally interacts with the respective vToken and obtains the borrower's `borrowBalance` using the VToken's `_borrowBalanceStored()` function:

```solidity
// VToken.sol

function getAccountSnapshot(address account)
       external
       view
       override
       returns (
           uint256 error,
           uint256 vTokenBalance,
           uint256 borrowBalance,
           uint256 exchangeRate
       )
   {
       return (NO_ERROR, accountTokens[account], _borrowBalanceStored(account), _exchangeRateStored());
   }

function _borrowBalanceStored(address account) internal view returns (uint256) {
       /* Get borrowBalance and borrowIndex */
       BorrowSnapshot memory borrowSnapshot = accountBorrows[account];

       /* If borrowBalance = 0 then borrowIndex is likely also 0.
        * Rather than failing the calculation with a division by 0, we immediately return 0 in this case.
        */
       if (borrowSnapshot.principal == 0) {
           return 0;
       }

       /* Calculate new borrow balance using the interest index:
        *  recentBorrowBalance = borrower.borrowBalance * market.borrowIndex / borrower.borrowIndex
        */
       uint256 principalTimesIndex = borrowSnapshot.principal * borrowIndex;

       return principalTimesIndex / borrowSnapshot.interestIndex;
   }
```

As we can see, this function uses the current borrow index, which is the accumulator of the total earned interest rate since the opening of the market. This index is only updated when `accrueInterest()` is called, which in our case is never done before actually performing the two important checks already mentioned in the beginning of the report. This will result in the borrower's `borrowBalance` not being properly accounted, and effectively reflecting a wrong borrowed amount for that user. The consequences of this can lead to the protocol incurring bad debt because of the `collateralToSeize` being calculated wrong. As mentioned before, this wrong calculation can lead to the second check in Comptroller's `liquidateAccount()`(the one that checks the borrower's `totalCollateral` against the computed `collateralToSeize`) to be bypassed due to `collateralToSeize` seeming to be smaller than the user's `totalCollateral`, when in reality it might actually be higher.

1. The second step performed inside `_getHypotheticalLiquiditySnapshot()` is fetching the collateral price. Venus protocol has [several oracle options](https://github.com/VenusProtocol/oracle/tree/develop/contracts/oracles), one of them being the [TWAP oracle](https://github.com/VenusProtocol/oracle/blob/develop/contracts/oracles/TwapOracle.sol) which fetches the price from Pancakeswap's token/BUSD pool. This specific oracle requires Venus protocol contracts to trigger the `updateTwap()` function in order to properly update the oracle's prices. This is properly done in several places of the protocol via `oracle.updatePrice(vToken);` (which internally calls the Twap Oracle's `updateTwap()`). Although the price updates are done later inside `liquidateAccount()`'s execution, they are not performed before actually verifyinh the two important checks mentioned in the beginning of the report. Because of this, the price obtained in `_getHypotheticalLiquiditySnapshot()` might differ from the real price, effectively making the borrower's `totalCollateral` computation be wrong. This could lead to both of the checks mentioned being bypassed due to the total collateral not being completely accurate.

### Tools used

Manual review

### Recommended mitigation steps

In order to mitigate the two issues mentioned in the report, it is recommended to:

1. Update each vToken's accrued interest. For accruing interest, each vToken's `accrueInterest()` function might be triggered
2. Update each vToken's oracle price by calling each vToken's `updatePrice()` function