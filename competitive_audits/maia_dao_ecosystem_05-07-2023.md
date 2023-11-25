# Maia DAO Ecosystem

Efficient liquidity renting and management across chains with Curvenized Uniswap V3.

## Findings summary

| ID | Description | Severity |
| --- | --- | --- |
| [H-01](#h-01---liquidity-providers-may-lose-funds-when-initialising-a-strategy) | Liquidity providers may lose funds when initialising a strategy | High |
| [H-02](#h-02---improper-fee-handling-when-reranging-and-rebalancing-leads-to-protocol-dos) | Improper fee handling when reranging and rebalancing leads to protocol DoS | High |

## Detailed findings

## [H-01] - Liquidity providers may lose funds when initialising a strategy. 

### Lines of code

https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/talos/base/TalosBaseStrategy.sol#L135-L149

https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/talos/base/TalosBaseStrategy.sol#L102C27-L102C41

### Vulnerability details

Liquidity providers may lose a portion of provided liquidity in either of the pair tokens when creating a new position. 

The `init` function on `TalosBaseStrategy.sol` does not check for price volatility before providing / swapping liquidity. Unlike in the rest of interactions with Uniswap where the modifier `checkDeviation` checks for price volatility before providing / swapping liquidity. While `amount0Desired` & `amount1Desired` specify the amount of tokens the user wants to initialise the position with. `amount0Min` & `amount1Min` should not be set to 0 in order to protect from slippage when adding liquidity.

```solidity
(_tokenId, _liquidity, amount0, amount1) = _nonfungiblePositionManager.mint(
    INonfungiblePositionManager.MintParams({
        token0: address(_token0),
        token1: address(_token1),
        fee: poolFee,
        tickLower: tickLower,
        tickUpper: tickUpper,
        amount0Desired: amount0Desired,
        amount1Desired: amount1Desired,
        amount0Min: 0,
        amount1Min: 0,
        recipient: address(this),
        deadline: block.timestamp
     })
 );
```

### Tools used

Manual review, foundry

### Recommended mitigation steps

Add the modifier `checkDeviation` to the init function on TalosBaseStrategy.sol to prevent price manipulation, or use the pool twap oracle to get accurate minimum amounts for the swap.

## [H-02] - Improper fee handling when reranging and rebalancing leads to protocol DoS

### Lines of code

https://github.com/code-423n4/2023-05-maia/blob/main/src/talos/libraries/PoolActions.sol#L68

https://github.com/code-423n4/2023-05-maia/blob/main/src/talos/libraries/PoolActions.sol#L98-L99

https://github.com/code-423n4/2023-05-maia/blob/main/src/talos/TalosStrategyVanilla.sol#L130-L131

### Vulnerability details

Previously to depositing to/redeeming from talos, fees are earned and compounded from uniswap (this is done through the `beforeDeposit()` and `beforeRedeem` functions, which both trigger `_earnFees()` to collect fees and `_compoundFees()` to reinvest fees). Regarding the fees, the protocol avoids autocompounding fees belonging to the protocol (`protocolFees0` and `protocolFees1`), and only invests the fees that belong to the users. This is done in order to keep them in the protocol balance and allow for posterior protocol fees withdrawal through `collectProtocolFees()`. 

We can clearly see how `protocolFees0` and `protocolFees1` are NOT autocompounded in  `_compoundFees()`. This function computes the difference between the current contract balance (tokens collected in the previously called `_earnFees()`) and the fees belonging to the protocol (`protocolFees0` and `protocolFees1`), stores the difference into `balance0` and `balance1`, and finally only increases liquidity with an amount desired of `balance0` and `balance1`:

```solidity
function _compoundFees(uint256 _tokenId) internal returns (uint256 amount0, uint256 amount1) {
     uint256 balance0 = token0.balanceOf(address(this)) - protocolFees0;
     uint256 balance1 = token1.balanceOf(address(this)) - protocolFees1;

     emit Snapshot(balance0, balance1);

     //Get Liquidity for Optimizer's balances
     uint128 _liquidity = pool.liquidityForAmounts(balance0, balance1, tickLower, tickUpper);

     // Add liquidity to the pool
     if (_liquidity > 0) {
         uint128 liquidityDifference;
         (liquidityDifference, amount0, amount1) = nonfungiblePositionManager.increaseLiquidity(
             INonfungiblePositionManager.IncreaseLiquidityParams({
                 tokenId: _tokenId,
                 amount0Desired: balance0,
                 amount1Desired: balance1,
                 amount0Min: 0,
                 amount1Min: 0,
                 deadline: block.timestamp
             })
         );
         liquidity += liquidityDifference;
         emit CompoundFees(amount0, amount1);
     }
 }
```

The problem arises when a `rerange()` or `rebalance()` is triggered in the Vanilla Strategy. Reranging and rebalancing will both mint new uniswap positions, and the isse arises due to the fact that both functions reinvest ALL of the fees (both user fees and protocol fees) when minting the new position, leaving the protocol with a balance smaller than the actual accounted protocol fees. If we look at the execution of `rerange()` and `rebalance()`:

1. The first thing they do is calling is the `beforeRerange()` function, which internally will ONLY call `_earnFees()` (so fees will be collected and stored in contract balance, and properly accounted in `protocolFees0` and `protocolFees1`, but they won't be compounded). At this point, the contract balance has the fees collected (both user fees and protocol fees).
2. After collecting the fees, `_withdrawAll()` will be executed. This will decrease the liquidity in the Non-Fungible Position Manager by the amount of liquidity tracked by the `liquidity` variable in the protocol. This will transfer all the liquidity to our contract, so our contract balance will now consist in the liquidity we just withdrew, plus the fees collected in the previous step
3. Either `doRebalance()` or `doRerange()` get executed depending on the action we want to execute (rerange or rebalance). We can see that both of them end up triggering `PoolActions.rerange()`:

```solidity
 function doRerange() internal override returns (uint256 amount0, uint256 amount1) {
     (tickLower, tickUpper, amount0, amount1, tokenId, liquidity) = nonfungiblePositionManager.rerange(
         PoolActions.ActionParams(pool, optimizer, token0, token1, tickSpacing), poolFee
     ); 
 }

 function doRebalance() internal override returns (uint256 amount0, uint256 amount1) {
    ...

     (tickLower, tickUpper, amount0, amount1, tokenId, liquidity) =
         nonfungiblePositionManager.rerange(actionParams, poolFee);
 }
```
`PoolActions.rerange()` will query the current contract balance (remember that our balance consists of the liquidity we had deposited in the previous uniswap position + the user fees + the protocol fees), and then it will mint a new uniswap position, setting `amount0Desired` and `amount1Desired` to be the whole contract balance. We can see how `getThisPositionTicks` internally queries the contract balance, and later that balance is used to mint a new position:
```solidity
function rerange(
     INonfungiblePositionManager nonfungiblePositionManager,
     ActionParams memory actionParams,
     uint24 poolFee
 )
     internal
     returns (int24 tickLower, int24 tickUpper, uint256 amount0, uint256 amount1, uint256 tokenId, uint128 liquidity)
 {
    ...
     uint256 balance0;
     uint256 balance1;
     (balance0, balance1, tickLower, tickUpper) = getThisPositionTicks(
         actionParams.pool, actionParams.token0, actionParams.token1, baseThreshold, actionParams.tickSpacing
     );
     ...

     (tokenId, liquidity, amount0, amount1) = nonfungiblePositionManager.mint(
         INonfungiblePositionManager.MintParams({
             token0: address(actionParams.token0),
             token1: address(actionParams.token1),
             fee: poolFee,
             tickLower: tickLower,
             tickUpper: tickUpper,
             amount0Desired: balance0,
             amount1Desired: balance1,
             amount0Min: 0,
             amount1Min: 0,
             recipient: address(this),
             deadline: block.timestamp
         })
     );
 }

function getThisPositionTicks(
     IUniswapV3Pool pool,
     ERC20 token0,
     ERC20 token1,
     int24 baseThreshold,
     int24 tickSpacing
 ) private view returns (uint256 balance0, uint256 balance1, int24 tickLower, int24 tickUpper) {
     // Emit snapshot to record balances
     balance0 = token0.balanceOf(address(this));
     balance1 = token1.balanceOf(address(this));

                                        ...

 }
```
As we can see, all of the balance has been invested (all the protocol fees that should have been kept in the contract to cover withdrawal of protocol fees are now invested in the new uniswap position), and the contract now does not have enough balance to cover withdrawal of protocol fees.

This leads to two critical issues in the protocol:

1. Denial of Service in `deposit()` and `redeem()`: as we mentioned earlier, both deposit and redeem execute the `beforeDeposit()` and `beforeReedeem()` functions. Internally, both of them execute the `_earnFees()` and `_compoundFees()` functions. Concretely, the `_compoundFees()` will always revert after performing a rebalance or rerange.

```solidity
function _compoundFees(uint256 _tokenId) internal returns (uint256 amount0, uint256 amount1) {
     uint256 balance0 = token0.balanceOf(address(this)) - protocolFees0;
     uint256 balance1 = token1.balanceOf(address(this)) - protocolFees1;

    ...
 }
```
As we can see, the first thing the `_compoundFees()` function does is checking the difference between the current contract balance and the protocol fees. We have previously mentioned that our current protocol balance has been decreased due to the fact that it has all been reinvested in the new uniswap position minted, effectively making `protocolFees0` be greater than `token0.balanceOf(address(this))`, and `protocolFees1` be greater than `token1.balanceOf(address(this))`. This will always lead to a panic error due to an arithmetic underflow, effectively preventing users from interacting with the protocol

2. The owner of the contract will NEVER be able to withdraw the protocol fees after performing a rerange/rebalance. We can see that in order to withdraw the protocol fees, `collectProtocolFees()` function is called. This function will check if the current balance is enough to cover the amount requested to be withdrawn. Given that in the rebalance and rerange we have reinvested the protocol fees, it will never be possible for the owner to withdraw the full amount of fees that belong to the protocol.

### Proof of concept
The following PoC’s show how rerange and rebalance  will cause the DoS reverting for both trying to deposit and trying to collect protocol fees after reranging/rebalancing:
- Rerange:

```solidity
function testDoSRerange() public {
     uint256 amount0Desired = 10_0000;
     uint256 amount1Desired = 10_0000;

     /// Deposit user 1 amounts
     token0.mint(user1, amount0Desired * 2);
     token1.mint(user1, amount1Desired * 2);
     hevm.prank(user1);
     token0.approve(address(talosBaseStrategy), amount0Desired * 2);
     hevm.prank(user1);
     token1.approve(address(talosBaseStrategy), amount1Desired * 2);
     hevm.prank(user1);
     talosBaseStrategy.deposit(amount0Desired, amount1Desired, user1);
     hevm.warp(block.timestamp + 100);

     /// Mock uniswap fees
     poolSwap(1 ether, true);
     poolSwap(1 ether, false);
     poolSwap(1 ether, true);
     poolSwap(1 ether, false);

     /// Deposit user 2 amounts
     token0.mint(user2, amount0Desired * 2);
     token1.mint(user2, amount1Desired * 2);
     hevm.prank(user2);
     token0.approve(address(talosBaseStrategy), amount0Desired * 2);
     hevm.prank(user2);
     token1.approve(address(talosBaseStrategy), amount1Desired * 2);
     hevm.prank(user2);
     talosBaseStrategy.deposit(amount0Desired, amount1Desired, user2);
     hevm.warp(block.timestamp + 100);

     /// Ensure contract has fees generated
     assertGt(talosBaseStrategy.protocolFees0(), 0);
     assertGt(talosBaseStrategy.protocolFees1(), 0);

     /// Position is changed. Fees are completely reinvested
     talosBaseStrategy.rerange();

     /// Deposit user 1 amounts again and fail due to arithmetic error
     hevm.prank(user1);
     hevm.expectRevert(abi.encodeWithSignature("Panic(uint256)", 0x11)); // "Arithmetic over/underflow"
     talosBaseStrategy.deposit(amount0Desired, amount1Desired, user1);

     /// Try to collect fees. This will fail with the check in `collectProtocolFees()` that performs
     /// `require(balance0 >= amount0 && balance1 >= amount1);`
     uint256 protocolFees0 = talosBaseStrategy.protocolFees0();
     uint256 protocolFees1 = talosBaseStrategy.protocolFees1();

     hevm.expectRevert(abi.encodePacked(""));
     talosBaseStrategy.collectProtocolFees(protocolFees0, protocolFees1);
 }
```

- Rebalance:

```solidity
function testDoSRebalance() public {
    uint256 amount0Desired = 100000;

     TalosStrategyVanilla secondTalosStrategyVanilla = new TalosStrategyVanilla(
             pool,
             strategyOptimizer,
             nonfungiblePositionManager,
             address(this),
             address(this)
         );
     initTalosStrategy(secondTalosStrategyVanilla);

     deposit(amount0Desired, amount0Desired, user1);
     deposit(amount0Desired, amount0Desired, user2);

     _deposit(
         amount0Desired,
         amount0Desired,
         user1,
         secondTalosStrategyVanilla
     );
     _deposit(
         amount0Desired,
         amount0Desired,
         user2,
         secondTalosStrategyVanilla
     );

     poolDisbalancer(30);

     hevm.expectEmit(true, true, true, true);
     // emit Rerange(-12360, -5280, 59402, 179537); // From Popsicle
     emit Rerange(
         talosBaseStrategy.tokenId() + 2,
         -12360,
         -5280,
         59455,
         179687
     );

     talosBaseStrategy.rebalance();

     /// Deposit user 1 amounts again and fail due to arithmetic error
     hevm.prank(user1);
     hevm.expectRevert(abi.encodeWithSignature("Panic(uint256)", 0x11)); // "Arithmetic over/underflow"
     talosBaseStrategy.deposit(amount0Desired, amount0Desired, user1);


     /// Try to collect fees. This will fail with the check in `collectProtocolFees()` that performs
     /// `require(balance0 >= amount0 && balance1 >= amount1);`
     uint256 protocolFees0 = talosBaseStrategy.protocolFees0();
     uint256 protocolFees1 = talosBaseStrategy.protocolFees1();

     hevm.expectRevert(abi.encodePacked(""));
     talosBaseStrategy.collectProtocolFees(protocolFees0, protocolFees1);
 }
```

## Tools Used
Manual review, foundry

## Recommended Mitigation Steps

Protocol fees should NOT be reinvested in the event of minting of a new position so that they remain in the contract in order to be properly collected and not cause the previously mentioned issues. In order to avoid this, `PoolActions.rerange()` could receive the protocol fees as parameter, and considering depositing the difference between the current contract balance and the protocol fees for each token in order to keep the protocol fees in the contract balance