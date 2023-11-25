# Maia DAO - Ulysses

**Ulysses Protocol** is a decentralized and permissionless 'Omnichain Liquidity Protocol' owned by the community that aims at tackling the challenges presented by an increasingly fragmented liquidity landscape in DeFi, ensuring seamless interoperability and capital efficient cross-chain asset deployment.

## Findings summary

| ID | Description | Severity |
| --- | --- | --- |
| [M-01](#m-01---dos-receiving-cross-chain-messages-due-to-mistakenly-validating-_srcaddress) | DoS receiving cross-chain messages due to mistakenly validating _srcAddress | Medium |
| [M-02](#m-02---layerzero-channel-can-be-blocked-by-setting-low-gas-parameters-in-the-relayer-adapter-params) | LayerZero channel can be blocked by setting low gas parameters in the relayer adapter params | Medium |

## Detailed findings

## [M-01] - DoS receiving cross-chain messages due to mistakenly validating `_srcAddress`

### Lines of code

https://github.com/code-423n4/2023-09-maia/blob/main/src/RootBridgeAgent.sol#L1212

https://github.com/code-423n4/2023-09-maia/blob/main/src/BranchBridgeAgent.sol#L943

### **Vulnerability details**

LayerZero's trusted remotes allow contracts to only receive messages from known sources. From [Layer Zero's docs](

https://layerzero.gitbook.io/docs/evm-guides/master/set-trusted-remotes

): "A trusted remote is the 40 bytes (for evm-to-evm messaging) that identifies another contract which you will receive messages from within your LayerZero User Application contract." Trusted remotes are 40-bytes formed by the `remoteAddress` (the address of the contract sending the message) + `localAddress` (the current contract receiving the message).

When a contract integrating with LayerZero wants to check the trusted remote to verify they are receiving the message from a trusted source, the `_srcAddress` in ILayerZeroReceiver's `lzReceive()` function can be used.

Maia's bridge agents (both the RootBridgeAgent and BranchBridgeAgent) receive message from other chains via the `lzReceive()` function. This function will internally call the `lzReceiveNonBlocking` function, which has a `requiresEndpoint` modifier which aims at performing some validations:

```solidity
// RootBridgeAgent.sol
function lzReceive(uint16 _srcChainId, bytes calldata _srcAddress, uint64 , bytes calldata _payload) public {
    (bool success,) = address(this).excessivelySafeCall(
        gasleft(),
        150,
        abi.encodeWithSelector(this.lzReceiveNonBlocking.selector, msg.sender, _srcChainId, _srcAddress, _payload)
    );
    ...
}

function lzReceiveNonBlocking(
    address _endpoint,
    uint16 _srcChainId,
    bytes calldata _srcAddress,
    bytes calldata _payload
) public override requiresEndpoint(_endpoint, _srcChainId, _srcAddress) {

...
}
```

The problem comes with the validation performed inside `requiresEndpoint` that verifies the trusted remote. This validation is performed in both bridge agents [RootBridgeAgent](

https://github.com/code-423n4/2023-09-maia/blob/main/src/RootBridgeAgent.sol#L1204) and [BranchBridgeAgent](https://github.com/code-423n4/2023-09-maia/blob/main/src/BranchBridgeAgent.sol#L936) and aims at checking that the remote address who sent the message, stored inside `_srcAddress`, is a trusted bridge agent. We can see how the `remoteAddress` is extracted from the `_srcAddress` by accessing the last 20 bytes of `_srcAddress` in the form of `address(uint160(bytes20(_srcAddress[PARAMS_ADDRESS_SIZE:])`:

```solidity
// RootBridgeAgent.sol
modifier requiresEndpoint(address _endpoint, uint16 _srcChain, bytes calldata _srcAddress) virtual {
    ...

    // If endpoint is different from Local Branch Bridge Agent
    if (_endpoint != getBranchBridgeAgent[localChainId]) {
       ...

        if (getBranchBridgeAgent[_srcChain] != address(uint160(bytes20(_srcAddress[PARAMS_ADDRESS_SIZE:])))) {
            revert LayerZeroUnauthorizedCaller();
        }
    }
    _;
}

// BranchBridgeAgent.sol
function _requiresEndpoint(
    address _endpoint,
    bytes calldata _srcAddress
) internal view virtual {
    ...

    //Verify Remote Caller
   ...
    if (
        rootBridgeAgentAddress !=
        address(uint160(bytes20(_srcAddress[20:])))
    ) revert LayerZeroUnauthorizedCaller();
}
```

Perspective is really important in order to properly validate this parameter. We need to be aware of the fact that trusted remotes are always built by the remote address + the local address, and remote address and a local address differ depending on which chain you find yourself in. Consider the following example where a message is sent from `contracta` in chain A to `contractB` in chain B:

- From the source chain perspective (chain A), the trusted remote is built as `contractB`+`contractA` (remote address + local address)
- From the destination chain perspective (chain B), the trusted remote is built as `contractA`+`contractB`(remote address + local address)

LayerZero takes care of crafting the `_srcAddress` according to the receiver contract's perspective in their [UltraLightNode](https://github.com/LayerZero-Labs/LayerZero/blob/48c21c3921931798184367fc02d3a8132b041942/contracts/UltraLightNodeV2.sol#L111).

When the bridge agent receives the message in chain B, the modifier aims at extracting `contractA` address from `_srcAddress` in order to validate it. Because Ulysses' receiver contract incorrectly believes that the remote address from the perspective of chain B sits in the last 20 bytes of the `_srcAddress` without considering the change of perspective mentioned before, the modifier mistakenly extracts the remote address from `_srcAddress` by obtaining the last 20 bytes, when in reality the `_srcAddress` in chain B will be received as `contractA`+`contractB`, having the remote address in the FIRST 20 bytes. This makes the modifier wrongly extract `contractB` from `_srcAddress` instead of `contractA`, which is NOT the remote address.

This will make the modifier always fail and throw the `LayerZeroUnauthorizedCaller()` because of the improper address extraction, effectively preventing the bridge agents from receiving messages, and rendering the protocol unusable.

### Proof of concept

The following proof of concept illustrates the issue. It represents receiving a message in a destination contract (`coreBridgeAgent`) from a source contract (`avaxCoreBridgeAgentAddress`). The trusted remote from Destination's (coreBridgeAgent) perspective is built by `abi.encodePacked(avaxCoreBridgeAgentAddress, coreBridgeAgent)` (remoteAddress+sourceAddress). Because of the use of `excessivelySafeCall`, it is not possible to add a `vm.expectRevert(abi.encodeWithSelector("LayerZeroUnauthorizedCaller()"))` because the transaction never fails. Instead, the -vvvvv forge flags should be enabled when executing the test, seeing how LayerZeroUnauthorizedCaller() error is thrown in the traces.

```solidity
function testDos() public {

    // Source -> `avaxCoreBridgeAgentAddress`
    // Destination -> `coreBridgeAgent`
    // Trusted remote from Destination's perspective: abi.encodePacked(avaxCoreBridgeAgentAddress, coreBridgeAgent)

    //get some gas
    vm.deal(address(this), 1.5 ether);

    //Gas Params
    GasParams memory gasParams = GasParams(1 ether, 0.5 ether);

     //Get some gas
    vm.deal(address(lzEndpointAddress), gasParams.gasLimit + gasParams.remoteBranchExecutionGas);

    // Prank into endpoint address
    vm.startPrank(lzEndpointAddress);

    RootBridgeAgent(coreBridgeAgent).lzReceive{gas: gasParams.gasLimit}(
        avaxChainId, abi.encodePacked(avaxCoreBridgeAgentAddress, coreBridgeAgent), 1, bytes("")
    );

    // Prank out of user account
    vm.stopPrank();
}
```

### Tools used

Manual review, foundry

### Recommended Mitigation Steps

Change the extraction method in the `requiresEndpoint` modifiers so that the remote caller is extracted from `_srcAddress` obtaining the FIRST 20 bytes, rather than the last 20 bytes:

```diff
modifier requiresEndpoint(address _endpoint, uint16 _srcChain, bytes calldata _srcAddress) virtual {

-            if (getBranchBridgeAgent[_srcChain] != address(uint160(bytes20(_srcAddress[PARAMS_ADDRESS_SIZE:])))) {
-                revert LayerZeroUnauthorizedCaller();
-            }
+            if (getBranchBridgeAgent[_srcChain] != address(uint160(bytes20(_srcAddress[:PARAMS_ADDRESS_SIZE])))) {
+                revert LayerZeroUnauthorizedCaller();
+            }
    _;
}
```

## [M-02] - LayerZero channel can be blocked by setting low gas parameters in the relayer adapter params

### Lines of code

https://github.com/code-423n4/2023-09-maia/blob/main/src/BranchBridgeAgent.sol#L776

https://github.com/code-423n4/2023-09-maia/blob/main/src/RootBridgeAgent.sol#L829

https://github.com/code-423n4/2023-09-maia/blob/main/src/RootBridgeAgent.sol#L921

### Vulnerability details

LayerZero communication is blocking by default, which means if the message payload fails to be delivered in the destination by executing the `lz_receive()` function, the channel will be blocked and  messages won't be able to be delivered to the destination until the message gets unblocked. We can see this behavior in Layer Zero's endpoint implementation, where [if a message fails to be delivered, it will be stored in the `storedPayload` mapping](https://github.com/LayerZero-Labs/LayerZero/blob/48c21c3921931798184367fc02d3a8132b041942/contracts/Endpoint.sol#L118-L124). `lzReceive()` will then [not be able to be called if there is any stored payload](https://github.com/LayerZero-Labs/LayerZero/blob/48c21c3921931798184367fc02d3a8132b041942/contracts/Endpoint.sol#L115-L116). Payloads can be retried so that the application is no longer blocked by executing the [`retryPayload()` function](https://github.com/LayerZero-Labs/LayerZero/blob/48c21c3921931798184367fc02d3a8132b041942/contracts/Endpoint.sol#L127C14-L127C26).

To avoid the previous blocking issue, Ulysses implements a Nonblocking architecture with the use of `excessivelySafeCall()`, which aims at making the message receiving function `lz_receive()` never fail by bubbling up internal transactions and not reverting. An example can be seen in BranchBridgeAgent.sol, where `lzReceive()` will use `excessivelySafeCall()` to internally call `lzReceiveNonBlocking()`, making `lzReceive()` never revert and consequently never blocking the communication channel:

```solidity
// BranchBridgeAgent.sol
function lzReceive(
       uint16,
       bytes calldata _srcAddress,
       uint64,
       bytes calldata _payload
   ) public override {
       // excessivelySafeCall is not checked, thus making `lzReceive()` never revert
       address(this).excessivelySafeCall(
           gasleft(),
           150,
           abi.encodeWithSelector(
               this.lzReceiveNonBlocking.selector,
               msg.sender,
               _srcAddress,
               _payload
           )
       );
   }
```

However, there is a specific situation where the communication channel can inevitably be blocked even if the receiving contract make use of a non-blocking architecture. This situation is setting a low gas value when sending the transaction so that the destination transaction does not have enough gas to be executed, effectively blocking the channel.

From Layer Zero docs: "Every transaction costs a certain amount of gas. Since LayerZero delivers the destination transaction when a message is sent it must pay for that destination gas. A default of 200,000 gas is priced into the call for simplicity." Ulysses leverages [Layer Zero's airdrop feature](https://layerzero.gitbook.io/docs/evm-guides/advanced/relayer-adapter-parameters#airdrop) to bypass this default amount of gas restriction, allowing messages sent to instruct LayerZero to use a custom amount of gas in the destination chain by setting the so-called `adapterParams`.

The problem is raised by the fact that Ulysses allows users to arbitrarily pass the gas parameters to be included in the `adapterParams` for the destination transaction to be executed, and such gas parameters are never validated to ensure a minimum amount that will allow the transaction to nearly-always be successfully executed. We can see how BranchBridgeAgent.sol's `callOutAndBridge()` directly encodes the gas params, and then executes `_performCall()` to send the message to Layer Zero, allowing `_gParams` to be passed without validation and enabling malicious users to send transactions with low gas amounts that will make the destination transaction always fail:

```solidity
function callOutAndBridge(
       address payable _refundee,
       bytes calldata _params,
       DepositInput memory _dParams,
       GasParams calldata _gParams
   ) external payable override lock {
       ...

       //Perform Call
       _performCall(_refundee, payload, _gParams);
   }
function _performCall(
       address payable _refundee,
       bytes memory _payload,
       GasParams calldata _gParams 
   ) internal virtual {
       //Sends message to LayerZero messaging layer
       ILayerZeroEndpoint(lzEndpointAddress).send{value: msg.value}(
           rootChainId,
           rootBridgeAgentPath,
           _payload,
           payable(_refundee),
           address(0),
           abi.encodePacked(
               uint16(2),
               _gParams.gasLimit,
               _gParams.remoteBranchExecutionGas,
               rootBridgeAgentAddress
           )
       );
   }
```

This makes malicious users capable of constantly blocking the communication channel temporarily until `retryPayload()` is executed in Layer Zero's endpoint, effectively DoS'ing the contracts functionality.

### Proof of concept

The following PoC illustrates how the destination `lzReceive()` function can be blocked even if it uses the non-blocking pattern leveraging `excessivelySafeCall()`. By setting a 0 gas params amount, the transaction can effectively run out of gas, making the LayerZero channel be blocked:

```solidity
// Add function in `CoreRootBridgeAgentTest.t.sol`

function testDosOutOfGas() public {

       // Source -> `avaxCoreBridgeAgentAddress`
       // Destination -> `coreBridgeAgent`
       // Trusted remote from Destination's perspective: abi.encodePacked(avaxCoreBridgeAgentAddress, coreBridgeAgent)

       //get some gas
       vm.deal(address(this), 1.5 ether);

       //Gas Params: set to 0 to simulate execution failure on `lzReceive()`
       GasParams memory gasParams = GasParams(0 ether, 0 ether);

        //Get some gas
       vm.deal(address(lzEndpointAddress), gasParams.gasLimit + gasParams.remoteBranchExecutionGas);

       // Prank into endpoint address
       vm.startPrank(lzEndpointAddress);

       vm.expectRevert(); // EvmError: OutOfGas (Message-less reverts happen when there is an EVM error)
       RootBridgeAgent(coreBridgeAgent).lzReceive{gas: gasParams.gasLimit}(
           avaxChainId, abi.encodePacked(coreBridgeAgent, avaxCoreBridgeAgentAddress), 1, bytes("")
       );
   }
```

### Tools used

Manual review, foundry

### Recommended mitigation steps

Although fixing this issue is not trivial due to the fact that Ulysses' architecture requires to allow users to always set gas params in an arbitrary manner, it is recommended to study gas necessities in each destination chain and perform gas parameters validation accordingly by setting up values to compare against, or setup base gas parameters to which arbitrary user parameters are added to. These methods are not bullet-proof but will significantly reduce the failed transactions, making it way more easy for the Maia team to handle blocked channels and retry payloads.