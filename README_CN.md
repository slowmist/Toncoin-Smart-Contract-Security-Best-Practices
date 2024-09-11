# Toncoin 智能合约安全最佳实践

[English Version](./README.md)

- [Toncoin智能合约常见陷阱：](#toncoin智能合约常见陷阱)
  - [缺少impure修饰符](#缺少impure修饰符)
  - [错误使用修改/非修改方法](#错误使用修改非修改方法)
  - [错误使用有符号/无符号整数](#错误使用有符号无符号整数)
  - [不安全的随机数](#不安全的随机数)
  - [在链上发送私人数据](#在链上发送私人数据)
  - [漏掉对退回消息的检查](#漏掉对退回消息的检查)
  - [在竞争条件下销毁账户的风险](#在竞争条件下销毁账户的风险)
  - [避免执行第三方代码](#避免执行第三方代码)
  - [名称冲突](#名称冲突)
  - [检查throw的值](#检查throw的值)
  - [读/写正确类型数据](#读写正确类型数据)
  - [合约代码可以更新](#合约代码可以更新)
  - [交易和阶段](#交易和阶段)
  - [不能从其他合约中拉取数据](#不能从其他合约中拉取数据)
  - [两个预定义的 method\_id](#两个预定义的-method_id)
  - [使用可反弹消息](#使用可反弹消息)
  - [重放保护](#重放保护)
  - [消息的竞态条件](#消息的竞态条件)
  - [使用携带值模式](#使用携带值模式)
  - [小心退还多余的燃料费](#小心退还多余的燃料费)
  - [检查函数返回值](#检查函数返回值)
  - [检查假冒的 Jetton 代币](#检查假冒的-jetton-代币)
- [参考](#参考)

## Toncoin智能合约常见陷阱：

### 缺少impure修饰符

- 严重性：高
- 描述：
  攻击者可能会发现`authorize`函数未标记为`impure`。缺少此修饰符将允许编译器在函数没有返回值或返回值未使用时跳过该函数的调用。
- 攻击场景：

```rust
() authorize (sender) inline {
  throw_unless(187, equal_slice_bits(sender, addr1) | equal_slice_bits(sender, addr2));
}
```

- 建议：

确保函数使用`impure`修饰符。

```fc
() authorize (sender) impure inline {
  throw_unless(187, equal_slice_bits(sender, addr1) | equal_slice_bits(sender, addr2));
}
```

### 错误使用修改/非修改方法

- 严重性：高
- 描述：
  `udict_delete_get?`被错误地用`.`调用，而不是`~`，因此实际的字典未被修改。
- 攻击场景：

```rust
(_, slice old_balance_slice, int found?) = accounts.udict_delete_get?(256, sender);
```

- 建议：

始终检查方法是否为修改/非修改方法。

```fc
(cell, slice, int) udict_delete_get?(cell dict, int key_len, int index) asm(index dict key_len) "DICTUDELGET" "NULLSWAPIFNOT";
(cell, (slice, int)) ~udict_delete_get?(cell dict, int key_len, int index) asm(index dict key_len) "DICTUDELGET" "NULLSWAPIFNOT";
```

修改方法（`~`）可能会接收一些参数并返回一些值，但它们会修改第一个参数，即将返回值的第一个组成部分分配给第一个参数中的变量。

```fc
(_, int found?) = accounts~udict_delete_get?(256, sender);
if(found) {
        ;; accounts 已被修改
}
```

### 错误使用有符号/无符号整数

- 严重性：高
- 描述：
  投票权被以整数形式存储在消息中。因此攻击者可以在权力转移期间发送负值并获得无限投票权。
- 攻击场景：

```rust
(cell,()) transfer_voting_power (cell votes, slice from, slice to, int amount) impure {
  int from_votes = get_voting_power(votes, from);
  int to_votes = get_voting_power(votes, to);

  from_votes -= amount;
  to_votes += amount;

  ;; 无需检查结果from_votes为正数：set_voting_power会对负投票值抛出异常
  ;; throw_unless(998, from_votes > 0);

  votes~set_voting_power(from, from_votes);
  votes~set_voting_power(to, to_votes);
  return (votes,());
}
```

- 建议：

在一些场景下有符号整数更安全，因为它们在发生溢出时会抛出错误，且仅在确实需要时使用有符号整数。

### 不安全的随机数

- 严重性：高
- 描述：
  种子来源于交易的逻辑时间，攻击者可以通过暴力破解当前区块中的逻辑时间来获胜（因为逻辑时间在一个区块的边界内是连续的）。
- 攻击场景：

```rust
int seed = cur_lt();
int seed_size = min(in_msg_body.slice_bits(), 128);

if(in_msg_body.slice_bits() > 0) {
    seed += in_msg_body~load_uint(seed_size);
}
set_seed(seed);
var balance = get_balance().pair_first();
if(balance > 5000 * 1000000000) {
    ;; 禁止过大的奖池
    raw_reserve( balance - 5000 * 1000000000, 0);
}
if(rand(10000) == 7777) { ...send reward... }
```

- 建议：

在进行`rand()`之前始终随机化种子，最好是永远不要使用链上随机数，验证者可以控制或影响种子。

### 在链上发送私人数据

- 严重性：高
- 描述：

请记住，所有数据都会被存储在区块链上。

- 攻击场景：

钱包受密码保护，其哈希值被存储在合约数据中。然而，区块链会记录一切——密码会出现在交易历史中。

- 建议：

不要在链上发送私人数据。

### 漏掉对退回消息的检查

- 严重性：高
- 描述：

Vault 没有退回处理程序或代理消息至数据库，如果用户发送“check”，我们可以在数据库中将 `msg_addr_none` 设置为奖励地址，因为 `load_msg_address` 允许这样做。我们请求 Vault 检查，数据库尝试使用 `parse_std_addr` 解析 `msg_addr_none`，失败。消息从数据库退回到 Vault，操作不是 `op_not_winner`。

- 攻击场景：

Vault在数据库消息处理器中包含以下代码：

```fc
int op = in_msg_body~load_op();

int mode = null();
if (op == op_not_winner) {
    mode = 64; ;; 退还剩余的check-TONs
               ;; addr_hash对应于check请求者
} else {
     mode = 128; ;; 奖励
                 ;; addr_hash对应于中奖条目中的提款地址
}
```

- 建议：

始终检查退回的消息。不要忘记标准函数引起的错误。使您的条件尽可能严格。

```fc
slice in_msg_full_slice = in_msg_full.begin_parse();
int msg_flags = in_msg_full_slice~load_msg_flags();
if (msg_flags & 1) { ;; 被退回
    on_bounce(in_msg_body);
    return ();
}
;; 其他逻辑
```

### 在竞争条件下销毁账户的风险

- 严重性：高
- 描述：

绝不要为了好玩而销毁账户。

- 攻击场景：

合约中存在竞争条件：您可以存款，然后尝试在并发消息中提取两次。不能保证处理已保留资金的消息，因此银行在第二次提款后可能关闭。之后，可以重新部署合约，任何人都可以提取未领取的资金。

- 建议：

使用`raw_reserve`而不是向自己发送资金。考虑可能的竞争条件。小心使用hashmap的气体消耗。

### 避免执行第三方代码

- 严重性：高
- 描述：

没有办法在合约中安全地执行第三方代码，因为CATCH不能处理气体不足异常。攻击者只需提交合约的任何状态并引发气体不足。

- 攻击场景：

```fc
slice try_execute(int image, (int -> slice) dehasher) asm "<{ TRY:<{ EXECUTE DEPTH 2 THROWIFNOT }>CATCH<{ 2DROP NULL }> }>CONT"   "2 1 CALLXARGS";

slice safe_execute(int image, (int -> slice) dehasher) inline {
  cell c4 = get_data();

  slice preimage = try_execute(image, dehasher);

  ;; 如果dehasher破坏了它，恢复c4
  set_data(c4);
  ;; 如果dehasher破坏了操作，清除操作
  set_c5(begin_cell().end_cell());

  return preimage;
}
```

- 建议：

避免在您的合约中执行第三方代码。

### 名称冲突

- 严重性：中
- 描述：

Func变量和函数可能包含几乎任何合法字符。

- 攻击场景：

`var++`、`~bits`、`foo-bar+baz`包括逗号`,` 都是有效的变量和函数名称。

- 建议：

编写和检查Func代码时，应该使用Linter工具。

### 检查throw的值

- 严重性：中
- 描述：

每次TVM执行正常停止时，它会以退出代码`0`或`1`停止。虽然它是自动完成的，但TVM执行可以在意外方式下直接中断，如果`throw(0)`或`throw(1)`命令直接抛出退出代码`0`和`1`。

- 攻击场景：

```fc
;;..
throw(0)
;;..
throw(1)
```

- 建议：

不要使用`0`或`1`作为throw的值。

### 读/写正确类型数据

- 严重性：中
- 描述：

读取意外变量的值，并在不应有此类方法的数据类型上调用方法（或者其返回值未正确存储）是错误的，不会作为“警告”或“通知”被跳过，而是导致无法到达的代码。

- 攻击场景：

请记住，存储意外值可能是可以的，但是读取它可能会导致问题。例如，对于整数变量，错误代码5（整数超出预期范围）可能被抛出。

- 建议：

密切跟踪代码的操作和它可能的返回值。请记住，编译器仅关心代码及其初始状态。

### 合约代码可以更新

- 严重性：中
- 描述：  
  TON完全实现了Actor模型，这意味着合约的代码可以更改。代码可以通过 `SETCODE` TVM 指令永久更改，或者在运行时设置 TVM 代码寄存器为新的单元值，直到执行结束。
- 利用场景：  
  不道德的开发者可能会恶意更新代码以窃取资金。
- 建议：  
  注意合约代码是可以更新的，确保任何更新都遵循安全实践，并使用例如治理模型或多签名批准等机制进行更改。

### 交易和阶段

- 严重性：中
- 描述：  
  计算阶段执行智能合约代码，然后执行操作（如发送消息、修改代码、更改库等）。与基于以太坊的区块链不同，如果你预计发送的消息会失败，你将看不到计算阶段的退出代码，因为消息并不是在计算阶段执行的，而是在稍后的操作阶段执行。
- 利用场景：  
  在操作阶段消息失败时会产生意外行为，导致对交易状态的错误假设。
- 建议：  
  了解每个交易最多包含五个阶段：存储阶段、信用阶段、计算阶段、操作阶段和反弹阶段。

### 不能从其他合约中拉取数据

- 严重性：中

- 描述：  
  区块链上的合约可以驻留在不同的分片上，并由不同的验证者处理。因此，开发人员无法按需从其他合约中拉取数据。通信是异步的，通过发送消息进行。

- 利用场景：  
  
  ```fc
  send_raw_message(msg.end_cell(), mode);
  ```

- 建议：  
  围绕异步消息设计合约逻辑，避免对同步数据可用性的假设。

### 两个预定义的 method_id

- 严重性：中

- 描述：  
  有两个预定义的 method_id：一个用于接收区块链内的消息 `(0)`，通常命名为 `recv_internal`，另一个用于接收来自外部的消息 `(-1)`，命名为 `recv_external`。

- 利用场景：  
  
  ```fc
  () recv_internal(int msg_value, cell in_msg_cell, slice in_msg) impure {
  }
  ```

() recv_external(slice in_msg) impure {
}

```
- 建议：  
确保正确处理 `recv_internal` 和 `recv_external` 方法，因为它们是合约交互的关键入口点。

### 处理反弹消息

- 严重性：高
- 描述：  
合约可能会收到反弹消息（错误通知），这些消息应被处理。  
TON智能合约是确定性的，并且可以预先计算，即使尚未部署。如果消息发送到未初始化或冻结的账户，它将被反弹回。
- 利用场景：  
将消息发送到未初始化的账户可能会导致意外错误或资金损失，如果没有处理好。
- 建议：  
在接收内部消息时检查反弹标志，并相应地处理，以避免意外后果。

### TON 地址可能有三种表示形式

- 严重性：中
- 描述：  
TON 地址可能有三种表示形式：原始格式（`workchain:address`）、用户友好格式（可以是`可反弹`或`不可反弹`），以及工作链 ID 字节。区分这些表示形式对于确保正确的地址处理非常重要。
- 利用场景：  
不正确地解释或处理地址可能会导致错误或意外后果。
```fc
原始地址：
0:b4c1b2ede12aa76f4a44353944258bcc8f99e9c7c474711a152c78b43218e296

可反弹地址：
EQC0wbLt4Sqnb0pENTlEJYvMj5npx8R0cRoVLHi0MhjilkPX

不可反弹地址：
UQC0wbLt4Sqnb0pENTlEJYvMj5npx8R0cRoVLHi0Mhjilh4S
```

- 建议：  
  使用如 `force_chain(to_address)` 的方法来验证地址是否在正确的链上。

### 使用可反弹消息

- 严重性：高

- 描述：  
  TON 区块链是异步的，消息不必按顺序到达。失败的消息应得到正确处理。

- 利用场景：  
  
  ```fc
  var msg = begin_cell()
    .store_uint(0x10, 6) ;; 没有反弹消息返回
    .store_slice(to_address)
    .store_coins(input_amount)
    .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
    .store_uint(op::excesses(), 32)
    .store_uint(query_id, 64)
  .end_cell();
  ```

- 建议：  
  始终使用可反弹消息（`0x18`）来正确处理消息失败。

### 重放保护

- 严重性：高

- 描述：  
  为钱包（存储用户资金的合约）实现重放保护，可以使用序列号（`seqno`）来确保消息不被重复处理，或使用带有到期的唯一交易标识符。

- 利用场景：  
  
  ```fc
  var ds = get_data().begin_parse();
  var (stored_seqno, stored_subwallet, public_key, plugins) = (ds~load_uint(32), ds~load_uint(32), ds~load_uint(256), ds~load_dict());
  ds.end_parse();
  throw_unless(33, msg_seqno == stored_seqno); ;; 防止消息被重复处理
  ;;..
  accept_message();
  set_data(begin_cell()
    .store_uint(stored_seqno + 1, 32)
    ;;..
  ```

- 建议：  
  使用类似序列号或消息唯一标识符的重放保护方法，以防止重放攻击。

### 消息的竞态条件

- 严重性：高
- 描述：  
  消息级联可以跨多个区块处理，攻击者可能会启动一个并行流，从而导致竞态条件。
- 利用场景：  
  攻击者可能会利用时间差异操纵合约行为。
- 建议：  
  通过在每个步骤验证状态并不假设消息流中的状态一致性来预防竞态条件。

### 使用携带值模式

- 严重性：高
- 描述：  
  在代币转账（例如TON Jetton）中，余额应使用携带值模式进行转账。发送方扣减余额，接收方将其加回或反弹回去。
- 利用场景：  
  如果处理不当，Jetton 余额可能被操纵。
- 建议：  
  使用携带值模式以确保正确的值转移。

### 小心退还多余的燃料费

- 严重性：高
- 描述：  
  如果未将多余的燃料费退还给发送者，资金可能会随着时间的推移在合约中积累。原则上，这并不可怕，但这是一种次优的做法。可以添加一个功能来清除多余的费用，但像 TON Jetton 这样的流行合约仍然会向发送者返回多余的费用消息 `op::excesses`。

### 检查函数返回值

- 严重性：高

- 描述：  
  函数总是会返回值或错误，如果忽略对返回值的检查，可能会导致逻辑上的致命错误。

- 利用场景：  
  
  ```fc
  dictinfos~udict_delete?(32, index);
  ;;..
  ```

- 建议：  
  始终检查函数的返回值。  
  
  ```fc
  int success = dictinfos~udict_delete?(32, index);
  throw_unless(err::fail_to_delete_dict, success);
  ```

### 检查假冒的 Jetton 代币

- 严重性：高

- 描述：  
  Jetton 代币由两部分组成：`jetton-minter` 和 `jetton-wallet`。如果保险库合约没有正确验证，攻击者可能会通过存入假代币并提取有价值的代币来耗尽保险库中的资金。

- 利用场景：  
  
  ```fc
  if (op == op::internal_transfer) {
    deposit_for_sender(in_msg_body, sender_address, my_ton_balance, msg_value);
    return ();
  }
  ```

- 建议：  
  通过计算用户的 jetton 钱包地址，检查发送者是否发送了假冒的 Jetton 代币。

## 参考

[1]. https://dev.to/dvlkv/drawing-conclusions-from-ton-hack-challenge-1aep

[2]. https://docs.ton.org/develop/smart-contracts/security/ton-hack-challenge-1

[3]. https://docs.ton.org/learn/tvm-instructions/tvm-overview

[4]. https://docs.ton.org/develop/smart-contracts/messages

[5]. https://docs.ton.org/develop/smart-contracts/security/secure-programming

[6]. https://docs.ton.org/develop/smart-contracts/security/things-to-focus
