# Toncoin Smart Contract Security Best Practices

![https://img.shields.io/twitter/url/https/twitter.com/slowmist_team.svg?style=social&label=Follow%20%40SlowMist_Team](https://img.shields.io/twitter/url/https/twitter.com/slowmist_team.svg?style=social&label=Follow%20%40SlowMist_Team)

[中文版本](./README_CN.md)

- [Toncoin Smart Contract Security Best Practices](#toncoin-smart-contract-security-best-practices)
  - [Common Pitfalls of Toncoin Smart Contracts:](#common-pitfalls-of-toncoin-smart-contracts)
    - [Lack of impure modifier](#lack-of-impure-modifier)
    - [Incorrect use of modifying/non-modifying methods](#incorrect-use-of-modifyingnon-modifying-methods)
    - [Incorrect use of signed/unsigned integer](#incorrect-use-of-signedunsigned-integer)
    - [Un-secure random number](#un-secure-random-number)
    - [Send private data on chain](#send-private-data-on-chain)
    - [Missing check for bounced messages](#missing-check-for-bounced-messages)
    - [Risk of destroy account under race conditions](#risk-of-destroy-account-under-race-conditions)
    - [Avoid executing third-party code](#avoid-executing-third-party-code)
    - [Name collision](#name-collision)
    - [Check the throw values](#check-the-throw-values)
    - [Read/Write correct type data](#readwrite-correct-type-data)
    - [Code of contracts can be updated](#code-of-contracts-can-be-updated)
    - [Transaction and phases](#transaction-and-phases)
    - [Cannot pull data from other contracts](#cannot-pull-data-from-other-contracts)
    - [Two predefined medhod\_id](#two-predefined-medhod_id)
    - [Handle bounced messages](#handle-bounced-messages)
    - [TON addresses may have three representations](#ton-addresses-may-have-three-representations)
    - [Use bounce-able message](#use-bounce-able-message)
    - [Replay protection](#replay-protection)
    - [Race condition of messages](#race-condition-of-messages)
    - [Use a carry-value pattern](#use-a-carry-value-pattern)
    - [Return gas excesses carefully](#return-gas-excesses-carefully)
    - [Check function return values](#check-function-return-values)
    - [Check fake Jetton tokens](#check-fake-jetton-tokens)
  - [Reference](#reference)

## Common Pitfalls of Toncoin Smart Contracts:

### Lack of impure modifier

- Severity: High
- Description:
  The attacker could find that `authorize` function was not `impure`. The absence of this modifier allows a compiler to skip calls to that function if it returns nothing or the return value is unused.
- Exploit Scenario:

```rust
() authorize (sender) inline {
  throw_unless(187, equal_slice_bits(sender, addr1) | equal_slice_bits(sender, addr2));
}
```

- Recommendation:

Always check functions for `impure`modifier.

```fc
() authorize (sender) impure inline {
  throw_unless(187, equal_slice_bits(sender, addr1) | equal_slice_bits(sender, addr2));
}
```

### Incorrect use of modifying/non-modifying methods

- Severity: High
- Description:
  `udict_delete_get?` was called with `.` instead `~`, so the real dict was untouched.
- Exploit Scenario:

```rust
(_, slice old_balance_slice, int found?) = accounts.udict_delete_get?(256, sender);
```

- Recommendation:

Always check for modifying/non-modifying methods.

```fc
(cell, slice, int) udict_delete_get?(cell dict, int key_len, int index) asm(index dict key_len) "DICTUDELGET" "NULLSWAPIFNOT";
(cell, (slice, int)) ~udict_delete_get?(cell dict, int key_len, int index) asm(index dict key_len) "DICTUDELGET" "NULLSWAPIFNOT";
```

Modifying method (`~`) calls may take some arguments and return some values, but they modify their first argument, that is, assign the first component of the returned value to the variable from the first argument.

```fc
(_, int found?) = accounts~udict_delete_get?(256, sender);
if(found) {
        ;; accounts has been changed
}
```

### Incorrect use of signed/unsigned integer

- Severity: High
- Description:
  Voting power was stored in message as an integer. So the attacker could send a negative value during power transfer and get infinite voting power.
- Exploit Scenario:

```rust
(cell,()) transfer_voting_power (cell votes, slice from, slice to, int amount) impure {
  int from_votes = get_voting_power(votes, from);
  int to_votes = get_voting_power(votes, to);

  from_votes -= amount;
  to_votes += amount;

  ;; No need to check that result from_votes is positive: set_voting_power will throw for negative votes
  ;; throw_unless(998, from_votes > 0);

  votes~set_voting_power(from, from_votes);
  votes~set_voting_power(to, to_votes);
  return (votes,());
}
```

- Recommendation:

Unsigned integers are safer because they will error out if an overflow occurs, and signed integers are only used when they are really needed.

### Un-secure random number

- Severity: High
- Description:
  Seed was brought from logical time of the transaction, and a hacker can win by bruteforcing the logical time in the current block (cause lt is sequential in the borders of one block).
- Exploit Scenario:

```rust
int seed = cur_lt();
int seed_size = min(in_msg_body.slice_bits(), 128);

if(in_msg_body.slice_bits() > 0) {
    seed += in_msg_body~load_uint(seed_size);
}
set_seed(seed);
var balance = get_balance().pair_first();
if(balance > 5000 * 1000000000) {
    ;; forbid too large jackpot
    raw_reserve( balance - 5000 * 1000000000, 0);
}
if(rand(10000) == 7777) { ...send reward... }
```

- Recommendation:

Always randomize seed before doing `rand()`, a better suggestion is never use on chain randomness, the validators has ways to control or affect the seed.

### Send private data on chain

- Severity: High
- Description:

Remember that everything is stored in the blockchain.

- Exploit Scenario:

The wallet was protected with password, it's hash was stored in contract data. However, the blockchain remembers everything—the password was in the transaction history

- Recommendation:

Do not send private data on chain.

### Missing check for bounced messages

- Severity: High
- Description:

Vault does not have a bounce handler or proxy message to the database if the user sends “check”. In the database we can set `msg_addr_none` as an award address because `load_msg_address` allows it. We are requesting a check from the vault, database tries to parse `msg_addr_none` using `parse_std_addr`, and fails. Message bounces to the vault from the database and op is not `op_not_winner`.

- Exploit Scenario:

The vault has the following code in the database message handler:

```fc
int op = in_msg_body~load_op();

int mode = null();
if (op == op_not_winner) {
    mode = 64; ;; Refund remaining check-TONs
               ;; addr_hash corresponds to check requester
} else {
     mode = 128; ;; Award the prize
                 ;; addr_hash corresponds to the withdrawal address from the winning entry
}
```

- Recommendation:

Always check for bounced messages. Don't forget about errors caused by standard functions. Make your conditions as strict as possible.

```fc
slice in_msg_full_slice = in_msg_full.begin_parse();
int msg_flags = in_msg_full_slice~load_msg_flags();
if (msg_flags & 1) { ;; is bounced
    on_bounce(in_msg_body);
    return ();
}
;; other logic
```

### Risk of destroy account under race conditions

- Severity: High
- Description:

Never destroy account for fun.

- Exploit Scenario:
```
() recv_internal (msg_value, in_msg_full, in_msg_body) {
    if (in_msg_body.slice_empty?()) { ;; ignore empty messages
        return ();
    }
    slice cs = in_msg_full.begin_parse();
    int flags = cs~load_uint(4);

    if (flags & 1) { ;; ignore all bounced messages
        return ();
    }
    slice sender_address = cs~load_msg_addr();
    if (equal_slice_bits(sender_address, my_address())) {
        ;; money reserve
        return ();
    }
    


    (int wc, int sender) = parse_std_addr(sender_address);
    throw_unless(99, wc == 0);
    
    int op = in_msg_body~load_uint(32);
    int query_id = in_msg_body~load_uint(64);
    
    load_data();
    cell accounts' = accounts;

    if( op == 0 ) { ;; Deposit
      int fee = 10000000;
      int balance = max(msg_value - fee, 0);
      total_balance = total_balance + balance;
      (_, slice old_balance_slice, int found?) = accounts'.udict_delete_get?(256, sender);
      if(found?) {
        balance += old_balance_slice~load_coins();
      }
      accounts'~udict_set_builder(256, sender, begin_cell().store_coins(balance));
    }
    if (op == 1) { ;; Withdraw
      int withdraw_fee = 10000000;
      (accounts', slice old_balance_slice, int found?) = accounts'.udict_delete_get?(256, sender);
      throw_unless(98, found?);
      int balance = old_balance_slice~load_coins();
      int withdraw_amount = in_msg_body~load_coins() + withdraw_fee;
      throw_unless(100, balance >= withdraw_amount);
      balance -= withdraw_amount;
      total_balance = total_balance - withdraw_amount;
      if(balance > 0 ) {
        accounts'~udict_set_builder(256, sender, begin_cell().store_coins(balance));
      }
      
      ;; To be sure nobody steal funds - first send it to ourselves
      var storage_fee = 100000000;
      var msg = begin_cell()
        .store_uint(0x18, 6)
        .store_slice(my_address())
        .store_coins(total_balance + storage_fee)
        .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
      .end_cell();
      send_raw_message(msg, 2);      
      
      int mode = 2 | 128;
      if(get_balance().pair_first() < withdraw_amount) { ;; all money withdrawn, shutdown bank
        mode |= 32;
      }
      ;; everything else can be sent to user
      var msg = begin_cell()
        .store_uint(0x18, 6)
        .store_slice(sender_address)
        .store_coins(0)
        .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
      .end_cell();
      send_raw_message(msg, mode);
    }
    accounts = accounts';
    save_data();
}
```
There were race condition in the contract: you can deposit money, then try to withdraw two times in concurrent messages. There is no guarantee that message with reserved money will be processed, so bank can shutdown after second withdrawal. After that the contract could be redeployed and then anybody can withdraw unowned money.

- Recommendation:

Make `raw_reserve` instead of sending money to yourself. Think about possible race conditions. Be careful with hashmap gas consumption.

### Avoid executing third-party code

- Severity: High
- Description:

There is no way to safe execute a third-party code in the contract, because out of gas exception cannot be handled by CATCH. The attacker simply can COMMIT any state of contract and raise out of gas.

- Exploit Scenario:

```fc
slice try_execute(int image, (int -> slice) dehasher) asm "<{ TRY:<{ EXECUTE DEPTH 2 THROWIFNOT }>CATCH<{ 2DROP NULL }> }>CONT"   "2 1 CALLXARGS";

slice safe_execute(int image, (int -> slice) dehasher) inline {
  cell c4 = get_data();

  slice preimage = try_execute(image, dehasher);

  ;; restore c4 if dehasher spoiled it
  set_data(c4);
  ;; clean actions if dehasher spoiled them
  set_c5(begin_cell().end_cell());

  return preimage;
}
```

- Recommendation:

Avoid executing third-party code in your contract.

### Name collision

- Severity: Medium
- Description:

Func variables and functions may contain almost any legit character.

- Exploit Scenario:

`var++`, `~bits`, `foo-bar+baz` including commas`,` are valid variables and functions names.

- Recommendation:

When writing and inspecting a Func code, Linter should be used.

### Check the throw values

- Severity: Medium
- Description:

Each time the TVM execution stops normally, it stops with exit codes `0` or `1`. Although it is done automatically, TVM execution can be interrupted directly in an unexpected way if exit codes `0` and `1` are thrown directly by either `throw(0)` or `throw(1)` command.

- Exploit Scenario:

```fc
;;..
throw(0)
;;..
throw(1)
```

- Recommendation:

Do not use `0` or `1` as throw values.

### Read/Write correct type data

- Severity: Medium
- Description:

Reading unexpected variables values and calling methods on data types that are not supposed to have such methods (or their return values are not stored properly) are errors and are not skipped as "warnings" or "notices" but lead to unreachable code.

- Exploit Scenario:

Keep in mind that storing an unexpected value may be okay, however, reading it may cause problems. e.g. error code 5 (integer out of expected range) may be thrown for an integer variable.

- Recommendation:

It is crucial to keep track of what the code does and what it may return. Keep in mind that the compiler cares only about the code and only in its initial state. After certain operations stored values of some variables can change.

### Code of contracts can be updated

- Severity: Medium
- Description:

TON fully implements the actor model, it means the code of the contract can be changed. It can either be changed permanently, using `SETCODE` TVM directive, or in runtime, setting the TVM code registry to a new cell value until the end of execution.

- Exploit Scenario:

An unscrupulous developer could maliciously update the code to steal money.

- Recommendation:

Notice that the code of contracts can be updated.

### Transaction and phases

- Severity: Medium
- Description:

The computational phase executes the code of smart contracts and only then the actions are performed (sending messages, code modification, changing libraries, and others). 

- Exploit Scenario:

So, unlike on Ethereum-based blockchains, you won't see the computational phase exit code if you expected the sent message to fail, as it was performed not in the computational phase, but later, during the action phase.

- Recommendation:

Each transaction consists of up to 5 phases: Storage phase, credit phase, compute phase, action phase, bounce phase.

### Cannot pull data from other contracts

- Severity: Medium
- Description:

Contracts in the blockchain can reside in separate shards, processed by other set of validators, meaning that developer cannot pull data from other contracts on demand. Thus, any communication is asynchronous and done by sending messages.

- Exploit Scenario:

```fc
  send_raw_message(msg.end_cell(), mode);
```

- Recommendation:

Cannot pull data from other contracts.

### Two predefined medhod_id

- Severity: Medium
- Description:

They can be either set explicitly `"method_id(5)"`, or implicitly by a func compiler. In this case, they can be found among methods declarations in the .fift assembly file. Two of them are predefined: one for receiving messages inside of blockchain `(0)`, commonly named `recv_internal`, and one for receiving messages from outside `(-1)`, `recv_external`.

- Exploit Scenario:

```fc
() recv_internal(int msg_value, cell in_msg_cell, slice in_msg) impure {
}

() recv_external(slice in_msg) impure {
}
```

- Recommendation:

recv_internal/recv_external are predefined.

### Handle bounced messages

- Severity: High
- Description:

You may receive bounced messages (error notifications), which should be handled.

- Exploit Scenario:

Smart contracts addresses in TON blockchain are deterministic and can be precomputed. Ton Accounts, associated with addresses may even contain no code which means they are uninitialized (if not deployed) or frozen while having no more storage or TON coins if the message with special flags was sent. The message will be bounced if you send a message to an uninitialized account.

- Recommendation:

Check if the bounced flag was sent receiving internal messages.

### TON addresses may have three representations

- Severity: Medium
- Description:

TON addresses may have three representations. A full representation can either be "raw" (`workchain:address`) or "user-friendly". The last one is the one users encounter most often. It contains a tag byte, indicating whether the address is `bounceable` or `not bounceable`, and a workchain id byte. This information should be noted.

- Exploit Scenario:

```fc
Raw address:
0:b4c1b2ede12aa76f4a44353944258bcc8f99e9c7c474711a152c78b43218e296

Bounceable address:
EQC0wbLt4Sqnb0pENTlEJYvMj5npx8R0cRoVLHi0MhjilkPX

Non-bounceable address:
UQC0wbLt4Sqnb0pENTlEJYvMj5npx8R0cRoVLHi0Mhjilh4S
```

- Recommendation:

Check if an address is on a correct chain `force_chain(to_address);`.

### Use bounce-able message

- Severity: High
- Description:

TON blockchain is asynchronous. That means the messages do not have to arrive successively. e.g. when a fail notification of an action arrives, it should be handled properly.

- Exploit Scenario:

```fc
var msg = begin_cell()
    .store_uint(0x10, 6) ;; nobounceed no bounced msg return
    .store_slice(to_address)
    .store_coins(input_amount)
    .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
    .store_uint(op::excesses(), 32)
    .store_uint(query_id, 64)
.end_cell();
```

- Recommendation:

Always use bounce-able message `0x18` in case the message fails.

### Replay protection

- Severity: High
- Description:

There are two custom solutions for wallets (smart contracts, storing users money): `seqno-based` (check the counter not to process message twice) and `high-load` (storing processes identifiers and its expirations).

- Exploit Scenario:

```fc
  var ds = get_data().begin_parse();
  var (stored_seqno, stored_subwallet, public_key, plugins) = (ds~load_uint(32), ds~load_uint(32), ds~load_uint(256), ds~load_dict());
  ds.end_parse();
  throw_unless(33, msg_seqno == stored_seqno); ;;not to process message twice
  ;;..
  accept_message();
  set_data(begin_cell()
    .store_uint(stored_seqno + 1, 32)
    ;;..
```

- Recommendation:

Write replay protection for external messages.

### Race condition of messages

- Severity: High
- Description:

A message cascade can be processed over many blocks. Assume that while one message flow is running, an attacker can initiate a second one in parallel. That is, if a property was checked at the beginning (e.g. whether the user has enough tokens), do not assume that at the third stage in the same contract they will still satisfy this property.

- Exploit Scenario: Nothing
- Recommendation:

Expect a Man-in-the-Middle of the Message Flow

### Use a carry-value pattern

- Severity: High
- Description:

In the same TON Jetton, this is demonstrated: `sender_wallet` subtracts the balance and sends it with an `op::internal_transfer` message to `destination_wallet`, and it, in turn, receives the balance with the message and adds it to its own balance (or bounces it back).

- Exploit Scenario:

Why can't you find out your Jetton balance on-chain? Because such a question does not fit the pattern. By the time the response to the `op::get_balance` message reaches the requester, this balance could already have been spent by someone.

- Recommendation:

Use a carry-value pattern.

### Return gas excesses carefully

- Severity: High
- Description:

If excess gas is not returned to the sender, the funds will accumulate in your contracts over time. In principle, nothing terrible, this is just suboptimal practice. You can add a function for raking out excesses, but popular contracts like TON Jetton still return to the sender with the message `op::excesses`.

- Exploit Scenario:

If the value of the contract balance runs out, the transaction will be partially executed, and this cannot be allowed.

- Recommendation:

When using the `send_raw_message` function, it is important to select the appropriate mode and flag combination for your needs. 

### Check function return values

- Severity: High
- Description:

Functions always return values or errors, it will cause logical fatal if you miss to check it

- Exploit Scenario:

```fc
dictinfos~udict_delete?(32, index);
;;..
```

- Recommendation:

Always check function return values.

```
int success = dictinfos~udict_delete?(32, index);
throw_unless(err::fail_to_delete_dict, success);
```

### Check fake Jetton tokens

- Severity: High
- Description:

Jetton token are combine of two parts: jetton-minter and jetton-wallet, if the vault contracts not verify correctly, attacker will dry out the vaults by deposit fake token and withdraw valuable tokens.

- Exploit Scenario:

```fc
if (op == op::internal_transfer) {
    deposit_for_sender(in_msg_body, sender_address, my_ton_balance, msg_value);
    return ();
}
```

- Recommendation:

Check if sender send fake jetton token by calculate user jetton wallet address.

## Reference
[1]. https://github.com/ton-blockchain/hack-challenge-1

[2]. https://dev.to/dvlkv/drawing-conclusions-from-ton-hack-challenge-1aep

[3]. https://docs.ton.org/develop/smart-contracts/security/ton-hack-challenge-1

[4]. https://docs.ton.org/learn/tvm-instructions/tvm-overview

[5]. https://docs.ton.org/develop/smart-contracts/messages

[6]. https://docs.ton.org/develop/smart-contracts/security/secure-programming

[7]. https://docs.ton.org/develop/smart-contracts/security/things-to-focus
