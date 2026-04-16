# Engineering Standards
To ensure consistent high quality code, every PR must conform to the following principles.

- [Don't panic](#dont-panic)
- [Maintain local reasonability](#maintain-local-reasonability)
- [Use safe arithmetic methods](#use-safe-arithmetic-methods)
- [Separate business logic from I/O](#separate-business-logic-from-io)
- [Add tests](#add-tests)
- [Measure performance](#measure-performance)

Beyond our engineering standards,
The Rust library team maintains a set of [API guidelines](https://rust-lang.github.io/api-guidelines/about.html).
We should also try to follow these to the greatest extent possible where applicable.

## Don't panic
While there are a few exceptions to this rule, most of our code should be panic-free.
Therefore we should avoid calling `.expect()`, `.unwrap()` in production code, as
well as any other methods that may implicitly or explicitly panic.

The three exceptions to this rule are:

1. The top level main function may panic if it is not able to parse arguments,
   configuration or anything else needed to start the node in the first place.
2. In the smart contract, as panicking ensures no side-effects happen in the transaction.
3. Code paths that are guaranteed to be dead by runtime invariants.


In the first case there's no harm in panicking since the node hasn't started.
The second one is the convention of NEAR smart contracts.

However, the third case is more subtle and debatable.
We should minimize dead code paths, but occasionally it's possible to hit
scenarios when you can guarantee that a panic won't occur.

Take this code for example:

```rust
/// Increments the first number of the slice
fn increment_first_number(numbers: &mut [u8]) {
   if numbers.is_empty() {
      return;
   }

   // May not panic since we check above that the array is non-empty
   *numbers.get_mut(0).unwrap() += 1
}
```

This function contains an `.unwrap()`, but we can still guarantee that
this function will never ever panic. Therefore it's not violating
the "Don't panic" principle.

## Maintain Local Reasonability
It's often tempting to write code that has implicit sequential dependencies.
In these scenarios, the correctness of one expression depends on
the presence of other expressions.

Considering the code example from the [Don't panic](#dont-panic) section,
the correctness of the `.unwrap()` can only be reasoned about by understanding
the `numbers.is_empty()` check. This entangles these two expressions, making
it harder to reason about and review the code.
This also allows the risk of a future PR accidentally removing the `.is_empty()`
check potentially causing the panic to occur in production.

If we instead wrote the function the following way:

```rust
/// Increments the first number of the slice
fn increment_first_number(numbers: &mut [u8]) {
   if let Some(first_number) = numbers.get_mut(0) {
      *first_number += 1;
   }
}
```

we'd have no sequential dependencies.
This code cannot become incorrect by some externally maintained
invariant being broken because it doesn't make any assumptions
about any surrounding code.

Therefore we recognize the variant as the better alternative.

## Use safe arithmetic methods
It's convenient to use the arithmetic operators (`+`, `-`, `*`)
for mathematical expressions. However, these may panic or overflow/underflow
depending on the compiler. This can lead to unintended behavior and
it's best to completely avoid them for primitive types in favor of
explicit methods (`checked_add`, `wrapping_add` etc.).

Note that for custom types these operators may still be fine,
if they are implemented so that they don't overflow.

For example, typical implementations of cryptographic scalars
in some field use modular arithmetic and therefore have
well defined behavior when used with these operators.

```rust
// Don't
let z = x + y;

// Do
if let Some(z) = x.checked_add(y) {
   // Do stuff with z
} else {
   // Handle error or explain why this will never happen and panic
}
```

## Separate business logic from I/O
Imagine you're asked to implement a function that
posts incrementing fibonacci numbers after waiting the
same amount of hours as the current number to some endpoint.

It would be very tempting to write the function the following way.

```rust
async fn post_fibonacci_sequence(n: usize) {
    for i in 0..n {
        tokio::time::sleep(Duration::from_hours(i)).await;
        reqwest::Client::new()
            .post("https://fibonacci.org/sequence")
            .body(i.to_string())
            .send()
            .await;
    }
}
```

Functionally speaking there's nothing wrong with this implementation.
It fulfills the requirements and it would work correctly in production.

This is not a problem for a dummy example, but for any non-trivial system
it is wise to add tests for important functionality to ensure it works
as expected. This is where the naive implementation becomes problematic,
because how do you test this system?

The naive way of testing this would be to add a configuration value for
the endpoint and auto-advance tokio time in the test.
The tests could spin up their own web server which receives the request
and asserts that it matches the expectation.

Doing all this work just for a simple test case is both very complex,
and completely fails to test half of the functionality in this function.
You can assert that the values received to the endpoint are correct
but how do you measure that the sleep time is right?

The core problem is that this function mixes I/O and business logic.
If we instead broke out the I/O from the function by introducing appropriate
traits, we'd end up with the following:

```rust
async fn post_fibonacci_sequence(client: impl HttpClient, time: impl Time, n: usize) {
    for i in 0..n {
        time.sleep(Duration::from_hours(i)).await;
        client.post("https://fibonacci.org/sequence")
            .body(i.to_string())
            .send()
            .await;
    }
```

Now we can trivially test this function without spinning up any
web server or manipulating the tokio runtime.
As a bonus, unit testing this kind of functionality is typically lightning fast.

There are other approaches to separate I/O and business logic,
and we're currently agnostic to the approach taken but as a general
rule we'll reject new changes if they mix I/O and business logic.

## Add tests
Any change to our system should come with tests such that if
the change was reverted, these tests would fail.

Currently, we have three types of tests:

- **Unit tests**: Illustrate and assert behavior of individual pieces of functionality.
- **Crate integration tests**: Test the public interface of a crate to ensure different parts of it work nicely together.
- **System tests**: Test the whole system as a single unit.

All of these are important as they serve different purposes.
They complement each other and should not be used as a substitute for one-another.
E.g. we should not rely on system tests to cover all interesting code paths
of all pieces of the system,
and we should not run other functionality than the system under test in unit tests.

It's encouraged to follow this structure when writing new tests:

```rust

#[test]
fn <system_under_test>__should_<test_assertion>(){
   // Given
   <setup system under test>

   // When
   <interact with system under test>

   // Then
   <assert expected outcome>
}
```

the system under test (SUT) can be many things, but typically this would be a function,
method or a struct.

## Measure performance
It's easy to get stuck in arguments about what's faster or more expensive
when comparing different approaches. In these scenarios, we should strive
to measure the performance of the system of interest. Anything that isn't
benchmarked properly will regress over time.

Therefore, any proposed performance improvements should come with benchmarks
or some other objective measure of improvement and regression tests that
prevent the optimization from regressing in future iterations.
