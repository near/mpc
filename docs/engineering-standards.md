# Engineering Standards
To ensure consistent high quality code, every PR must conform to the following principles.

- [Don't panic](#dont-panic)
- [Maintain local reasonability](#maintain-local-reasonability)
- [Use safe arithmetic methods](#use-safe-arithmetic-methods)
- [Separate business logic from I/O](#separate-business-logic-from-io)
- [Add tests](#add-tests)
- [Measure performance](#measure-performance)
- [Write helpful code comments](#write-helpful-code-comments)

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

### `must_` prefix for panicking test helpers

In test code, plumbing helpers (loading WASM artifacts, resolving binary
paths, extracting setup data from a known-good state) should panic on
failure instead of returning `Result`: the failure means the test wasn't
built or wired correctly, not that the system under test misbehaved, so
there's no useful error path. Such helpers must be prefixed with `must_`
(e.g. `must_load_contract_wasm`, `must_get_bls_public_key`) so callers
can see at the call site that the function will panic on failure.

Helpers whose failure could be a meaningful test outcome (network calls,
state observations) should still return `Result`.

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

## Write helpful code comments
With the advent of LLMs, code comments have become much more prevalent. The issue is that LLMs tend to document **what** the code does, less so **why** the code does it.
As usual, the PR author is taking ownership of the code, regardless of whether that code has been produced by an LLM or was written by themselves.

As such, the following code comment patterns may get rejected at review:

1. **Paraphrasing the code, without providing additional information.** Instead of providing a code comment, try to find better function or struct names.
    ```rust
    // Don't
    /// Adds `y` and `x` modulo 10.
    ///
    /// Returns `None` when the result is zero — i.e. whenever `x + y` is a
    /// multiple of 10 (`1 + 9`, `5 + 5`, ...) — since the result type cannot
    /// represent zero. Returns `Some` with the mod-10 sum otherwise.
    ///
    /// Helper used by `this_other_method` to implement decimal-digit
    /// arithmetic. Kept separate to make the carry logic easier to test.
    fn my_add(x: NonZeroU8, y: NonZeroU8) -> Option<NonZeroU8> { ... }

    // Do
    /// Returns `None` if the result is zero.
    fn add_mod_10(x: NonZeroU8, y: NonZeroU8) -> Option<NonZeroU8> { ... }

    // Don't
    /// Has a field `x` of type `MyOtherStructX` and a field `y` of type `MyOtherStructY`
    struct MyStruct {
        /// An instance of `MyOtherStructX`
        x: MyOtherStructX,
        /// An instance of `MyOtherStructY`
        y: MyOtherStructY,
    }

    // Do
    struct MyStruct {
        descriptive_name_for_field_1: MyOtherStructX,
        descriptive_name_for_field_2: MyOtherStructY,
    }
    ```

2. **Repetition by explanation of common terminology.** There is no need in explaining concepts such as _Lazy_ or _idempotent_. We assume whoever is exploring our codebase knows how to search for definition of appropriate terms.
    ```rust
    // Don't
    /// Adds `thing`.
    ///
    /// Idempotent in `thing`: adding the same `thing` more than once has the
    /// same effect as adding it once. The second add is a no-op / overwrites
    /// the existing entry with an equal value — so callers can re-add without
    /// first checking whether it's already present.
    fn add_the_thing(self, thing: Thing) { ... }

    // Do
    /// idempotent
    fn add_the_thing(self, thing: Thing) { ... }
    ```
3. **Burdening the reader with unnecessary context.** LLMs often let session context leak into code comments.
If it was instructed to implement `ComponentVersionA` instead of `ComponentVersionB`, it often attaches a comment of the sort:
    ```rust
    // Don't
    /// This struct achieves <xyz>, using <insert_version_a_specific_way_of_doing_the_thing> instead of <insert_version_b_specific_way_of_doing_the_thing>.
    struct ComponentVersionA;

    // Do
    struct ComponentVersionA;
    ```
   This is not helpful to the reader. If the trade-off is non-obvious, then the PR description is probably the best place to explain it and requires a more lengthy explanation, focusing on the different approaches that have been considered, their trade-offs and explaining **why** the author chose one way over the other.
4. **Explaining where this code is used**. Most of the time, it is redundant to explain _where_ a piece of code is used. Code editors can produce that information much more reliably than code comments. In the rare case where such a code comment is warranted and provides useful information, it is imperative that the referred callsite or objects are linked, such that the CI can pick up stale references.

    ```rust
    // Don't
    /// Stored behind a `Lazy` in `ThisOtherStruct`.
    struct ThisStruct;

    // Do
    struct ThisStruct;
    ```

5. **Long-form rationale that belongs in an issue.** Prefer
   `// TODO(#NNNN): <short replacement>` over a paragraph of
   context. The *why* lives in the issue:

    ```rust
    // Don't
    /// We use [`BTreeMap`] instead of [`HashMap`] here because the snapshot
    /// test in [`parameter_store::tests::stable_iteration`] was written
    /// against a stable iteration order. If we ever migrate that test to be
    /// insensitive to order, this could go back to [`HashMap`]. Leaving as
    /// [`BTreeMap`] for now to keep the diff small and avoid touching
    /// unrelated test infrastructure.
    fn build_params() -> Params { ... }

    // Do
    /// TODO(#NNNN): can become [`HashMap`] once [`parameter_store`] test no
    /// longer asserts stable iteration order.
    fn build_params() -> Params { ... }
    ```


**Public APIs are the exception.** Doc comments on public items
(types, functions, traits) may be more explanatory than internal
comments, because consumers can't see the implementation.
It may be permittable to explain **what** the code does, to the extent necessary and relevant for the reader (for example: _Sorts a vector in O(n log n)_).
Generally speaking, such API comments increase their value if they explain _how_ to use the code, with a brief example.

**Use rustdoc intra-doc links instead of plain backticks.** Whenever a doc
comment names another type, function, module, or path, write it as
`` [`Foo`] `` (a rustdoc intra-doc link) rather than `` `Foo` `` (a plain
inline-code span). `cargo doc` verifies the former and reports broken
references; plain backticks render the same but are not checked, so
references silently rot when items are renamed or moved.

