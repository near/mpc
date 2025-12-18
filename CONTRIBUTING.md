# Contributing to NEAR MPC
Thanks for considering contributing to the NEAR MPC network.
Whether you're an external developer looking to make a contribution
or a member of the Near One MPC team working in this repo every day,
this guide should help you understand our workflow and our expectations on contributions.

There are several ways to contribute to the MPC network.
The following are the most common:

1. Run an MPC node.
2. Spot a problem or potential improvement and raise an issue.
3. Open PRs to resolve issues.
4. Review PRs to verify they are correct and follow our standards.

If you're interested in running an MPC node, please reach out to us directly at [mpc@nearone.org](mailto:mpc@nearone.org).
The rest of this guide is focused on our flow for creating issues and PRs.

## Creating issues
We use issues to define and track changes to our system.
A good issue should contain sufficient context so that any developer
can pick it up and implement an acceptable solution to it.

We use the following template to ensure all issues are well-defined and provide relevant context:

- **Background**: Explains relevant aspects of the current state of things and highlights what's currently lacking/problematic.
- **Acceptance Criteria**: A condition that must be met for the issue to be regarded as completed.
- **User Story**: (optional) Follows the form: "As a <user type>, I want to <feature description>, so that I can <user benefit>".
  This helps clarify the relevance of the issue.

Issues should contain relevant links to other issues and PRs for more context,
and be tagged with relevant labels (e.g. `contract`, `launcher`, `security`, `tech-debt`, `bug`).

This helps keep the issues discoverable and easy to track.

## Working on issues and opening PRs
Congratulations, you've found an issue you want to work on.
Now, please do the following things:

1. Assign yourself to the issue to ensure it's visible you're working on it.
2. Create a branch and link it to the issue.
   We recommend using the github UI to create the branch as it will automatically link it and use a canonical format for the branch name.
3. Check out the branch and get to work.

Once you've made the relevant changes to fulfill the acceptance criteria and the code lives up to our [engineering standards](#engineering-standards),
it's time to open a PR.

When opening the PR, make sure to link the issue in the PR description.
Add any other notes that will be helpful for reviewers in the description.
However, in many cases it is sufficient to only reference the issue in the PR description.

## Reviewing PRs
A PR review is the act of answering the following questions:

- Is this code fulfilling the acceptance criteria of the issue?
- Is the code correct?
- Is the code secure?
- Is the code covered by tests?
- Does the code follow our engineering standards?
- In the absence of explicit standards, does the code respect established patterns and conventions?

If the answer to all of these questions is yes, the PR should be approved.
If not, the PR reviewer should request changes.
When requesting changes, please be as precise as possible.
Concrete code suggestions or even stacked PRs are encouraged.

### Don't fear the red button
It can sometimes feel harsh to press the red button to request changes.
Therefore, it's common in many projects for people to add their comments
and withhold their approval instead of explicitly requesting changes.

In our project, this is discouraged. This is because it can often be
frustrating as a PR author to end up in this limbo state where
you don't get approval to merge and it's not clear exactly what
changes are needed to get there.

Instead, we prefer PR reviewers to explicitly request changes
on anything that prevents the PR from being merged.
This can be small things, as long as they are objective.
A good PR reviewer will make it very easy to understand
which requested changes are blocking and needs to be addressed
for an approval and which requested changes/comments are optional.

### Don't fear the green button
If there are no explicit objective blocking changes requested
for a PR, it should be approved.
Even if you as a reviewer don't like the code.
It is not acceptable to withold an approval for a PR,
because you prefer another way of doing something if
the way implemented in the PR is correct.

### When it's okay to neither accept, nor reject
A PR review is binary, in the sense that it should either lead to
an approval or requested changes.

However, there are instances when it's okay to do neither.

1. **Partial reviews**. If you have started reviewing a PR but not completed it,
   it's perfectly fine to drop any comments you've found so far without approving.
   What's important here is to highlight that you've only done a partial review,
   and set the expectations for when you aim to complete it.
2. **Chiming in**. PRs often turn into a venue for interesting conversations.
   Naturally it's okay to ask your peers for opinions or chime in on existing PRs.
   It is also okay to skim a PR and write some notes/observations on it.
   Just make sure it's clear to everyone involved that you're not taking any responsibility as a reviewer.

### When there's a disagreement
At times it happens that we have different views on some matter regarding the code,
and disagree about how things should be done.
This may be a disagreement about how to apply/interpret our engineering standards,
or how to approach some fundamental tradeoff.
It is tempting as a reviewer to withold your approval to get it your way,
and as a PR author it's tempting to refuse to listen to suggestions.

Naturally, for any conflict it's good to explore and understand what's
behind each conflicting view. Can it be reduced to some objective principle?
Is there a way forward that circumvents this issue?
Can we get some perspective from another person?

While a full conflict-resolution guide is out of scope for this guide,
there are some general principles we can adopt to ensure we have
a good climate to sort these out without blocking critical work:

1. **The majority isn't necessarily right.**
   It's okay and sometimes good to ask another person for perspective,
   perhaps they can help uncover the underlying conflict or see the problem
   from a different angle to help build alignment.
   However, don't try to make it a competition to outnumber anyone with conflicting views.
   We don't recognize majority voting as an acceptable method
   to resolve disagreements in PR reviews.
2. **Seniority doesn't give you any extra weight.**
   We can often weight opinions differently based on who they come from.
   It is common to end up in cultures where a certain senior person
   always gets the last word, and no one dares disagree with them.
   This is quite backwards. While it's natural that a senior
   contributor with plenty of experience may often be the one to find
   the best path forward in complex scenarios, they still need to
   explain and motivate their proposals on the same terms as any other
   developer would.
3. **The PR author has spent the most time with this code and has the final say.**
   The person with most insight in the current code is the PR author.
   As already stated, we should never block a PR unless there are objective
   reasons to do so. If there are any doubt, we should err on the liberal
   side and accept the PR. A single PR is not the end of the world, and
   we'll be able to fix any sub-optimal design decisions in the future.
4. **Security concerns trumps everything else.**
   The exception to the above is if there's any concern about the security of the system.
   Letting through a critical vulnerability may very well be the end of this system.
   We should never merge a PR if there's any doubt about the security of it.
   These doubts needs to be cleared out first, and even a suspicion of a
   security issue is legitimate grounds to block a PR.

# Engineering Standards
To ensure consistent high quality code, every PR must conform to the following principles.

- [Don't panic](#dont-panic)
- [Maintain local reasonability](#maintain-local-reasonability)
- [Use safe arithmetic methods](#use-safe-arithmetic-methods)
- [Don't be an `as`](#dont-be-an-as)
- [Separate business logic from I/O](#separate-business-logic-from-io)
- [Add tests](#add-tests)
- [Measure performance](#measure-performance)

Beyond our engineering standards,
The Rust library team maintains a set of [API guidelines](https://rust-lang.github.io/api-guidelines/about.html).
We should also try to follow these to the greatest extent possible where applicable.

## Don't panic
While there are a few exections to this rule, most of our code should be panic-free.
Therefore we should avoid calling `.expect()`, `.unwrap()` in production code, as
well as any other methods that may implicitly or explicitly panic.

The two exceptions to this rule are:

1. The top level main function may panic if it is not able to parse arguments,
   configuration or anything else needed to start the node in the first place.
2. Code paths that are guaranteed to be dead by runtime invariants.

In the first case there's no harm in panicking since the node hasn't started.

The second case is more subtle and debatable.
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
In these scenarios, the correctness of one expressions depends on
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
invariant being broken because it does't make any assumptions
about any surrounding code.

Therefore we recognize the variant as the better alternative.

## Use safe arithmetic methods
It's convenient to use the arithmetic operators (`+`, `-`, `*`)
for mathematical expressions. However, these may panic or overflow/underflow
depending on the compiler. This can lead to unintended behavior and
it's best to completely avoid them for primitive types in favor of
explicit methods (`checked_add`, `wrapping_add` etc.).

Note that for custom types these operators may be still fine,
if they are implemented so that they don't overflow.

For example, typical implementations of cryptographic scalars
in some field use modular arithmetic and therefore have
well defined behavior when used with these operators.

```rust
// Don't
let z = x + y

// Do
if let Some(z) = x.checked_add(y) {
   // Do stuff with z
} else {
   // Handle error or explain why this will never happen and panic
}
```

## Don't be an `as`
Many `as` conversions can have unintended behavior.
Therefore we should not use them in production code.
Instead, use explicit conversion methods.

```rust
let x: u64;

// Don't
let y = x as u128;

// Do
let y = u128::from(x);

// Don't
let z = y as u64;

// Do
if let Ok(z) = u64::try_from(y) {
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
and asserts that it matches the expecation.

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
- **Crate integration tests**: Test the public interface of a crate to ensure different parts of it works nicely together.
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

# Concluding remarks
I hope this guide helps maintain a good climate for contributors in this repo,
and helps us guide ourselves towards more performant, robust and maintainable code
so that we can continue deliver all exciting features we want to support.

This guide only scratches the surface of all our collective thoughts
and opinions on what constitutes good practices. We'll maintain this as a living
document and update it as we uncover more insights on which conventions and standards
we want to hold ourselves to.

May the force be with you!
