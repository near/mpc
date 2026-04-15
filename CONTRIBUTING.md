# Contributing to NEAR MPC
Thanks for considering contributing to the NEAR MPC network.
Whether you're an external developer looking to make a contribution
or a member of the NEAR One MPC team working in this repo every day,
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
   We recommend using the GitHub UI to create the branch as it will automatically link it and use a canonical format for the branch name.
3. Check out the branch and get to work.

Once you've made the relevant changes to fulfill the acceptance criteria and the code lives up to our [engineering standards](./ENGINEERING_STANDARDS.md),
it's time to open a PR.

When opening the PR, make sure to link the issue in the PR description.
Add any other notes that will be helpful for reviewers in the description.
However, in many cases it is sufficient to only reference the issue in the PR description.

# Engineering Standards
All code must meet the conventions in [ENGINEERING_STANDARDS.md](./ENGINEERING_STANDARDS.md).

# PR review guidelines
This section mainly targets current maintainers of this code authorized
to approve PR requests.

## What is a code review?
A code review is the act of answering the following questions:

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
which requested changes are blocking and need to be addressed
for an approval and which requested changes/comments are optional.

### Don't fear the green button
If there are no explicit objective blocking changes requested
for a PR, it should be approved.
Even if you as a reviewer don't like the code.
It is not acceptable to withhold an approval for a PR,
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
It is tempting as a reviewer to withhold your approval to get it your way,
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
   The person with the most insight in the current code is the PR author.
   As already stated, we should never block a PR unless there are objective
   reasons to do so. If there are any doubts, we should err on the liberal
   side and accept the PR. A single PR is not the end of the world, and
   we'll be able to fix any sub-optimal design decisions in the future.
4. **Security concerns trump everything else.**
   The exception to the above is if there's any concern about the security of the system.
   Letting through a critical vulnerability may very well be the end of this system.
   We should never merge a PR if there's any doubt about the security of it.
   These doubts need to be cleared out first, and even a suspicion of a
   security issue is legitimate grounds to block a PR.

# Concluding remarks
I hope this guide helps maintain a good climate for contributors in this repo,
and helps us guide ourselves towards more performant, robust and maintainable code
so that we can continue to deliver all exciting features we want to support.

This guide only scratches the surface of all our collective thoughts
and opinions on what constitutes good practices. We'll maintain this as a living
document and update it as we uncover more insights on which conventions and standards
we want to hold ourselves to.

May the force be with you!
