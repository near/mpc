#!/usr/bin/env python3
"""
Format GitHub PR comments, reviews, and review threads for Claude Code Review.

This script takes GitHub GraphQL API response JSON and formats it into
a readable markdown structure for consumption by Claude AI code reviewer.
"""

import json
import sys
from typing import Dict, List, Optional, Any


def get_author(node: Dict[str, Any]) -> str:
    """
    Safely get author login, handling deleted accounts.

    Args:
        node: GitHub API node containing author information

    Returns:
        Author login string or 'ghost' for deleted accounts
    """
    author = node.get('author')
    return author.get('login', 'ghost') if author else 'ghost'


def truncate_diff_hunk(diff_hunk: str, max_length: int = 500) -> str:
    """
    Truncate diff hunk at line boundaries to avoid cutting mid-line.

    Args:
        diff_hunk: The diff hunk text to truncate
        max_length: Maximum character length before truncation

    Returns:
        Truncated diff hunk with indicator if truncation occurred
    """
    if len(diff_hunk) <= max_length:
        return diff_hunk

    lines = diff_hunk.split('\n')
    truncated_lines = []
    char_count = 0

    for line in lines:
        line_length = len(line) + 1  # +1 for newline
        if char_count + line_length > max_length and truncated_lines:
            break
        truncated_lines.append(line)
        char_count += line_length

    return '\n'.join(truncated_lines) + "\n... (truncated)"


def format_general_comments(pr: Dict[str, Any], output: List[str]) -> None:
    """Format general PR comments section."""
    comments_data = pr.get('comments', {})
    issue_comments = comments_data.get('nodes', [])
    total_comments = comments_data.get('totalCount', 0)

    output.append("## General PR Comments")
    output.append("")

    if issue_comments:
        for comment in issue_comments:
            author = get_author(comment)
            created = comment.get('createdAt', '')[:10]
            body = comment.get('body', '').strip()

            output.append(f"### Comment by @{author} on {created}")
            output.append(body)
            output.append("")
            output.append("-" * 40)
            output.append("")

        if total_comments > 100:
            output.append(f"*Note: This PR has {total_comments} comments. Showing first 100.*")
            output.append("")
    else:
        output.append("No general comments found.")
        output.append("")


def format_review_summaries(pr: Dict[str, Any], output: List[str]) -> None:
    """Format review summaries section."""
    reviews_data = pr.get('reviews', {})
    reviews = reviews_data.get('nodes', [])

    if not reviews:
        return

    output.append("## Review Summaries")
    output.append("")

    for review in reviews:
        if review.get('body'):
            author = get_author(review)
            state = review.get('state', 'COMMENTED')
            created = review.get('createdAt', '')[:10]
            body = review.get('body', '').strip()

            output.append(f"### {state} Review by @{author} on {created}")
            output.append(body)
            output.append("")
            output.append("-" * 40)
            output.append("")


def format_review_thread(thread: Dict[str, Any], output: List[str], show_resolved: bool = False) -> None:
    """
    Format a single review thread with its comments.

    Args:
        thread: Review thread data from GitHub API
        output: Output list to append formatted lines to
        show_resolved: Whether this is a resolved thread (affects formatting)
    """
    path = thread.get('path', 'unknown')
    line = thread.get('line')
    line_str = f"L{line}" if line else "file-level"
    is_outdated = thread.get('isOutdated', False)
    is_resolved = thread.get('isResolved', False)

    # Build header with status indicators
    outdated_marker = " [OUTDATED]" if is_outdated else ""
    status = "RESOLVED" if is_resolved else "UNRESOLVED"

    output.append(f"### Thread: {path}:{line_str}{outdated_marker}")
    output.append(f"**Status:** {status}")
    output.append("")

    # Format comments in thread
    comments = thread.get('comments', {}).get('nodes', [])
    for i, comment in enumerate(comments):
        author = get_author(comment)
        body = comment.get('body', '').strip()
        created = comment.get('createdAt', '')[:10]

        # Show diff hunk for first comment (provides code context)
        if i == 0 and comment.get('diffHunk'):
            diff_hunk = truncate_diff_hunk(comment['diffHunk'])
            output.append("**Code context:**")
            output.append("```")
            output.append(diff_hunk)
            output.append("```")
            output.append("")

        prefix = "Original comment" if i == 0 else f"Reply {i}"
        output.append(f"**{prefix} by @{author} on {created}:**")
        output.append(body)
        output.append("")

    output.append("-" * 40)
    output.append("")


def format_review_threads(pr: Dict[str, Any], output: List[str]) -> None:
    """Format all review threads (unresolved and resolved)."""
    threads_data = pr.get('reviewThreads', {})
    review_threads = threads_data.get('nodes', [])
    total_threads = threads_data.get('totalCount', 0)

    # Separate unresolved and resolved threads
    unresolved = [t for t in review_threads if not t.get('isResolved', False)]
    resolved = [t for t in review_threads if t.get('isResolved', False)]

    # Unresolved threads (higher priority)
    output.append("## Unresolved Code Review Discussions")
    output.append("")

    if unresolved:
        for thread in unresolved:
            format_review_thread(thread, output, show_resolved=False)
    else:
        output.append("No unresolved discussions.")
        output.append("")

    # Resolved threads (for context)
    output.append("## Resolved Code Review Discussions")
    output.append("")

    if resolved:
        for thread in resolved:
            format_review_thread(thread, output, show_resolved=True)
    else:
        output.append("No resolved discussions.")
        output.append("")

    # Pagination warning
    if total_threads > 100:
        output.append(f"*Note: This PR has {total_threads} review threads. Showing first 100.*")
        output.append("")


def format_pr_comments(comments_json: str) -> str:
    """
    Main formatting function that orchestrates the output generation.

    Args:
        comments_json: JSON string from GitHub GraphQL API

    Returns:
        Formatted markdown string ready for Claude consumption

    Raises:
        json.JSONDecodeError: If JSON parsing fails
        KeyError: If expected data structure is missing
    """
    try:
        data = json.loads(comments_json)

        # Check for GraphQL errors
        if 'errors' in data:
            error_msg = data['errors'][0].get('message', 'Unknown error')
            return f"⚠️ GitHub API error: {error_msg}"

        # Extract PR data
        pr = data.get('data', {}).get('repository', {}).get('pullRequest')
        if not pr:
            return "⚠️ No PR data found in API response."

    except (json.JSONDecodeError, KeyError) as e:
        return f"⚠️ Unable to parse comment data: {e}"

    # Build formatted output
    output = []
    output.append("=" * 80)
    output.append("EXISTING PR COMMENTS AND DISCUSSIONS")
    output.append("=" * 80)
    output.append("")

    format_general_comments(pr, output)
    format_review_summaries(pr, output)
    format_review_threads(pr, output)

    output.append("=" * 80)
    output.append("END OF EXISTING COMMENTS")
    output.append("=" * 80)

    return "\n".join(output)


def main() -> int:
    """
    Main entry point for the script.

    Reads COMMENTS_JSON from environment variable and writes formatted
    output to stdout.

    Returns:
        Exit code: 0 for success, 1 for error
    """
    import os

    comments_json = os.environ.get('COMMENTS_JSON')
    if not comments_json:
        print("⚠️ COMMENTS_JSON environment variable not set.", file=sys.stderr)
        return 1

    try:
        formatted_output = format_pr_comments(comments_json)
        print(formatted_output)
        return 0
    except Exception as e:
        print(f"⚠️ Unexpected error formatting comments: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())