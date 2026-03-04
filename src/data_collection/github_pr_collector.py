"""
GitHub PR Collector for Real Baseline Data

This module collects real Pull Request data from GitHub repositories
using the GitHub REST API. It filters for security-relevant PRs and
extracts the necessary information for baseline sample generation.

Author: Cecilia Nothstein
Bachelor Thesis: Robustness of LLM-based Code Reviews for Hardcoded Secret Detection
"""

import json
import logging
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import requests
from datetime import datetime


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class GitHubPR:
    """Data class for a GitHub Pull Request."""
    pr_number: int
    title: str
    body: str
    diff_url: str
    html_url: str
    repository: str
    author: str
    created_at: str
    state: str


class GitHubPRCollector:
    """
    Collector for GitHub Pull Requests.

    Uses GitHub REST API to search for and collect PRs that are relevant
    for security testing (containing keywords like auth, token, api, etc.)
    """

    # GitHub API base URL
    API_BASE = "https://api.github.com"

    # Keywords for PRs where secrets would realistically appear
    # Focus on: config changes, integrations, database setup, auth systems
    SECURITY_KEYWORDS = [
        # Configuration & Setup
        'config', 'configuration', 'setup', 'settings', 'initialize', 'init',
        # Database & Storage
        'database', 'db', 'postgres', 'mysql', 'mongodb', 'redis', 'elasticsearch',
        's3', 'storage', 'connection', 'migrate',
        # Authentication & Security
        'auth', 'authentication', 'oauth', 'jwt', 'token', 'credential',
        'password', 'secret', 'api key', 'apikey',
        # Integrations & Services
        'integration', 'webhook', 'stripe', 'twilio', 'sendgrid', 'slack',
        'aws', 'firebase', 'email', 'smtp', 'ssh', 'ssl', 'certificate',
        # Environment
        'environment', 'env', '.env', 'dotenv'
    ]

    # Exclude keywords that indicate non-relevant PRs (bug fixes, UI, docs)
    EXCLUDE_KEYWORDS = [
        'typo', 'fix typo', 'readme', 'documentation', 'docs', 'comment',
        'test fix', 'lint', 'style', 'formatting', 'css', 'html', 'template',
        'translation', 'i18n', 'l10n', 'deprecat'
    ]

    # Repositories with config/integration-heavy codebases
    TARGET_REPOS = [
        # Web Frameworks (often have config examples)
        'django/django',
        'pallets/flask',
        'encode/django-rest-framework',
        'tiangolo/fastapi',
        # Cloud & Infrastructure
        'boto/boto3',
        'hashicorp/terraform',
        'ansible/ansible',
        # API Clients (contain credential handling)
        'stripe/stripe-python',
        'twilio/twilio-python',
        'sendgrid/sendgrid-python',
        'googleapis/google-api-python-client',
        # Database Drivers
        'sqlalchemy/sqlalchemy',
        'mongodb/mongo-python-driver',
        # Auth Libraries
        'oauthlib/oauthlib',
        'jpadilla/pyjwt',
    ]

    def __init__(self, github_token: Optional[str] = None):
        """
        Initialize the collector.

        Args:
            github_token: Optional GitHub personal access token for higher rate limits
        """
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')
        self.session = requests.Session()

        if self.github_token:
            self.session.headers.update({
                'Authorization': f'token {self.github_token}',
                'Accept': 'application/vnd.github.v3+json'
            })
            logger.info("Using authenticated GitHub API (higher rate limits)")
        else:
            self.session.headers.update({
                'Accept': 'application/vnd.github.v3+json'
            })
            logger.warning("Using unauthenticated GitHub API (lower rate limits). "
                          "Set GITHUB_TOKEN environment variable for better limits.")

    def _check_rate_limit(self) -> Tuple[int, int]:
        """
        Check current rate limit status.

        Returns:
            Tuple of (remaining, limit)
        """
        try:
            response = self.session.get(f"{self.API_BASE}/rate_limit")
            response.raise_for_status()
            data = response.json()
            core = data['resources']['core']
            return core['remaining'], core['limit']
        except Exception as e:
            logger.warning(f"Could not check rate limit: {e}")
            return -1, -1

    def _wait_for_rate_limit(self):
        """Wait if rate limit is low."""
        remaining, limit = self._check_rate_limit()

        if remaining != -1 and remaining < 10:
            logger.warning(f"Rate limit low ({remaining}/{limit}), waiting 60 seconds...")
            time.sleep(60)

    def search_prs_in_repo(self, repo: str, state: str = 'closed',
                          max_results: int = 30) -> List[Dict]:
        """
        Search for PRs in a specific repository.

        Args:
            repo: Repository in format 'owner/name'
            state: PR state ('open', 'closed', 'all')
            max_results: Maximum number of PRs to retrieve

        Returns:
            List of PR dictionaries
        """
        logger.info(f"Searching PRs in {repo}...")

        self._wait_for_rate_limit()

        url = f"{self.API_BASE}/repos/{repo}/pulls"
        params = {
            'state': state,
            'per_page': min(max_results, 100),
            'sort': 'updated',
            'direction': 'desc'
        }

        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            prs = response.json()

            logger.info(f"Found {len(prs)} PRs in {repo}")
            return prs

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch PRs from {repo}: {e}")
            return []

    def filter_security_relevant(self, prs: List[Dict]) -> List[Dict]:
        """
        Filter PRs for security-relevant keywords.

        Includes PRs about: config, database, auth, integrations
        Excludes PRs about: bug fixes, typos, docs, UI changes

        Args:
            prs: List of PR dictionaries from GitHub API

        Returns:
            Filtered list of PRs
        """
        filtered = []

        for pr in prs:
            title = (pr.get('title') or '').lower()
            body = (pr.get('body') or '').lower()
            text = f"{title} {body}"

            # Check for exclusion keywords first
            if any(keyword in text for keyword in self.EXCLUDE_KEYWORDS):
                logger.debug(f"Excluded PR: {title[:50]} (matched exclude keyword)")
                continue

            # Then check for inclusion keywords
            if any(keyword in text for keyword in self.SECURITY_KEYWORDS):
                filtered.append(pr)
                logger.debug(f"Included PR: {title[:50]}")

        logger.info(f"Filtered {len(filtered)}/{len(prs)} PRs with security keywords")
        return filtered

    def get_pr_diff(self, diff_url: str) -> Optional[str]:
        """
        Fetch the diff/patch for a PR.

        Args:
            diff_url: URL to the PR diff

        Returns:
            Diff text or None if failed
        """
        self._wait_for_rate_limit()

        try:
            # GitHub provides diff via .diff or .patch URL
            response = self.session.get(diff_url)
            response.raise_for_status()
            return response.text

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch diff from {diff_url}: {e}")
            return None

    def collect_prs(self, target_count: int = 100,
                   max_per_repo: int = 20) -> List[Dict]:
        """
        Collect PRs from multiple repositories.

        Args:
            target_count: Target number of PRs to collect
            max_per_repo: Maximum PRs to collect per repository

        Returns:
            List of collected PR data dictionaries
        """
        logger.info(f"Collecting up to {target_count} PRs from {len(self.TARGET_REPOS)} repositories...")

        all_prs = []
        collected_count = 0

        for repo in self.TARGET_REPOS:
            if collected_count >= target_count:
                break

            # Search PRs
            prs = self.search_prs_in_repo(repo, max_results=max_per_repo * 2)

            # Filter for security relevance
            filtered = self.filter_security_relevant(prs)

            # Limit per repo
            filtered = filtered[:max_per_repo]

            # Process each PR
            for pr in filtered:
                if collected_count >= target_count:
                    break

                # Extract basic info
                pr_data = {
                    'pr_number': pr['number'],
                    'title': pr.get('title', ''),
                    'body': pr.get('body', '') or '',  # Body can be None
                    'diff_url': pr['diff_url'],
                    'html_url': pr['html_url'],
                    'repository': repo,
                    'author': pr['user']['login'],
                    'created_at': pr['created_at'],
                    'state': pr['state']
                }

                # Fetch diff
                logger.info(f"Fetching diff for PR #{pr['number']} from {repo}...")
                diff = self.get_pr_diff(pr['diff_url'])

                if diff:
                    pr_data['diff'] = diff
                    pr_data['patch'] = diff  # Compatibility with baseline builder
                    all_prs.append(pr_data)
                    collected_count += 1
                    logger.info(f"Progress: {collected_count}/{target_count} PRs collected")

                # Rate limiting delay
                time.sleep(0.5)

        logger.info(f"Collection complete: {len(all_prs)} PRs collected")
        return all_prs

    def save_to_json(self, prs: List[Dict], output_path: str):
        """
        Save collected PRs to JSON file.

        Args:
            prs: List of PR dictionaries
            output_path: Path to save JSON file
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(prs, f, indent=2, ensure_ascii=False)

        logger.info(f"Saved {len(prs)} PRs to {output_path}")


def main():
    """CLI entry point for PR collection."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Collect real Pull Request data from GitHub"
    )
    parser.add_argument(
        '--token',
        type=str,
        help='GitHub personal access token (or set GITHUB_TOKEN env var)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='data/01_raw/github_prs.json',
        help='Output JSON file path'
    )
    parser.add_argument(
        '--count',
        type=int,
        default=100,
        help='Target number of PRs to collect (default: 100)'
    )
    parser.add_argument(
        '--max-per-repo',
        type=int,
        default=20,
        help='Maximum PRs per repository (default: 20)'
    )

    args = parser.parse_args()

    # Initialize collector
    collector = GitHubPRCollector(github_token=args.token)

    # Check rate limit
    remaining, limit = collector._check_rate_limit()
    if remaining != -1:
        logger.info(f"GitHub API rate limit: {remaining}/{limit} remaining")

    # Collect PRs
    try:
        prs = collector.collect_prs(
            target_count=args.count,
            max_per_repo=args.max_per_repo
        )
    except KeyboardInterrupt:
        logger.warning("Collection interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Collection failed: {e}", exc_info=True)
        return 1

    # Save results
    if prs:
        collector.save_to_json(prs, args.output)
        logger.info(f"Successfully collected {len(prs)} PRs")
    else:
        logger.error("No PRs collected")
        return 1

    return 0


if __name__ == '__main__':
    exit(main())
