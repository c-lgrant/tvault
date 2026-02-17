import os

import httpx
from google.adk.agents import Agent


def get_token(service: str) -> str:
    resp = httpx.get(
        "https://api.tokenvault.uk/api/agents/credentials",
        params={"service": service},
        headers={"Authorization": f"Bearer {os.environ['TOKENVAULT_AGENT_KEY']}"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["accessToken"]

def list_github_repos() -> dict:
    """List all GitHub repositories the authenticated user has access to."""
    repos = []
    page = 1
    while True:
        resp = httpx.get(
            "https://api.github.com/user/repos",
            params={"per_page": 100, "page": page, "sort": "updated"},
            headers={
                "Authorization": f"Bearer {get_token('github_pat')}",
                "Accept": "application/vnd.github+json",
            },
            timeout=15,
        )
        if resp.status_code != 200:
            return {"error": f"GitHub API returned {resp.status_code}: {resp.text}"}
        batch = resp.json()
        if not batch:
            break
        repos.extend(
            {"name": r["full_name"], "private": r["private"], "url": r["html_url"]}
            for r in batch
        )
        page += 1
    return {"total": len(repos), "repos": repos}


root_agent = Agent(
    name="github_repo_lister",
    model="gemini-2.5-flash",
    description="Github List Agent",
    instruction=(
        "You help users see their GitHub repositories.\n\n"
        "Steps:\n"
        "If any step fails, explain the error to the user.\n"
        "Call list_github_repos tool to list all repositories.\n\n"
        "Do not ever ask the user for any access tokens, use the tooling provided."
    ),
    tools=[list_github_repos],
)
