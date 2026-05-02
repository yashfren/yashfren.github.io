---
title: Git & GitHub Cheatsheet
date: 2026-05-03 1:00:00 + 05:30
categories: [Cheatsheet]
tags: [git, github, cheatsheet]
description: A comprehensive Git and GitHub cheatsheet covering everything from setup to advanced features like bisect, worktrees, and interactive rebase.
---

# Git & GitHub Cheatsheet

I recently had to learn Git properly after [Dual booting linux](https://yashfren.github.io/posts/Week_16_2026/). and needing a way to sync my notes and projects across both operating systems. Before this I was mostly just using GitHub's web UI like a caveman, so I decided to actually sit down and learn how Git works under the hood.

These are my compiled notes from that process. It starts with the basics (setup, commits, branching) and goes all the way to more advanced stuff like interactive rebase, bisect, worktrees, and resolving merge conflicts. I've tried to keep explanations short and include diagrams where they help. Think of this as a reference you can come back to rather than a tutorial you read once.

## Setup

### Install Git (Linux/WSL)

```bash
sudo apt update
sudo apt install software-properties-common # enables add-apt-repository command
sudo add-apt-repository ppa:git-core/ppa
sudo apt update
sudo apt install git
git version
```

### Porcelain Commands vs Plumbing Commands

In Git version control system, commands are often grouped into porcelain and plumbing:

- Porcelain commands are the user-friendly ones you use daily (`git commit`, `git push`, etc.). They provide a clean, stable interface and hide internal complexity.
- Plumbing commands are low-level tools (`git hash-object`, `git cat-file`) that interact directly with Git's internal data structures and are mostly used for scripting or advanced tasks.

The names come from a metaphor: plumbing is the hidden infrastructure, while porcelain is the part you actually interact with.

## Configuration

We need to configure git with credentials before we start. We will setup a global config which is used mostly. Different types of config are covered later.

#### Check current config

```bash
git config get user.name  # check username
git config get user.email # check email
```

#### Set the config

```bash
git config set --global user.name "github_username_here"
git config set --global user.email "email@example.com"
git config set --global init.defaultBranch main
```

> Note: `init.defaultBranch main` sets the default branch name to `main` to match GitHub's convention (Git's own default is `master`).

### Config Hierarchy

#### Worktree > Local > Global > System

- System: applies to all users on the machine
- Global: applies to all repos for the current user (`~/.gitconfig`)
- Local: applies only to the current repo (`.git/config`)
- Worktree: applies to a specific worktree (advanced, rarely used)

Later config levels override earlier ones (local overrides global, etc.)

#### Get a value

```bash
git config get <key>
```

The `<key>` format is `<section>.<keyname>` e.g. `user.name`

#### Unset a value

```bash
git config unset <key>
```

#### List config

```bash
git config list --local   # local repo config
git config list --global  # global config
```

#### Remove a section

```bash
git config remove-section <section>
```

#### Unset all values for a key

```bash
git config unset --all <example.key>
```

#### Set a local config value

```bash
git config set --append <example.key> "<Value>"
```

## Basic Workflow

### Initialize an Empty Repo

```bash
git init
```

Creates a `.git` folder in the current directory. This folder contains all the data Git uses to track file changes.

### Check Status

```bash
git status
```

A file can be in one of a few states in git. The most important ones are:

- `untracked`: Not being tracked by Git at all
- `staged`: Marked for inclusion in the next commit
- `committed`: Saved to the repository's history

### Stage Files

```bash
git add .
# or
git add <path to file OR pattern>
```

`git add .` stages all changes in the current directory and its subdirectories — new (untracked), modified, and deleted files — preparing them for the next commit.

The `.` refers to the current directory. For more control, specify a path or pattern like `git add src/` or `git add *.js`.

### Commits

```bash
git commit -m "your message here"
```

Commits snapshot the staged files into the repository's history. Like save files in a video game — you can always go back to any save point.

### Logs

```bash
git log --no-pager -n 10
```

Shows the last 10 commits. Each commit has a SHA1 hash to uniquely identify it.

Example hash: `74094e704bbaff54fe00df960c1b6713ed520f04`

This is stored in `.git/objects/` at: `.git/objects/74/094e704bbaff54fe00df960c1b6713ed520f04`

The pattern is: `.git/objects/<first 2 chars of hash>/<remaining chars of hash>`

```bash
git log --oneline          # compact one-line view
git log --oneline --graph  # shows branch/merge graph
git log --oneline --graph --all # shows all branches
```

## Git Internals

### Viewing Commits

```bash
git cat-file -p 74094e704bbaff54fe00df960c1b6713ed520f04
```

Git stores objects as raw compressed bytes. Running `cat` on the file in `.git/objects/` outputs gibberish. Running `xxd` shows raw hex bytes — still unreadable. Use `git cat-file -p <hash>` to let Git decompress and display it in a human-readable way. This is a plumbing command.

### Trees and Blobs

```bash
git cat-file -p <commit hash> # shows the tree hash (directory snapshot)
git cat-file -p <tree hash>   # shows blob hashes (file snapshots)
git cat-file -p <blob hash>   # shows the actual file content
```

- `tree`: Git's way of storing a directory
- `blob`: Git's way of storing a file

### HEAD

```bash
cat .git/HEAD
```

HEAD is a reference (pointer) to the branch you're currently on. It tells Git which commit to base your next commit on.

## Branching

Branches let you work on different things without affecting the main codebase. Each branch is just a pointer to a commit.

#### Check current branch

```bash
git branch
```

#### Create a new branch

```bash
git branch my_new_branch   # creates branch but stays on current branch
git switch -c my_new_branch # creates branch AND switches to it
```

#### Switch branches

```bash
git switch main     # new way (preferred)
git checkout main   # old way (still works)
```

#### Rename a branch

```bash
git branch -m oldname newname
```

#### Delete a branch

```bash
git branch -d <branch-name>  # safe delete (only if fully merged)
git branch -D <branch-name>  # force delete
```

## Merge

Merging brings changes from one branch into another.

#### Merge a branch into current branch

```bash
git switch main
git merge <branch-name>  # a text editor opens for the merge commit message
```

#### View merge log

```bash
git log --oneline --decorate --graph --parents
```

#### Fast-forward merge

Happens when the branch you're merging _into_ has no new commits since the feature branch was created — Git just moves the pointer forward, no merge commit needed.

```
Before:
main:    A---B
              \
feature:       C---D

After fast-forward:
main:    A---B---C---D
```

#### Three-way merge (creates a merge commit)

Happens when both branches have diverged — Git creates a new merge commit that ties both histories together.

```
Before:
main:    A---B---C
              \
feature:       D---E

After merge:
main:    A---B---C---F   (F is the merge commit)
              \       /
feature:       D---E
```

## Rebase

Rebase moves your branch's commits onto a new base, rewriting history to keep it linear.

```
Before:
main:    A---B---C
              \
feature:       D---E

After rebase onto main:
main:    A---B---C
                  \
feature:           D'---E'   (D and E are rewritten as D' and E')
```

After a rebase, merging back into main will be a fast-forward (clean, no merge commit).

#### Rebase command

```bash
git switch feature_branch
git rebase main  # replays feature_branch commits on top of main
```

#### New branch from any commit

```bash
git switch -c <new-branch-name> <commit-hash>
```

Creates a new branch starting from that specific commit and switches to it immediately.

## Reset

Used to undo commits. Both commands move HEAD back to the specified commit hash.

#### Soft reset — undoes the commit but keeps file changes staged

```bash
git reset --soft <commit-hash>
```

#### Hard reset — undoes the commit AND discards all file changes

```bash
git reset --hard <commit-hash>
```

> Warning: `--hard` permanently discards uncommitted changes. Use with caution.

## .gitignore

A `.gitignore` file tells Git which files and directories to ignore (not track).

#### Create a .gitignore

```bash
touch .gitignore
nano .gitignore
```

#### Pattern rules

```
secret.txt          # ignore a specific file
*.log               # ignore all .log files
build/              # ignore an entire directory
!important.log      # exception — do NOT ignore this file (overrides *.log)
/config.txt         # ignore only at the root level, not in subdirectories
src/config.txt      # ignore only this specific path
```

Key rules:

- Patterns without a leading `/` match anywhere in the project
- Patterns with a leading `/` are anchored to the root directory
- `!` negates a pattern (un-ignores something previously ignored)
- A `.gitignore` file in a subdirectory applies rules relative to that subdirectory

#### Remove a file already tracked by Git

Adding a file to `.gitignore` won't stop tracking it if Git already tracks it. To stop tracking it:

```bash
git rm --cached <filename>
```

This removes it from Git's tracking without deleting the file from your disk.

## Remote

A remote is a pointer to another copy of the repository, usually hosted on GitHub.

#### Add a remote

```bash
git remote add <name> <url>
```

`<name>` is conventionally `origin`. `<url>` is the repo URL (HTTPS or SSH).

#### View remotes

```bash
git remote -v
```

#### Change remote URL

```bash
git remote set-url origin <new-url>
```

#### Remove a remote

```bash
git remote remove <name>
```

## Fetch

Downloads objects and refs from a remote but does NOT merge them into your local branch.

```bash
git fetch           # fetches from the default remote (origin)
git fetch origin    # explicitly fetches from origin
```

After fetching, you can inspect what changed before merging:

```bash
git log origin/main --oneline  # see what's on the remote
```

## Pull

`git pull` is a shortcut for `git fetch` + `git merge`. It fetches from the remote and immediately merges into your current branch.

```bash
git pull origin main
```

#### Pull behavior options

```bash
git config set pull.rebase false  # merge on pull (default, creates merge commit if diverged)
git config set pull.rebase true   # rebase on pull (keeps history linear)
```

## Push

Uploads your local commits to the remote repository.

```bash
git push origin main              # push local main to remote main
git push origin <branch-name>     # push a specific branch (creates it on remote if it doesn't exist)
git push -u origin main           # push and set upstream tracking (-u means --set-upstream)
```

The `-u` flag sets up tracking so future `git push` and `git pull` commands don't need to specify the remote and branch.

## Pull Requests (GitHub)

A Pull Request (PR) is a GitHub feature (not a Git feature) that lets you propose merging one branch into another. It allows code review before the merge happens.

#### Typical workflow

```bash
git switch -c feature-branch  # create and switch to a new branch
# make changes, commit them
git push origin feature-branch # push branch to GitHub
# then open a PR on GitHub to merge feature-branch into main
```

After the PR is merged on GitHub:

```bash
git switch main
git pull origin main          # bring merged changes down locally
git branch -d feature-branch  # delete local branch
```

## GitHub CLI Setup

Configure git to use the GitHub CLI as a credential helper:

```bash
gh auth setup-git
```

## Fork

Forking is a GitHub feature, not a Git feature. It creates a personal copy of someone else's repository under your GitHub account, letting you make changes without affecting the original.

## Reflog and Commitish

```bash
git reflog
```

Reflog keeps a log of everywhere HEAD has been — even across branch deletions, rebases, and resets. It's your safety net for recovering "lost" commits.

A commitish is any value that resolves to a commit hash. Examples:

- `HEAD` — the current commit
- `HEAD@{1}` — where HEAD was one move ago (from reflog)
- `abc1234` — a short hash
- `main~2` — two commits before the tip of main

#### Recovering a deleted branch using reflog

```bash
git reflog                  # find the hash of the lost commit
git merge HEAD@{1}          # or: git switch -c recovered-branch <hash>
```

## Merge Conflicts

Conflicts occur when the same lines are changed differently across two branches being merged.

```
name,role
<<<<<<< HEAD
alice,engineer
=======
bob,designer
>>>>>>> main
```

- `<<<<<<< HEAD` — your current branch's version
- `=======` — divider between the two versions
- `>>>>>>> main` — the incoming branch's version

You must manually edit the file to keep what you want, then stage and commit it.

### Resolving Merge Conflicts with `git checkout`

```bash
git checkout --ours path/to/file    # keep current branch's version
git checkout --theirs path/to/file  # keep incoming branch's version
```

- `--ours` keeps the version from the branch you're currently on (before the merge)
- `--theirs` uses the version from the branch being merged in

After resolving:

```bash
git add path/to/file
git commit
```

### Resolving Rebase Conflicts with `git checkout`

During a rebase, the meaning of `--ours` and `--theirs` is flipped compared to a merge:

- `--ours` refers to the branch you're rebasing onto (e.g. `main`)
- `--theirs` refers to the branch being replayed (your feature branch)

```bash
git checkout --ours path/to/file    # keep main's version during rebase
git add path/to/file
git rebase --continue
```

> Note: Unlike merge conflicts, you do not run `git commit` after resolving a rebase conflict — use `git rebase --continue` instead.

## RERERE — Reuse Recorded Resolution

RERERE automatically remembers how you resolved a conflict and reapplies that resolution the next time it sees the same conflict. Useful when repeatedly rebasing a long-running branch onto main.

#### Enable RERERE

```bash
git config set --local rerere.enabled true
```

Once enabled, after you manually resolve a conflict once, future identical conflicts in rebases or merges are resolved automatically — just run:

```bash
git rebase --continue
```

## Squash

Squashing collapses multiple commits into one, keeping history clean.

```bash
git rebase -i HEAD~n
```

`n` is the number of commits to squash. An interactive editor opens with each commit listed as `pick`.

- Keep the first (oldest) commit as `pick`
- Change the rest to `squash` (or `s`)
- Save and close — a second editor opens to write the combined commit message
- Keep only the message you want, delete everything else, then save and close

> Squashing is a destructive operation — it rewrites history. Only do it on branches that haven't been pushed, or use a temporary branch first.

## Stash

Stash temporarily shelves changes so you can switch context without committing incomplete work.

```bash
git stash           # stash current uncommitted changes
git stash pop       # reapply the most recent stash and remove it
git stash list      # see all stashes
git stash apply     # reapply stash but keep it in the list
git stash drop      # delete the most recent stash
```

> Stash is great for quick context switches. For longer-lived work, worktrees (see below) are often a better choice.

## Revert

Revert creates a new commit that undoes the changes from a previous commit, preserving history. Unlike `reset`, it's safe to use on shared/public branches.

```bash
git revert <commit-hash>
```

Your editor opens for the commit message. Write a descriptive message, save, and close. The bad commit stays in history, but its effects are cancelled out.

> Use `revert` (not `reset`) when you want to undo something while keeping a record that you did so.

## Cherry Pick

Cherry pick applies a specific commit from one branch onto your current branch — without merging the whole branch.

```bash
git cherry-pick <commit-hash>
```

Useful for pulling in a single bug fix from another branch without taking all its other changes.

## Bisect

Bisect performs a binary search through commit history to find which commit introduced a bug.

#### Manual bisect

```bash
git bisect start
git bisect bad HEAD              # mark current commit as bad
git bisect good <commit-hash>    # mark a known good commit

# Git checks out a middle commit — inspect it, then:
git bisect good   # if the bug is absent
git bisect bad    # if the bug is present

# Repeat until Git identifies the first bad commit
git show <bad-commit-hash>       # verify the culprit
git bisect reset                 # exit bisect mode
```

#### Automated bisect with a script

You can pass a script to `git bisect run` and it will automate the search using the script's exit code:

- Exit `0` → Git marks the commit as good
- Non-zero exit → Git marks the commit as bad

```bash
git bisect run ./scripts/bisect.sh
```

Example `bisect.sh` — checks if a bug-introducing string exists in a file:

```bash
if grep -q "bug_string" "path/to/file"; then
    exit 1   # bad
else
    exit 0   # good
fi
```

Git runs the script at each step and finds the first bad commit automatically.

## Worktree

Worktrees let you check out multiple branches simultaneously in separate directories — all sharing the same `.git` folder. Great for working on two things at once without stashing or switching.

#### List worktrees

```bash
git worktree list
```

#### Create a linked worktree

```bash
git worktree add <path> [<branch>]
```

If `<branch>` is omitted, Git uses the last part of the path as the branch name.

```bash
git worktree add ../my-feature     # creates branch 'my-feature' and directory ../my-feature
```

The linked worktree's `.git` is a file (not a directory) containing a path back to the main `.git`:

```bash
cat ../my-feature/.git
# gitdir: /home/user/my-project/.git/worktrees/my-feature
```

The main worktree tracks linked worktrees in `.git/worktrees/`.

#### Branch indicators in `git branch`

```
* main        # currently checked out in THIS worktree
+ my-feature  # currently checked out in a LINKED worktree
```

You cannot check out a branch in one worktree if it's already checked out in another.

#### Remove a linked worktree

```bash
git worktree remove <worktree-name>   # removes the directory and the reference
git worktree prune                    # cleans up references to manually-deleted directories
```

> Removing a worktree does not delete the branch — it only removes the working directory and its reference in `.git/worktrees/`.

## Tags

Tags are permanent labels attached to a specific commit, commonly used for version releases.

#### Create a tag

```bash
git tag <tag-name>                          # lightweight tag (just a pointer)
git tag -a <tag-name> -m "your message"     # annotated tag (with metadata)
```

#### List tags

```bash
git tag
```

#### View a tag in the log

```bash
git log --oneline
# cef56e1 (HEAD -> main, tag: v1.0.0) initial release
```

#### Push tags to remote

```bash
git push origin <tag-name>   # push a specific tag
git push origin --tags       # push all tags
```

#### Delete a tag

```bash
git tag -d <tag-name>              # delete locally
git push origin --delete <tag-name>  # delete from remote
```

---

## Conclusion

That covers pretty much everything I've learnt about Git so far. Obviously this doesn't cover every single feature. Git is massive but this should be more than enough for day-to-day use and even some advanced workflows. The stuff I found most useful to actually understand (rather than just memorize commands) was how Git stores objects internally (trees, blobs, commits) and the difference between merge and rebase.

I'll keep updating this post if I learn anything new worth adding. If you spot any mistakes or have suggestions, feel free to DM me on Twitter.
