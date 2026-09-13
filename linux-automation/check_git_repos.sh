#!/bin/bash
# ==============================================================================
# Script Name : check_git_repos.sh
# Description : Scans a target directory (default: ~/appsec-lab) to identify
#               Git repositories, including submodules and worktrees.
# Author      : Rishabh Trivedi
# ==============================================================================

set -euo pipefail

# Default lab directory or accept command-line argument
TARGET_DIR="${1:-$HOME/appsec-lab}"
RECURSIVE=false

# Check for flags
for arg in "$@"; do
    case $arg in
        -r|--recursive)
            RECURSIVE=true
            ;;
        -h|--help)
            echo "Usage: $0 [TARGET_DIR] [-r|--recursive]"
            echo ""
            echo "Options:"
            echo "  TARGET_DIR     Path to directory (default: ~/appsec-lab)"
            echo "  -r, --recursive Perform recursive discovery of Git repos"
            echo "  -h, --help      Show this help message"
            exit 0
            ;;
    esac
done

# Ensure target directory exists
if [ ! -d "$TARGET_DIR" ]; then
    echo "[-] Error: Target directory '$TARGET_DIR' does not exist." >&2
    exit 1
fi

echo "=================================================="
echo "  AppSec Lab Git Repository Audit"
echo "  Target Directory: $TARGET_DIR"
echo "=================================================="

if [ "$RECURSIVE" = true ]; then
    echo "[*] Mode: Recursive Search"
    echo ""
    
    # Find all .git directories/files up to 5 levels deep
    while IFS= read -r -d '' git_path; do
        repo_dir="$(dirname "$git_path")"
        if git -C "$repo_dir" rev-parse --git-dir >/dev/null 2>&1; then
            status="[+] Git Repository"
            
            # Check for uncommitted changes
            if [ -n "$(git -C "$repo_dir" status --porcelain 2>/dev/null)" ]; then
                dirty_status=" [! DIRTY: Uncommitted Changes]"
            else
                dirty_status=" [CLEAN]"
            fi
            echo "$status: $repo_dir$dirty_status"
        fi
    done < <(find "$TARGET_DIR" -maxdepth 5 \( -name ".git" -o -type f -name ".git" \) -print0 2>/dev/null)

else
    echo "[*] Mode: Top-level Subdirectories"
    echo ""

    cd "$TARGET_DIR" || exit 1
    shopt -s nullglob
    dirs=(*/)

    if [ ${#dirs[@]} -eq 0 ]; then
        echo "[!] No subdirectories found in $TARGET_DIR"
        exit 0
    fi

    for dir in "${dirs[@]}"; do
        repo="${dir%/}"
        
        # Robust git check handling standard repos, worktrees, and submodules
        if git -C "$dir" rev-parse --git-dir >/dev/null 2>&1; then
            # Check for uncommitted changes
            if [ -n "$(git -C "$dir" status --porcelain 2>/dev/null)" ]; then
                dirty_status=" (Uncommitted Changes)"
            else
                dirty_status=" (Clean)"
            fi
            echo "[+] $repo -> Git Repository: YES$dirty_status"
        else
            echo "[-] $repo -> Git Repository: NO"
        fi
    done
fi

echo "=================================================="
echo "Scan Complete."
