#!/usr/bin/env bash

if [[ (-z $(git rev-parse HEAD 2>/dev/null)) ]]; then
	echo "$PWD is not a Git repository"
	[[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

current=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
git fetch --all &>/dev/null &>/dev/null
if [[ "$?" -ne "0" ]]; then
	echo "git fetch --all failed"
	[[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

for branch in $(git branch -a | cut -b 2- | grep "remotes/origin" | cut -f 3 -d '/' | awk '{print $1}');
do
	# Skip anything that looks like Master
	if [[ ((-z "$branch") || ("$branch" = "master") || ("$branch" = "HEAD")) ]]; then
		continue;
	fi

	# Skip anything that looks like a release, like CRYPTOPP_5_6_3
	if [[ (! -z $(echo -n "$branch" | grep "CRYPTOPP_")) ]]; then
		continue;
	fi

	echo "**************** $branch *******************"

	git checkout -f "$branch" &>/dev/null
	if [[ "$?" -ne "0" ]]; then
		echo "git checkout $branch failed"
		continue;
	fi

	git rebase "origin/$branch"
	if [[ "$?" -ne "0" ]]; then
		echo "git rebase $branch failed"
		continue;
	fi

	git merge master -S -m "Merge branch 'master' into dev-branch '$branch'" &>/dev/null
	if [[ "$?" -ne "0" ]]; then
		echo "git merge $branch failed"
		continue;
	fi

	git push &>/dev/null
	if [[ "$?" -ne "0" ]]; then
		echo "git push $branch failed"
		continue;
	fi

	echo "Completed merging for '$branch'"

done

if [[ ! -z  "$current" ]]; then
	git checkout "$current" &>/dev/null
fi

echo "Back on branch $current"

[[ "$0" = "$BASH_SOURCE" ]] && exit 0 || return 0
