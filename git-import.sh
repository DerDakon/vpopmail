#!/bin/bash

if ! git filter-repo --version >/dev/null; then
	echo "git filter-repo is missing, get it from https://github.com/newren/git-filter-repo/"
	exit 1
fi

COMMIT_PREFIX=origin/

# usage get_commit <svn revision> [branch]
function get_commit
{
	git log --grep " https://svn.code.sf.net/p/vpopmail/code/.*@${1:?} " --format=%H ${2}
}

set -ex

git svn clone -A vpopmail-authors -s https://svn.code.sf.net/p/vpopmail/code/

cd code

git switch --orphan Subversion-import
cp ../git-import.sh ../vpopmail-authors .
git add git-import.sh vpopmail-authors
git commit -m 'SVN import: add scripts'
git switch master

# do not take authorship for anything
export GIT_COMMITTER_NAME="git import"
export GIT_COMMITTER_EMAIL="<>"

# create a better history for them
## 5.2.1 .. 5.2.2
git checkout -b old_tags ${COMMIT_PREFIX}tags/v5_2_1
git commit --amend -C ${COMMIT_PREFIX}tags/v5_2_1 --date=2002-05-18
git tag v5.2.1
git restore -s ${COMMIT_PREFIX}tags/v5_2_2 -- *
git add -u
git add contrib/qmail-maildir++.patch
git commit -C ${COMMIT_PREFIX}tags/v5_2_2
git tag v5.2.2
# 5.2.2 was a stable release on it's own branch, see ChangeLog
TAG_RM_LIST=(v5_2_1 v5_2_2)

## 5.3.20 .. 5.3.27
git reset --hard v5.2.1
git restore -s ${COMMIT_PREFIX}tags/v5.3.20 -- *
git add -u
git add contrib/qmail-maildir++.patch
git commit -C ${COMMIT_PREFIX}tags/v5.3.20 --date 2003-04-01
git tag v5.3.20
TAG_RM_LIST=(${TAG_RM_LIST[@]} v5.3.20)
for i in $(seq 21 27); do
  git restore -s ${COMMIT_PREFIX}tags/v5_3_${i} -- *
  git add -u
  # new in 5.3.24
  if [ -f contrib/sendmail2vpopmail.pl ]; then
    git add contrib/sendmail2vpopmail.pl
  fi
  if [ ${i} -eq 25 ]; then
    DATE_ARG=2003-08-26
  else
    DATE_ARG=$(head -n 5 ChangeLog | sed -n "/^5\.3\.${i}[[:space:]]/s/.*released[[:space:]]*//p")
  fi
  GIT_COMMITTER_NAME="Matt Brookings" GIT_COMMITTER_EMAIL="matt@inter7.com" GIT_COMMITTER_DATE="2009-08-24 17:54:14" git commit -C ${COMMIT_PREFIX}tags/v5_3_${i} --date="${DATE_ARG}"
  git tag v5.3.${i}
  TAG_RM_LIST=(${TAG_RM_LIST[@]} v5_3_${i})
done

# add a commit that allows to merge with the cvs import where everything was in a subdir
mkdir vpopmail
git mv $(ls -1 | grep -vFx vpopmail) vpopmail/
git commit --author "git import <>" -m 'git import: move files into subdirectory'
git switch -

# recreate history with them included
git replace --graft $(get_commit 5) $(get_commit 3) old_tags
git filter-repo --force

git branch -d old_tags

# there exist 2 other imports of this commit, this one is identical to Release_5_3-28
git tag v5.3.28 $(get_commit 36)

# replaced above
git branch -D tags/Release_5-3-28
# no changes, stale commit
git branch -D tags/start
# another import attempt, unrelated to other history, parent of the 2 above
git branch -D vendor

# add proper author when external patches were taken
# this intentionally omits r628 as that combines multiple patches and authors

git filter-repo --commit-callback '
def set_author(commit, name, email = b""):
  commit.author_name = name
  commit.author_email = email
  commit.message = commit.message.replace(b" (" + name + b")",b"")
  commit.message = commit.message.replace(b" (from " + name + b")",b"")
  commit.message = commit.message.replace(b" (patch from " + name + b")",b"")
  return commit

if b"add John Simpson" in commit.message or b"John'\''s" in commit.message or b" (John Simpson)" in commit.message or b"v5_5_0@629" in commit.message or b"stable-5_4@549" in commit.message or b"stable-5_4@552" in commit.message or b"stable-5_4@568 " in commit.message:
  commit = set_author(commit, b"John Simpson", b"jms1@jms1.net")
  if not b"stable-5_4@552" in commit.message:
    commit.message = commit.message.replace(b"John Simpson'\''s ",b"")
  commit.message = commit.message.replace(b"John Simpson ",b"")
  commit.message = commit.message.replace(b"John'\''s ",b"")
  commit.message = commit.message.replace(b"from John",b"")

elif b"Rolf Eike Beer" in commit.message:
  commit = set_author(commit, b"Rolf Eike Beer", b"dakon@users.sf.net")
  commit.message = commit.message.replace(b" by Rolf Eike Beer",b"")
  commit.message = commit.message.replace(b" from Rolf Eike Beer",b"")

elif b"v5_4_32@1030" in commit.message or b"v5_4_32@1028" in commit.message:
  commit = set_author(commit, b"", b"kenji@kens.fm")

elif b"v5_4_32@1022" in commit.message:
  commit = set_author(commit, b"Drew Wells", b"")

elif b"v5_4_32@1015" in commit.message:
  commit = set_author(commit, b"Tullio Andreatta", b"")

elif b"v5_4_32@1004" in commit.message:
  commit = set_author(commit, b"Alessio", b"alessio@skye.it")

elif b"v5_4_32@990" in commit.message or b"v5_5_0@907" in commit.message or b"v5_5_0@895" in commit.message or b"v5_5_0@894" in commit.message or b"v5_5_0@822" in commit.message:
  commit = set_author(commit, b"aledr", b"matrixworkstation@gmail.com")
  if b"v5_4_32@990" in commit.message:
    commit.message = commit.message.replace(b"aledr <matrixworkstation@gmail.com>",b"")
    commit.message = commit.message.replace(b"   - ",b"")
  elif b"v5_4_32@822" in commit.message:
    commit.message = commit.message.replace(b"aledr <matrixworkstation@gmail.com>",b"aledr")

elif b"v5_5_0@815" in commit.message:
  commit = set_author(commit, b"Luis Felipe Silveira da Silva",b"felipe@bsd.com.br")
  commit.message = commit.message.replace(b"Added patch by Luis Felipe Silveira da Silva to ",b"")

elif b"trunk@683" in commit.message:
  commit = set_author(commit, b"Manvendra Bhangui",b"mbhangui@gmail.com")

elif b"trunk@632" in commit.message:
  commit = set_author(commit, b"Ronnie Karstenberg",b"") # rkarstenberg

elif b"trunk@631" in commit.message:
  commit = set_author(commit, b"Vitali Malicky",b"") # coonardoo

elif b"trunk@630" in commit.message:
  commit = set_author(commit, b"Harm van Tilborg",b"")

elif b"trunk@622" in commit.message:
  commit = set_author(commit, b"Remo Mattei",b"")

elif b"stable-5_4@594" in commit.message or b"stable-5_4@593" in commit.message:
  commit = set_author(commit, b"Stoyan Marinov",b"") # smarinov

elif b"stable-5_4@559" in commit.message:
  commit = set_author(commit, b"Joshua Megerman")
  commit.message = commit.message.replace(b"Joshua'\''s SQL Backend Fixes [1619489] See UPGRADE for 1.4.18\!\n",b"SQL Backend Fixes [1619489]\n\nSee UPGRADE for 1.4.18!")

elif b"stable-5_4@580" in commit.message:
  commit = set_author(commit, b"Fabio Busatto",b"")

elif b"stable-5_4@553" in commit.message or b"stable-5_4@554" in commit.message:
  commit = set_author(commit, b"Drew")
  commit.message = commit.message.replace(b"Drew'\''s ",b"")

elif b"stable-5_4@548" in commit.message:
  commit = set_author(commit, b"Tijs Zwinkels")

elif b"v5_4_18-rwidmer@534" in commit.message:
  commit = set_author(commit, b"Trent Lloyd")

elif b"v5_4_18-rwidmer@524" in commit.message or  b"v5_4_18-rwidmer@525" in commit.message or  b"v5_4_18-rwidmer@526" in commit.message or  b"v5_4_18-rwidmer@527" in commit.message or  b"v5_4_18-rwidmer@529" in commit.message or  b"v5_4_18-rwidmer@530" in commit.message or  b"v5_4_18-rwidmer@531" in commit.message or  b"v5_4_18-rwidmer@532" in commit.message or  b"v5_4_18-rwidmer@533" in commit.message:
  commit = set_author(commit, b"Peter Pentchev")

elif b"stable-5_4@507" in commit.message or b"stable-5_4@386" in commit.message:
  commit = set_author(commit, b"Jeremy Kister")
  commit.message = commit.message.replace(b"Patch from Jeremy Kister; ",b"")

elif b"stable-5_4@506" in commit.message:
  commit = set_author(commit, b"Ron Gage")

elif b"stable-5_4@500" in commit.message or  b"stable-5_4@501" in commit.message or  b"stable-5_4@487" in commit.message or b"stable-5_4@475" in commit.message:
  commit = set_author(commit, b"Michael Krieger")

elif b"stable-5_4@492" in commit.message:
  commit = set_author(commit, b"Toshihiko Kyoda")

elif b"stable-5_4@488" in commit.message:
  commit = set_author(commit, b"Jianbin Xiao")

elif b"stable-5_4@460" in commit.message:
  commit = set_author(commit, b"Gaetan Minet")

elif b"stable-5_4@446" in commit.message:
  commit = set_author(commit, b"Jory A. Pratt")
  commit.message = commit.message.replace(b"(from Jory A. Pratt) ",b"")

elif b"stable-5_4@445" in commit.message:
  commit = set_author(commit, b"Riccardo Bini")

elif b"stable-5_4@403" in commit.message or b"stable-5_4@400" in commit.message:
  commit = set_author(commit, b"Niki Denev")

elif b"stable-5_4@385" in commit.message:
  commit = set_author(commit, b"Charles Boening")
  commit.message = commit.message.replace(b"from Charles Boening ",b"")

elif b"stable-5_4@361" in commit.message or b"stable-5_4@362" in commit.message or b"stable-5_4@489" in commit.message or b"stable-5_4@513" in commit.message or b"stable-5_4@509" in commit.message or b"stable-5_4@362" in commit.message:
  commit = set_author(commit, b"Rick Widmer")
  commit.message = commit.message.replace(b"add Rick Widmer'\''s patch ",b"add patch ")
  commit.message = commit.message.replace(b"Rick Widmer'\'' ",b"")

elif b"stable-5_4@327" in commit.message:
  commit = set_author(commit, b"Pit Palme")

# r312 is a cherry-pick of r287
elif b"stable-5_4@312" in commit.message or b"stable-5_4@487" in commit.message:
  commit = set_author(commit, b"Ken Jones", b"kbo@inter7.com")
  commit.message = commit.message.replace(b"Ken Jones'\'' ",b"")

elif b"trunk@239" in commit.message or b"trunk@16 " in commit.message or b"trunk@195" in commit.message or b"trunk@28 " in commit.message:
  commit = set_author(commit, b"Anders Brander", b"anders@brander.dk")
  commit.message = commit.message.replace(b"apply Anders Brander'\''s patch to ",b"")
  commit.message = commit.message.replace(b"Anders Brander'\''s ",b"")

elif b"trunk@210" in commit.message or b"trunk@193" in commit.message or b"stable-5_4@577" in commit.message or b"trunk@87 " in commit.message or b"stable-5_4@392" in commit.message:
  commit.author_name = b"Bill Shupp"
  commit.author_email = b"hostmaster@shupp.org"
  if b"trunk@87" in commit.message:
    commit.message = commit.message.replace(b"bill shupp'\''s patch: ",b"")
  elif b"stable-5_4@392" in commit.message:
    commit.message = commit.message.replace(b"Bill Shupp'\''s ",b"")
  else:
    commit.message = commit.message.replace(b"Bill'\''s ",b"")
    commit.message = commit.message.replace(b"Shupp'\''s ",b"")

elif b"trunk@196" in commit.message:
  commit = set_author(commit, b"Erwin Hoffmann")

elif b"trunk@133" in commit.message or b"trunk@136" in commit.message or b"trunk@194" in commit.message:
  commit = set_author(commit, b"Casey Zacek")
  commit.message = commit.message.replace(b"(from Casey Zacek, ",b"(")

elif b"trunk@99 " in commit.message:
  commit = set_author(commit, b"Dmitry Vodennikov")
  commit.message = commit.message.replace(b"from Dmitry Vodennikov",b"")

elif b"trunk@15 " in commit.message:
  commit = set_author(commit, b"Kazuho Oku")

elif b"trunk@12 " in commit.message:
  commit = set_author(commit, b"Michael Bowe")
  commit.message = commit.message.replace(b"Bowe'\''s ",b"")

elif b"*** empty log message ***" in commit.message:
  commit.message = commit.message.replace(b"*** empty log message ***\n",b"")

while b"\n\n\ngit-svn-id: https://svn.code.sf.net/p/vpopmail/code/" in commit.message:
  commit.message = commit.message.replace(b"\n\n\ngit-svn-id: https://svn.code.sf.net/p/vpopmail/code/",b"\n\ngit-svn-id: https://svn.code.sf.net/p/vpopmail/code/")
'

# git-svn does not set tags because svn can later change tags

# first get rid of the imported old versions that have already been converted
for b in ${TAG_RM_LIST[@]}; do
	git branch -D tags/${b}
done

# fix some stupid imported tags
# they all had "This commit was manufactured by cvs2svn to create tag 'v5_4_x'." as message, but no changes
for v in $(seq 3 15) 18; do
	if [ -n "$(git diff tags/v5_4_${v}^..tags/v5_4_${v})" ]; then
		echo "tag commit v5_4_${v} was not empty"
		exit 1
	fi
	git tag v5.4.${v} tags/v5_4_${v}^
	git branch -D tags/v5_4_${v}
done

# looks like a typo and is the same as the one without the first '_'
git branch -D tags/v_5_4_23

for b in $(git branch --list tags/*); do
	git tag ${b#tags/} ${b}
	git branch -D ${b}
	# remove any release branch with the tag name that may still exist, there are several
	# they have been moved in SVN history but are preserved in git
	git branch -D ${b#tags/} || true
done

# HEAD was moved from 5_5_1 to 5_4 in r616, the old contents were removed before
# this messes up tracking of when the lines were changed, so just rewrite the history so
# "master" follows "stable-5_4^"
git branch devel-5_5_1 $(get_commit 615)
git replace --graft $(get_commit 616) stable-5_4^
# just because it makes more sense
git replace --graft v5_4_31 v5_4_30
git replace --graft $(get_commit 545) $(get_commit 523) $(get_commit 544 v5_4_18-rwidmer)
git filter-repo --force

# These are somehow misplaced
git tag v5.4.2 $(get_commit 240)
git tag -d v5_4_2
git tag v5.4.1 $(get_commit 230)
git tag -d v5_4_1
git tag v5.4.0 $(get_commit 227)
git tag -d v5_4_0
git tag v5.4.0-rc2 $(get_commit 221)
git tag -d v5_4_0-rc2
git tag v5.4.0-rc1 $(get_commit 167)
git tag -d v5_4_0-rc1
git tag v5.4.0-pre2 $(get_commit 154)
git tag -d v5_4_0-pre2
git tag v5.4.0-pre1 $(get_commit 131)
git tag -d v5_4_0-pre1
git tag v5.3.30 $(get_commit 103)
git tag -d Release-5_3_30
git tag v5.3.29 $(get_commit 78)
git tag -d Release-5_3_29
git branch -D v5_4_18-rwidmer

sed '/replace\//d' -i .git/packed-refs .git/info/refs
rmdir .git/refs/replace
