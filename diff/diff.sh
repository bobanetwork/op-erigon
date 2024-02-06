#!/bin/bash
# Execute me from inside of a repo which has been cloned from the Boba
# v3-erigon repository e.g.
# git clone  https://github.com/bobanetwork/v3-erigon.git
# cd v3-erigon
# ./diff.sh

BOBA=ba22a4040d5fb8f2d74e13ae50db91575ca72c78
UPST=3040e2576c29512addaf8ce50528609b4ff9a8e0

git diff -w --numstat "${BOBA}..${UPST}" > all_modified_files.txt

cat all_modified_files.txt | \
    # Check only .go files \
    grep -e '\.go$' | \
    # Skip _test.go files \
    grep -ve '_test\.go$' | \
    grep -ve 'cmd/rpcdaemon/rpcdaemontest/test_util.go' | \
    grep -ve 'tests/state_test_util.go' | \
    # Skip generated protobuf files
    grep -ve '\.pb\.go$' | \
    # Skip a couple generated JSON marshaling files
    grep -v 'core/types/receipt_codecgen_gen.go' | \
    grep -ve 'core/types/gen_[^/]*.go' > interesting_files.txt

cat all_modified_files.txt interesting_files.txt | sort | uniq -u > omitted_files.txt

# Sum up the new lines of code
awk '{Total=Total+$2} END{print "Total added is: " Total}' interesting_files.txt
