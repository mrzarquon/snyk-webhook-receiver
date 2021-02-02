#!/usr/bin/env zsh

export NOW=`date "+%Y-%m-%d"` 

cat >> test << BREWEOF

# injects homebrew installed binaries infront of apple's
# added: `date "+%Y-%m-%d"`
export PATH=/usr/local/bin:\$PATH

BREWEOF