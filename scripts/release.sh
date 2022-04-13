#!/usr/bin/env bash

BODY="File SHA=BUNDLE_SHA<br />"

payload=$(cat  << EOF
{
    "tag_name": "$TRAVIS_TAG",
    "name": "$TRAVIS_TAG",
    "body": "$BODY",
    "draft": false
}
EOF
)

curl --data "$payload" \
     --header "Authorization: token $GITHUB_TOKEN" \
     "https://api.github.com/repos/$REPO/releases"
