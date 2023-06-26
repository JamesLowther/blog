#!/bin/bash

cd $(dirname $0)

echo "Pulling latest from main - overwriting changed files"
git fetch --all
git reset --hard origin/main

echo "Copying manifest.json"
cp .obsidian/plugins/metadata-extractor/metadata.json .

