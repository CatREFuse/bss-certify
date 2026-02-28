#!/bin/bash
# 使用 gh CLI 上传文件到 GitHub

REPO="CatREFuse/bss-certify"

# 上传 SKILL.md
echo "SKILL.md" | gh api repos/CatREFuse/bss-certify/contents/SKILL.md \
  --method PUT \
  --field message="Add SKILL.md" \
  --field content="$(base64 -i SKILL.md | tr -d '\n')" \
  2>&1

# 创建 references 目录并上传文件
for file in references/*.md; do
  filename=$(basename "$file")
  echo "Uploading references/$filename"
  gh api "repos/CatREFuse/bss-certify/contents/references/$filename" \
    --method PUT \
    --field message="Add references/$filename" \
    --field content="$(base64 -i "$file" | tr -d '\n')" \
    2>&1
done
