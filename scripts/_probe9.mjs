
import fs from "node:fs";
const s = fs.readFileSync(".locale.js", "utf8");
for (const needle of ["define", "register", "service", "locale", "messages", "namespace", "NS", "t(", "use", "current", "setLocale", "zh-CN", "en-US"]) {
  let i = s.indexOf(needle);
  const hits = [];
  while (i !== -1 && hits.length < 3) {
    hits.push(s.slice(Math.max(0, i - 120), Math.min(s.length, i + 180)).replace(/\n/g, " "));
    i = s.indexOf(needle, i + 1);
  }
  console.log("### " + needle + " (" + hits.length + ")");
  for (const h of hits) console.log("  ..." + h + "...");
}
