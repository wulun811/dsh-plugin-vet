
import fs from "node:fs";
const s = fs.readFileSync(".subagent.js", "utf8");
for (const needle of ["slots.register", "locale", "header.actions", "useLocale", "getLocale", "locale/change", "t(", "installLocale", "register("]) {
  let i = s.indexOf(needle);
  const hits = [];
  while (i !== -1 && hits.length < 3) {
    hits.push(s.slice(Math.max(0, i - 150), Math.min(s.length, i + 220)).replace(/\n/g, " "));
    i = s.indexOf(needle, i + 1);
  }
  console.log("### " + needle + " (" + hits.length + ")");
  for (const h of hits) console.log("  ..." + h + "...");
}
