
import fs from "node:fs";
const s = fs.readFileSync(".conv.js", "utf8");
for (const needle of ["header.actions", "session.header", "headerActions", "actions", "overflow", "zIndex: 100", "position: absolute", "right: 0", "grid-template-columns"]) {
  let i = s.indexOf(needle);
  const hits = [];
  while (i !== -1 && hits.length < 3) {
    hits.push(s.slice(Math.max(0, i - 160), Math.min(s.length, i + 200)).replace(/\n/g, " "));
    i = s.indexOf(needle, i + 1);
  }
  console.log("### " + needle + " (" + hits.length + ")");
  for (const h of hits) console.log("  ..." + h + "...");
}
