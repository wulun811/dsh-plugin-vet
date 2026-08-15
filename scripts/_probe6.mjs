
import fs from "node:fs";
const s = fs.readFileSync(".index.html", "utf8");
const i = s.indexOf('"id":"@deepseek-ai/dsh-client-ui-conversation"');
console.log("idx:", i);
if (i !== -1) console.log(s.slice(i, i + 300));
