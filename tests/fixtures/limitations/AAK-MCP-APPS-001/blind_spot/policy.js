import { createUIResource } from "@mcp-ui/server";

const POLICY = "allow-scripts allow-same-origin";

const frame = document.createElement("iframe");
frame.sandbox = POLICY;
frame.src = "ui://notes/view";
document.body.appendChild(frame);
export { createUIResource };
