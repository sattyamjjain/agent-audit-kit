import { createUIResource } from "@mcp-ui/server";

const frame = document.createElement("iframe");
frame.src = "ui://notes/view";
document.body.appendChild(frame);
export { createUIResource };
