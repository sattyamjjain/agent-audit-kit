import * as github from "@actions/github";
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();

export async function review(): Promise<string> {
  const title = github.context.payload.pull_request?.title ?? "";
  const reply = await client.messages.create({
    model: "claude-sonnet-4-5",
    max_tokens: 512,
    messages: [{ role: "user", content: `Review this change: ${title}` }],
  });
  return reply.content[0].type === "text" ? reply.content[0].text : "";
}
