#!/usr/bin/env node

/**
 * DarkLens Model Context Protocol (MCP) Server
 * Connects Cursor, Windsurf, Claude Desktop, and AI coding agents to DarkLens.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createRequire } from "module";
import fetch from "node-fetch";

const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require("../package.json");

// Parse API key from env or command line arguments
function getApiKey() {
  if (process.env.DARKLENS_API_KEY && process.env.DARKLENS_API_KEY.trim()) {
    return process.env.DARKLENS_API_KEY.trim();
  }
  const eqArg = process.argv.find((arg) => arg.startsWith("--key="));
  if (eqArg) {
    const val = eqArg.slice("--key=".length).trim();
    if (val && !val.startsWith("--")) return val;
  }
  const keyIdx = process.argv.indexOf("--key");
  if (keyIdx !== -1) {
    const nextVal = process.argv[keyIdx + 1]?.trim();
    if (nextVal && !nextVal.startsWith("--")) {
      return nextVal;
    }
  }
  return null;
}

const ALLOWED_FAIL_ON = new Set(["score", "critical", "any"]);

function validateTargetUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(String(rawUrl || "").trim());
  } catch {
    throw new Error(`Invalid URL "${rawUrl}". Include http:// or https://.`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Unsupported URL protocol "${parsed.protocol}". Use http:// or https://.`);
  }
  return parsed.href;
}

function sanitizeRawHtml(rawHtml) {
  if (typeof rawHtml !== "string") return undefined;
  let cleaned = rawHtml
    .replace(/<style\b[\s\S]*?<\/style>/gi, "")
    .replace(/<svg\b[\s\S]*?<\/svg>/gi, "")
    .replace(/<input\b[^>]*>/gi, (tag) => {
      if (/\b(?:type=["']?(?:password|email|tel|number)["']?|\b(?:name|id|autocomplete)=["']?(?:[^"']*(?:pass|pwd|email|card|cc|cvv|cvc|ssn)[^"']*))["']?/i.test(tag)) {
        return tag.replace(/\bvalue=(?:"[^"]*"|'[^']*'|[^\s>]+)/i, 'value="[REDACTED]"');
      }
      return tag.replace(/\bvalue=(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i, (m, q1, q2, u) => {
        const val = q1 ?? q2 ?? u ?? "";
        return val.replace(/\D/g, "").length >= 13 ? 'value="[REDACTED_CC]"' : m;
      });
    })
    .replace(/(<textarea\b[^>]*>)([\s\S]*?)(<\/textarea>)/gi, (m, open, inner, close) => {
      return inner.replace(/\D/g, "").length >= 13 ? `${open}[REDACTED_CC]${close}` : m;
    })
    .replace(/(src=["'])data:image\/[^"']*(["'])/gi, "$1$2");

  if (cleaned.length > 150000) {
    const footerMatch = cleaned.match(/<footer\b[\s\S]*?<\/footer>/i);
    const reservedFooter = footerMatch ? footerMatch[0].slice(0, 12000) : "";
    cleaned = cleaned.slice(0, 150000 - reservedFooter.length) + reservedFooter;
  }
  return cleaned;
}

async function callDarkLensScanApi({ apiKey, url, rawHtml, threshold = 70, failOn = "score" }) {
  const validUrl = validateTargetUrl(url);
  if (threshold === "" || threshold === null || typeof threshold === "boolean") {
    throw new Error(`Invalid threshold "${threshold}". Must be a number between 0 and 100.`);
  }
  const numericThreshold = Number(threshold);
  if (!Number.isFinite(numericThreshold) || numericThreshold < 0 || numericThreshold > 100) {
    throw new Error(`Invalid threshold "${threshold}". Must be between 0 and 100.`);
  }
  if (!ALLOWED_FAIL_ON.has(failOn)) {
    throw new Error(`Invalid failOn "${failOn}". Expected 'score', 'critical', or 'any'.`);
  }

  const body = {
    url: validUrl,
    threshold: Math.round(numericThreshold),
    failOn,
  };
  if (rawHtml !== undefined) {
    body.rawHtml = sanitizeRawHtml(rawHtml);
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 65000);
  let res;
  try {
    res = await fetch("https://darklens.dev/api/ci/scan", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "User-Agent": `darklens-mcp/${PKG_VERSION}`,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("DarkLens API request timed out after 65 seconds.");
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }

  const rawText = await res.text();
  let data;
  try {
    data = rawText ? JSON.parse(rawText) : {};
  } catch {
    throw new Error(`DarkLens API returned non-JSON response (${res.status} ${res.statusText}).`);
  }

  if (!res.ok && res.status !== 422) {
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: `❌ DarkLens API Error (${res.status}): ${data.message || data.error || res.statusText}`,
        },
      ],
    };
  }

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(data, null, 2),
      },
    ],
  };
}

const server = new Server(
  {
    name: "darklens-mcp",
    version: PKG_VERSION,
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Define MCP Tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "darklens_audit_url",
        description:
          "Audit any staging or live URL for deceptive dark patterns, compliance risks (FTC, GDPR, CCPA, EU DSA), and sneaky checkout traps. Returns compliance score (0-100), pass/fail, and detailed findings with remediation fixes.",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "The target website or staging URL to audit (e.g. https://staging.myapp.com)",
            },
            threshold: {
              type: "number",
              description: "Minimum acceptable passing compliance score (0-100). Default is 70.",
              default: 70,
            },
            failOn: {
              type: "string",
              enum: ["score", "critical", "any"],
              description: "Failure criterion: 'score' (score below threshold), 'critical' (only critical legal traps), or 'any'. Default is 'score'.",
              default: "score",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "darklens_audit_html",
        description:
          "Audit raw HTML, JSX, or component markup for dark patterns (pre-checked auto-renewal checkboxes, confirmshaming guilt copy, fake countdown timers, hidden fees, missing reject buttons) before committing to production.",
        inputSchema: {
          type: "object",
          properties: {
            rawHtml: {
              type: "string",
              description: "The raw HTML or JSX markup to inspect for dark patterns.",
            },
            url: {
              type: "string",
              description: "Optional URL context (default: 'https://localhost:3000').",
              default: "https://localhost:3000",
            },
            threshold: {
              type: "number",
              description: "Minimum acceptable passing compliance score (0-100). Default is 70.",
              default: 70,
            },
            failOn: {
              type: "string",
              enum: ["score", "critical", "any"],
              description: "Failure criterion. Default is 'score'.",
              default: "score",
            },
          },
          required: ["rawHtml"],
        },
      },
      {
        name: "darklens_get_fair_pattern_guide",
        description:
          "Retrieve regulatory compliance rules, legal citations (FTC Act Sec. 5, GDPR Art. 25, EU DSA Art. 25, CCPA), and compliant UI/UX alternatives for specific deceptive design categories.",
        inputSchema: {
          type: "object",
          properties: {
            patternCategory: {
              type: "string",
              description: "Category to get remediation guidelines for (e.g., 'forced_continuity', 'confirmshaming', 'fake_urgency', 'hidden_fees', 'interface_interference', 'roach_motel').",
            },
          },
        },
      },
    ],
  };
});

// Handle Tool Calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const apiKey = getApiKey();

  if (!apiKey && name !== "darklens_get_fair_pattern_guide") {
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: `❌ Error: Missing DarkLens API key.
Please configure your DARKLENS_API_KEY environment variable in your MCP configuration.
Generate an API key at https://darklens.dev/dashboard and subscribe to Agency or purchase API credits.`,
        },
      ],
    };
  }

  try {
    if (name === "darklens_audit_url") {
      const { url, threshold = 70, failOn = "score" } = args || {};
      return await callDarkLensScanApi({ apiKey, url, threshold, failOn });
    }

    if (name === "darklens_audit_html") {
      const { rawHtml, url, threshold = 70, failOn = "score" } = args || {};
      if (!rawHtml || typeof rawHtml !== "string" || !rawHtml.trim()) {
        throw new Error("rawHtml must be a non-empty string.");
      }
      const targetUrl = typeof url === "string" && url.trim() ? url.trim() : "https://localhost:3000";
      return await callDarkLensScanApi({ apiKey, url: targetUrl, rawHtml, threshold, failOn });
    }

    if (name === "darklens_get_fair_pattern_guide") {
      const { patternCategory = "general" } = args || {};

      const guides = {
        forced_continuity: {
          issue: "Pre-checked recurring subscriptions or auto-renewals without explicit affirmative consent.",
          regulation: "FTC Act Section 5, ROSCA, California Auto-Renewal Law (ARL)",
          fairPattern: "Checkboxes for recurring billing MUST be unchecked by default. Explicitly state the renewal frequency, cancellation method, and exact price before the payment button.",
        },
        confirmshaming: {
          issue: "Using emotionally manipulative language on opt-out buttons (e.g., 'No thanks, I hate saving money').",
          regulation: "EU Digital Services Act (DSA) Article 25, FTC Deceptive Practices",
          fairPattern: "Use neutral, factual dismiss copy such as 'No thanks', 'Close', or 'Skip for now'.",
        },
        fake_urgency: {
          issue: "Fabricating artificial countdown timers or claiming 'Only 2 items left' when inventory is unlimited.",
          regulation: "FTC Act Section 5, UK CMA Guidelines, EU UCPD",
          fairPattern: "Only display timers if tied to an actual expiring sale or real reservation hold. Never reset timers on page refresh.",
        },
        hidden_fees: {
          issue: "Drip pricing or revealing mandatory service, handling, or resort fees only at the final payment screen.",
          regulation: "FTC Junk Fees Rule, California SB 478, EU Consumer Rights Directive",
          fairPattern: "Display the all-in total price inclusive of mandatory fees upfront on the product card and initial cart summary.",
        },
        sneak_into_basket: {
          issue: "Automatically adding paid add-ons, shipping protection, or extended warranties to the user's cart without opt-in.",
          regulation: "EU Consumer Rights Directive Art. 22, UK DMCCA, FTC Section 5",
          fairPattern: "Require an un-ticked, explicit opt-in action from the shopper before adding any secondary product or warranty to the cart.",
        },
        interface_interference: {
          issue: "Visual misdirection such as giant bright 'Accept Cookies' button with microscopic gray 'Reject' link.",
          regulation: "GDPR Article 25, French CNIL / EDPB Guidelines",
          fairPattern: "Present 'Accept All' and 'Reject All' buttons with equal visual contrast, shape, and prominence.",
        },
        roach_motel: {
          issue: "Making account cancellation significantly harder than initial signup (e.g. phone-call required to cancel an online subscription).",
          regulation: "FTC Click-to-Cancel Rule (2024)",
          fairPattern: "Provide a 1-click or 2-click digital cancellation path through the web dashboard without phone calls or chat-support friction.",
        },
      };

      const guide = guides[patternCategory] || {
        guidelines: "DarkLens identifies 26 categories of deceptive design. Ensure explicit affirmative consent, symmetrical choices, clear pricing without hidden drip fees, and neutral non-shaming copy.",
        categories: Object.keys(guides),
      };

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(guide, null, 2),
          },
        ],
      };
    }

    throw new Error(`Unknown tool: ${name}`);
  } catch (error) {
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: `DarkLens MCP Error: ${error.message}`,
        },
      ],
    };
  }
});

async function run() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("DarkLens MCP server running on stdio");
}

run().catch((error) => {
  console.error("Fatal error running DarkLens MCP server:", error);
  process.exit(1);
});
