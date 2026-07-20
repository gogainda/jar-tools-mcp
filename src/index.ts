#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { readFile } from "fs/promises";
import { basename } from "path";

const JAR_TOOLS_BASE_URL = process.env.JARTOOLS_BASE_URL || "https://jar.tools";

interface ScanResultData {
  class_count?: number;
  suspicious_class_count?: number;
  suspicious_class_ratio?: number;
  suspicious_reason_counts?: Record<string, number>;
  decompiler_anomaly_class_count?: number;
  [key: string]: unknown;
}

interface ScanResult {
  success: boolean;
  requestId?: string;
  redacted?: boolean;
  error?: string;
  data?: ScanResultData;
  // Rate-limit response fields (present when the request itself is a 429 body)
  message?: string;
  reset?: string;
  upgradeUrl?: string;
  upgrade?: { api_access?: string };
}

const tools: Tool[] = [
  {
    name: "scan_jar_security",
    description:
      "Run jar.tools' static security scan on a local .jar/.zip or .class file. Returns structured findings — suspicious-class counts by category (network activity, file access, process execution, hard-to-review/obfuscated code) plus decompiler-anomaly signals. Useful for auditing a dependency before adding it to a build, or investigating a suspicious plugin/mod. Static analysis only — the file is never executed. Free for .jar/.zip up to 64MB and .class up to 5MB; pass a Pro license_key to raise the JAR size cap to 256MB.",
    inputSchema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Path to a local .jar, .zip, or .class file to scan.",
        },
        license_key: {
          type: "string",
          description:
            "Optional jar.tools Pro license key, raises the .jar size cap from 64MB to 256MB. Falls back to the JARTOOLS_LICENSE_KEY environment variable if not provided.",
        },
      },
      required: ["file_path"],
    },
  },
];

export async function scanJarSecurity(
  filePath: string,
  licenseKey?: string
): Promise<ScanResult> {
  const lower = filePath.toLowerCase();
  let endpoint: string;
  if (lower.endsWith(".jar") || lower.endsWith(".zip")) {
    endpoint = "jar-report";
  } else if (lower.endsWith(".class")) {
    endpoint = "class-report";
  } else {
    throw new Error("Only .jar, .zip, or .class files are supported.");
  }

  const buffer = await readFile(filePath);
  const blob = new Blob([buffer]);
  const formData = new FormData();
  formData.append("file", blob, basename(filePath));

  const key = licenseKey || process.env.JARTOOLS_LICENSE_KEY;
  const headers: Record<string, string> = {};
  if (key) {
    headers["X-License-Key"] = key;
  }

  const response = await fetch(`${JAR_TOOLS_BASE_URL}/api/v1/security-scan/${endpoint}`, {
    method: "POST",
    body: formData,
    headers,
  });

  const payload = (await response.json()) as ScanResult;

  if (response.status === 429) {
    const parts = [payload.message || "jar.tools security-scan rate limit reached."];
    if (payload.reset) {
      parts.push(`Resets at ${payload.reset}.`);
    }
    const upgrade = payload.upgradeUrl || payload.upgrade?.api_access;
    if (upgrade) {
      parts.push(`Upgrade: ${upgrade}`);
    }
    throw new Error(parts.join(" "));
  }

  if (!response.ok || payload.success === false) {
    throw new Error(payload.error || `jar.tools scan failed (HTTP ${response.status}).`);
  }

  return payload;
}

function formatScanSummary(filePath: string, result: ScanResult): string {
  const data = result.data;
  const classCount = data?.class_count;
  const suspiciousCount = data?.suspicious_class_count;
  const suspiciousRatio = data?.suspicious_class_ratio;
  const reasonCounts = data?.suspicious_reason_counts;
  const anomalyCount = data?.decompiler_anomaly_class_count;

  const topReasons = reasonCounts
    ? Object.entries(reasonCounts)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 3)
        .map(([reason, count]) => `${reason} (${count})`)
        .join(", ")
    : "";

  return [
    `Scanned ${basename(filePath)}${typeof classCount === "number" ? `: ${classCount} classes analyzed` : ""}.`,
    typeof suspiciousCount === "number"
      ? `${suspiciousCount} flagged as suspicious${
          typeof suspiciousRatio === "number" ? ` (${(suspiciousRatio * 100).toFixed(1)}%)` : ""
        }.`
      : null,
    topReasons ? `Top signals: ${topReasons}.` : null,
    typeof anomalyCount === "number" && anomalyCount > 0
      ? `${anomalyCount} class(es) show decompiler-evasion anomalies — worth a manual read.`
      : null,
  ]
    .filter((line): line is string => Boolean(line))
    .join("\n");
}

const server = new Server(
  { name: "jar-tools-mcp", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    if (name === "scan_jar_security") {
      const { file_path, license_key } = args as {
        file_path: string;
        license_key?: string;
      };

      if (!file_path) {
        throw new Error("file_path is required.");
      }

      const result = await scanJarSecurity(file_path, license_key);
      const summary = formatScanSummary(file_path, result);

      return {
        content: [
          { type: "text", text: summary },
          { type: "text", text: JSON.stringify(result.data ?? result, null, 2) },
        ],
      };
    }

    throw new Error(`Unknown tool: ${name}`);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text", text: `Error: ${errorMessage}` }],
      isError: true,
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("jar-tools MCP server running on stdio");
}

main().catch(console.error);
