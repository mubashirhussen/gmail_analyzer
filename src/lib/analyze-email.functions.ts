import { createServerFn } from "@tanstack/react-start";
import { generateText } from "ai";
import { z } from "zod";
import { createLovableAiGatewayProvider } from "./ai-gateway.server";

const AttachmentSchema = z.object({
  name: z.string().max(300),
  mimeType: z.string().max(200),
  dataBase64: z.string().min(1).max(8_000_000), // ~6MB binary
  textContent: z.string().max(200_000).optional(),
});

const InputSchema = z.object({
  sender: z.string().max(500).optional().default(""),
  subject: z.string().max(1000).optional().default(""),
  body: z.string().max(40000).optional().default(""),
  attachments: z.array(AttachmentSchema).max(5).optional().default([]),
}).refine((v) => v.body.trim().length > 0 || (v.attachments?.length ?? 0) > 0, {
  message: "Provide email text or at least one attachment.",
});

const AnalysisSchema = z.object({
  verdict: z.enum(["safe", "suspicious", "phishing", "fraud"]),
  riskScore: z.number().min(0).max(100),
  confidence: z.number().min(0).max(100),
  summary: z.string(),
  indicators: z.array(
    z.object({
      category: z.string(),
      severity: z.enum(["low", "medium", "high", "critical"]),
      detail: z.string(),
    }),
  ).default([]),
  suspiciousLinks: z.array(
    z.object({
      url: z.string(),
      reason: z.string(),
      risk: z.enum(["low", "medium", "high", "critical"]),
    }),
  ).default([]),
  recommendations: z.array(z.string()).default([]),
});

export type EmailAnalysis = z.infer<typeof AnalysisSchema>;

const SYSTEM = `You are MailGuard, an elite email security analyst. Inspect forwarded emails (text and any attached screenshots / PDFs / documents) and decide whether they are phishing, fraud, scam, or safe.

Apply rigorous analysis:
- Sender spoofing, homoglyph / look-alike domains.
- Urgency, fear, social engineering.
- Credential / OTP / payment / KYC harvesting.
- Every suspicious URL: shorteners, IP URLs, mismatched display text, unusual TLDs.
- Impersonation of banks, courier, tax, executives, IT, HR.
- Attachment-based threats (invoices, .zip, .html, macros).
- Financial fraud: lottery, inheritance, crypto, romance, advance fee, BEC, fake invoice.

Score 0-100 (0 safe, 100 definitely malicious):
- 0-20 safe · 21-50 suspicious · 51-80 phishing · 81-100 fraud.

Return ONLY a single JSON object, no prose, no markdown fences. Shape:
{
  "verdict": "safe"|"suspicious"|"phishing"|"fraud",
  "riskScore": number,
  "confidence": number,
  "summary": string,
  "indicators": [{"category": string, "severity": "low"|"medium"|"high"|"critical", "detail": string}],
  "suspiciousLinks": [{"url": string, "reason": string, "risk": "low"|"medium"|"high"|"critical"}],
  "recommendations": [string]
}

Always include at least one recommendation. Better to over-warn than miss an attack.`;

function extractJson(text: string): unknown {
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fence ? fence[1] : text;
  const start = candidate.indexOf("{");
  const end = candidate.lastIndexOf("}");
  if (start === -1 || end === -1) throw new Error("Model did not return JSON.");
  return JSON.parse(candidate.slice(start, end + 1));
}

export const analyzeEmail = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => InputSchema.parse(input))
  .handler(async ({ data }): Promise<EmailAnalysis> => {
    const key = process.env.LOVABLE_API_KEY;
    if (!key) throw new Error("Missing LOVABLE_API_KEY");

    const gateway = createLovableAiGatewayProvider(key);

    const content: Array<Record<string, unknown>> = [];
    const textBlock = `Analyze this email:

FROM: ${data.sender || "(not provided)"}
SUBJECT: ${data.subject || "(not provided)"}

BODY:
${data.body || "(none — see attachments)"}`;
    content.push({ type: "text", text: textBlock });

    for (const att of data.attachments) {
      const dataUrl = `data:${att.mimeType};base64,${att.dataBase64}`;
      if (att.mimeType.startsWith("image/")) {
        content.push({ type: "image", image: dataUrl });
      } else if (att.textContent && att.textContent.trim().length > 0) {
        content.push({
          type: "text",
          text: `\n--- Attached file: ${att.name} (${att.mimeType}) ---\n${att.textContent.slice(0, 60000)}`,
        });
      } else {
        // PDFs and other binary docs as file parts
        content.push({
          type: "file",
          data: dataUrl,
          mediaType: att.mimeType || "application/octet-stream",
          filename: att.name,
        });
      }
    }

    try {
      const { text } = await generateText({
        model: gateway("google/gemini-3-flash-preview"),
        system: SYSTEM,
        messages: [{ role: "user", content: content as never }],
      });
      const parsed = extractJson(text);
      return AnalysisSchema.parse(parsed);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("429")) throw new Error("Rate limit reached. Please wait and try again.");
      if (msg.includes("402")) throw new Error("AI credits exhausted. Please add credits to continue.");
      throw new Error(`Analysis failed: ${msg}`);
    }
  });
