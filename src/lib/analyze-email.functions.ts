import { createServerFn } from "@tanstack/react-start";
import { generateText, Output } from "ai";
import { z } from "zod";
import { createLovableAiGatewayProvider } from "./ai-gateway.server";

const InputSchema = z.object({
  sender: z.string().max(500).optional().default(""),
  subject: z.string().max(1000).optional().default(""),
  body: z.string().min(1).max(20000),
});

const AnalysisSchema = z.object({
  verdict: z.enum(["safe", "suspicious", "phishing", "fraud"]),
  riskScore: z.number().min(0).max(100),
  confidence: z.number().min(0).max(100),
  summary: z.string(),
  indicators: z.array(
    z.object({
      category: z.enum([
        "suspicious_link",
        "spoofed_sender",
        "urgency_pressure",
        "credential_request",
        "attachment_risk",
        "grammar_anomaly",
        "financial_scam",
        "impersonation",
        "malicious_payload",
        "other",
      ]),
      severity: z.enum(["low", "medium", "high", "critical"]),
      detail: z.string(),
    }),
  ),
  suspiciousLinks: z.array(
    z.object({
      url: z.string(),
      reason: z.string(),
      risk: z.enum(["low", "medium", "high", "critical"]),
    }),
  ),
  recommendations: z.array(z.string()),
});

export type EmailAnalysis = z.infer<typeof AnalysisSchema>;

export const analyzeEmail = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => InputSchema.parse(input))
  .handler(async ({ data }): Promise<EmailAnalysis> => {
    const key = process.env.LOVABLE_API_KEY;
    if (!key) throw new Error("Missing LOVABLE_API_KEY");

    const gateway = createLovableAiGatewayProvider(key);

    const system = `You are MailGuard, an elite email security analyst. You inspect forwarded emails and decide whether they are phishing, fraud, scam, or safe.

Apply rigorous analysis:
- Inspect the sender domain for spoofing, homoglyphs, and look-alike domains.
- Detect urgency pressure, fear tactics, and social engineering.
- Identify credential / OTP / payment / KYC harvesting attempts.
- Flag every suspicious URL: shorteners, IP-address URLs, mismatched display text, lookalike domains, unusual TLDs.
- Note impersonation of banks, courier services, tax authorities, executives, IT, HR.
- Detect attachment-based threats (invoices, .zip, .html, macro docs).
- Detect financial fraud: lottery, inheritance, crypto, romance, advance fee, fake invoice, BEC.

Score 0-100 where 0 = perfectly safe, 100 = definitely malicious.
- 0-20: safe
- 21-50: suspicious
- 51-80: phishing
- 81-100: fraud / highly malicious

Be decisive. Better to over-warn than miss a real attack. Always return at least one recommendation.`;

    const prompt = `Analyze this email:

FROM: ${data.sender || "(not provided)"}
SUBJECT: ${data.subject || "(not provided)"}

BODY:
${data.body}`;

    try {
      const { output } = await generateText({
        model: gateway("google/gemini-3-flash-preview"),
        system,
        prompt,
        output: Output.object({ schema: AnalysisSchema }),
      });
      return output;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("429")) throw new Error("Rate limit reached. Please wait a moment and try again.");
      if (msg.includes("402")) throw new Error("AI credits exhausted. Please add credits to continue.");
      throw new Error(`Analysis failed: ${msg}`);
    }
  });
