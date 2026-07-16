"""AIGeneratedDetector — heuristics for synthetic (LLM-authored) email text.

Not a classifier; a set of stable, explainable features that shift risk
when combined with credential / fraud signals.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

_LLM_PHRASES = (
    "as an ai language model", "i cannot", "certainly!", "as previously mentioned",
    "in conclusion,", "furthermore,", "moreover,", "however, it is important to note",
    "i hope this message finds you well",
)
_PROMPT_LEAK = re.compile(
    r"(system prompt|you are a helpful assistant|ignore previous instructions)",
    re.I,
)


def _shannon_entropy(text: str) -> float:
    text = text[:5000]
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class AIGeneratedDetector:
    def analyze(self, subject: str | None, body: str | None) -> dict[str, Any]:
        text = (body or "")
        low = f"{subject or ''} {text}".lower()
        flags: list[str] = []
        score = 0.0

        hits = sum(1 for p in _LLM_PHRASES if p in low)
        if hits:
            flags.append(f"llm_phrases:{hits}")
            score += min(30, hits * 12)

        if _PROMPT_LEAK.search(low):
            flags.append("prompt_leakage")
            score += 25

        # Very-uniform sentence lengths are common in LLM output.
        sentences = re.split(r"[\.!?]\s+", text[:4000])
        lens = [len(s) for s in sentences if s.strip()]
        if len(lens) >= 6:
            mean = sum(lens) / len(lens)
            var = sum((l - mean) ** 2 for l in lens) / len(lens)
            if mean > 40 and var < mean * 2:
                flags.append("uniform_sentence_length")
                score += 10

        entropy = _shannon_entropy(text)
        if text and 3.5 <= entropy <= 4.5:
            flags.append("moderate_entropy")

        confidence = round(min(1.0, score / 60.0), 3)
        return {
            "flags": flags,
            "score": min(40.0, score),
            "confidence_ai_generated": confidence,
            "entropy": round(entropy, 3),
        }


ai_generated_detector = AIGeneratedDetector()
