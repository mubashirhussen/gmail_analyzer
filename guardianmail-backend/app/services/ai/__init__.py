"""AI Analysis Engine (Module 6).

Consumes structured `ThreatReport` documents (Module 5) and produces
explainable `AIReport` decisions. The engine never touches raw email
bodies or Gmail payloads — Module 5 is the single source of truth for
signal, and this module reasons on top of it.
"""
