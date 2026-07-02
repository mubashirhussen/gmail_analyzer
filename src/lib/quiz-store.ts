// Local, per-account quiz score history. Not encrypted — no sensitive data.

export type QuizAttempt = {
  id: string;
  at: number;
  score: number; // 0..total
  total: number;
  mode: "quiz" | "simulator";
};

const KEY = (uid: string) => `mg.quiz.v1.${uid}`;

function ls(): Storage | null {
  if (typeof window === "undefined") return null;
  return window.localStorage;
}

export function loadAttempts(uid: string): QuizAttempt[] {
  try {
    return JSON.parse(ls()?.getItem(KEY(uid)) || "[]") as QuizAttempt[];
  } catch { return []; }
}

export function saveAttempt(uid: string, a: QuizAttempt) {
  const list = loadAttempts(uid);
  list.unshift(a);
  ls()?.setItem(KEY(uid), JSON.stringify(list.slice(0, 50)));
}

export function clearAttempts(uid: string) {
  ls()?.removeItem(KEY(uid));
}

export type QuizQuestion = {
  id: string;
  scenario: string;
  choices: { key: "safe" | "suspicious" | "phishing" | "fraud"; label: string }[];
  answer: "safe" | "suspicious" | "phishing" | "fraud";
  explain: string;
  category: string;
};

// 12 India-flavoured, real-world social-engineering scenarios.
export const QUIZ_BANK: QuizQuestion[] = [
  {
    id: "q1",
    category: "UPI fraud",
    scenario: "You get a WhatsApp message: \"Sir I sent ₹5000 by mistake, please approve the collect request in your GPay to return it.\" A UPI request appears in your GPay.",
    choices: [
      { key: "safe", label: "Approve — they must have made a genuine mistake." },
      { key: "suspicious", label: "Approve but reduce the amount." },
      { key: "fraud", label: "Reject. UPI PIN is only for PAYING, never receiving." },
      { key: "phishing", label: "Call the sender back on the number in the message." },
    ],
    answer: "fraud",
    explain: "This is the classic 'wrong UPI' scam. Receiving money never needs your PIN. Approving a collect request PAYS them.",
  },
  {
    id: "q2",
    category: "Impersonation",
    scenario: "Email from security-alert@paypa1-support.com: \"Your account will be suspended in 24 hours. Verify at http://paypa1-verify.secure-login.ru/confirm\"",
    choices: [
      { key: "safe", label: "Click and log in to save the account." },
      { key: "phishing", label: "Delete — the domain is spoofed (paypa1, .ru host)." },
      { key: "suspicious", label: "Reply asking if the mail is genuine." },
      { key: "fraud", label: "Forward to friends as a warning by clicking it first." },
    ],
    answer: "phishing",
    explain: "'paypa1' with a numeral 1 and a .ru host is a spoofed domain designed to steal credentials.",
  },
  {
    id: "q3",
    category: "Courier scam",
    scenario: "SMS: \"India Post: your parcel is held. Pay ₹25 customs fee: https://indiapost-fee.top/pay\"",
    choices: [
      { key: "safe", label: "Pay — the fee is tiny." },
      { key: "phishing", label: "Ignore. Real India Post never charges via SMS links." },
      { key: "suspicious", label: "Open the link but don't pay." },
      { key: "fraud", label: "Call the number in the SMS." },
    ],
    answer: "phishing",
    explain: "India Post/BlueDart/DHL never collect small 'customs fees' via SMS. The .top TLD and lookalike domain confirm the scam.",
  },
  {
    id: "q4",
    category: "Job scam",
    scenario: "Telegram DM: \"Earn ₹3,000/day by rating hotels. Free training. Send ₹500 refundable deposit to start.\"",
    choices: [
      { key: "safe", label: "Try it — refund is promised." },
      { key: "fraud", label: "Block. Any 'job' asking you to pay first is a scam." },
      { key: "suspicious", label: "Ask for a contract." },
      { key: "phishing", label: "Send a smaller amount to test." },
    ],
    answer: "fraud",
    explain: "Task-based investment scams start with tiny 'earnings' to build trust, then vanish with your larger deposits.",
  },
  {
    id: "q5",
    category: "BEC",
    scenario: "Your CEO emails from ceo.company@gmail.com: \"Urgent — buy 5 Amazon vouchers of ₹10,000, send the codes. I'm in a meeting, don't call.\"",
    choices: [
      { key: "safe", label: "Buy them — CEO said urgent." },
      { key: "phishing", label: "Verify in person or on a known number. Real CEO won't use Gmail or forbid calls." },
      { key: "suspicious", label: "Reply asking for confirmation." },
      { key: "fraud", label: "Buy one voucher first to check." },
    ],
    answer: "phishing",
    explain: "Business Email Compromise (BEC) always uses urgency + a channel that blocks verification. Never act on gift-card requests without out-of-band confirmation.",
  },
  {
    id: "q6",
    category: "KYC scam",
    scenario: "Call: \"I'm from RBI. Your PAN is not linked to Aadhaar, your accounts will be frozen. Share the OTP I just sent to complete e-KYC.\"",
    choices: [
      { key: "safe", label: "Share OTP — it's the RBI." },
      { key: "fraud", label: "Hang up. RBI and banks NEVER ask for OTP." },
      { key: "suspicious", label: "Give a wrong OTP to test." },
      { key: "phishing", label: "Ask them to email details." },
    ],
    answer: "fraud",
    explain: "RBI, banks, income-tax, and UIDAI never ask for OTP/PIN/CVV. Sharing OTP hands over your account.",
  },
  {
    id: "q7",
    category: "Investment scam",
    scenario: "WhatsApp group adds you: \"Premium stock tips, guaranteed 40% returns weekly. Deposit via this crypto wallet.\"",
    choices: [
      { key: "safe", label: "Small deposit to try." },
      { key: "fraud", label: "Leave and report. No legitimate broker guarantees returns via crypto." },
      { key: "suspicious", label: "Ask them for SEBI registration." },
      { key: "phishing", label: "Screenshot and forward to friends." },
    ],
    answer: "fraud",
    explain: "SEBI-registered advisors never solicit via WhatsApp or promise fixed returns. Crypto-only deposits are untraceable.",
  },
  {
    id: "q8",
    category: "Credential harvest",
    scenario: "You click a Google Docs link and it opens a page that looks exactly like Google Sign-In but the URL is docs-google.verify-app.com.",
    choices: [
      { key: "safe", label: "Log in — page looks correct." },
      { key: "phishing", label: "Close it. Real Google URL is accounts.google.com." },
      { key: "suspicious", label: "Enter fake credentials." },
      { key: "fraud", label: "Try with a burner account." },
    ],
    answer: "phishing",
    explain: "The 'brand name in subdomain' trick. The real domain is verify-app.com — Google is just in the subdomain.",
  },
  {
    id: "q9",
    category: "Romance / relative distress",
    scenario: "Voice-note in your mother's voice on WhatsApp from an unknown number: \"Beta I'm in trouble, send ₹20,000 to this UPI immediately.\"",
    choices: [
      { key: "safe", label: "Send — it's her voice." },
      { key: "fraud", label: "Call her on her known number first. AI voice-cloning scams are on the rise." },
      { key: "suspicious", label: "Send half the amount." },
      { key: "phishing", label: "Reply on the same number." },
    ],
    answer: "fraud",
    explain: "AI can clone a voice from 30 seconds of audio. Always verify on the person's known number before sending money.",
  },
  {
    id: "q10",
    category: "Malicious attachment",
    scenario: "HR email with attachment 'Salary_Revision.html' asking you to open it to see your new package.",
    choices: [
      { key: "safe", label: "Open — it's from HR." },
      { key: "phishing", label: "Don't open. .html attachments almost always redirect to credential-harvest pages." },
      { key: "suspicious", label: "Download but scan first." },
      { key: "fraud", label: "Forward to a colleague to open." },
    ],
    answer: "phishing",
    explain: "Real HR sends PDFs, not standalone .html files. HTML attachments render locally and steal credentials.",
  },
  {
    id: "q11",
    category: "Shortener / QR",
    scenario: "Poster at a cafe: \"Scan QR to WIN free coffee for 1 year.\" It opens bit.ly/free-cf-2024 which redirects to a payment page.",
    choices: [
      { key: "safe", label: "Pay ₹10 processing fee to claim." },
      { key: "fraud", label: "Close it. Real giveaways never charge and never redirect via shorteners." },
      { key: "suspicious", label: "Read the page terms." },
      { key: "phishing", label: "Enter card to test." },
    ],
    answer: "fraud",
    explain: "Shorteners hide the real destination. Any 'free prize' that ends at a payment page is a card-skimming scam.",
  },
  {
    id: "q12",
    category: "Tech support",
    scenario: "Popup on a shopping site: \"WARNING: Your PC is infected with 5 viruses. Call Microsoft support: +91-... immediately.\"",
    choices: [
      { key: "safe", label: "Call — better safe than sorry." },
      { key: "fraud", label: "Close the tab. Real Microsoft never puts a phone number on a warning popup." },
      { key: "suspicious", label: "Restart the PC first." },
      { key: "phishing", label: "Install the suggested cleaner." },
    ],
    answer: "fraud",
    explain: "Fake tech-support popups lead to remote-access scams. Close the tab; run your own antivirus if worried.",
  },
];
