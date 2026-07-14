/* ============================================================
   content.js — all educational data for the training module.
   Kept separate from behaviour so copy is easy to edit.
   ============================================================ */

/* Red flags in the sample phishing email (module 02). The `flag`
   key matches the data-flag attribute on each highlighted span. */
const EMAIL_FLAGS = {
  sender: {
    title: "Look-alike sender address",
    text: "The display name says “PayPal” but the real address is paypa1-support.com (a number 1 in place of the L). Attackers spoof trusted names while the true domain gives them away.",
  },
  recipient: {
    title: "You are not the named recipient",
    text: "Legitimate companies address you directly. “undisclosed-recipients” means the same message was blasted to thousands of people at once.",
  },
  subject: {
    title: "Alarming, ALL-CAPS subject",
    text: "Manufactured urgency in the subject line is designed to make you react before you think. Real security notices are calm and specific.",
  },
  greeting: {
    title: "Generic greeting",
    text: "“Dear Valued Customer” shows they do not actually know your name. Your bank and PayPal address you by the name on your account.",
  },
  pretext: {
    title: "Vague pretext",
    text: "“Unusual activity” with no details is a classic hook. It sounds scary but commits to nothing that could be fact-checked.",
  },
  urgency: {
    title: "Artificial deadline",
    text: "“Within 24 hours or your account is closed” pressures you to skip your normal caution. Deadlines like this are a hallmark of fraud.",
  },
  link: {
    title: "Deceptive call-to-action button",
    text: "The button hides its true destination. Hovering would reveal a domain that has nothing to do with PayPal. Never click; go to the site yourself.",
  },
  grammar: {
    title: "Spelling and grammar mistakes",
    text: "“will results” and “you're account” are errors a real corporate email would not ship. Sloppy language is a strong warning sign.",
  },
  attachment: {
    title: "Unexpected .html attachment",
    text: "An HTML attachment often opens a local fake login form that steals your password. Unexpected attachments, especially .html, .zip or .exe, should never be opened.",
  },
};

/* Domain-spotting mini game (module 04). */
const DOMAIN_ROUNDS = [
  { url: "paypal.com", safe: true,  note: "The genuine PayPal domain. Clean, exact, no extras." },
  { url: "paypa1.com", safe: false, note: "The L is a number 1. A classic typosquat." },
  { url: "secure-paypal-login.com", safe: false, note: "Extra words and hyphens. PayPal never owns domains like this." },
  { url: "apple.com.icloud-verify.net", safe: false, note: "The real owner is icloud-verify.net. Everything before the last dot is a decoy." },
  { url: "microsoft.com", safe: true,  note: "Legitimate. The owner is the last two labels: microsoft.com." },
  { url: "arnazon.com", safe: false, note: "“rn” looks like “m” at a glance. It reads amazon but it is not." },
  { url: "accounts.google.com", safe: true,  note: "Genuine. google.com is the owner; accounts is just a subdomain." },
  { url: "netflix-billing.info", safe: false, note: "Wrong domain and an unusual .info TLD. Netflix uses netflix.com." },
];

/* Social-engineering tactics (module 05). */
const TACTICS = [
  {
    icon: "⏰", name: "Urgency & Fear",
    play: "“Act now or your account will be suspended.” A ticking clock stops you from thinking clearly.",
    defence: "Slow down. Real emergencies survive a two-minute pause to verify. Urgency itself is the red flag.",
  },
  {
    icon: "👔", name: "Authority",
    play: "The message impersonates your CEO, IT department, the bank, or the police to borrow their power.",
    defence: "Confirm through a known channel. Call the person back on a number you already have, not one in the message.",
  },
  {
    icon: "🎁", name: "Greed & Reward",
    play: "“You’ve won!” or “Claim your refund.” A prize you didn’t enter for is bait on a hook.",
    defence: "If it seems too good to be true, it is. Never pay a fee or share details to release a “prize”.",
  },
  {
    icon: "🤝", name: "Trust & Familiarity",
    play: "Attackers name-drop a colleague, a real project, or a brand you use so the request feels normal.",
    defence: "Familiarity is easy to fake with public information. Verify the request, not just the sender’s name.",
  },
  {
    icon: "😟", name: "Curiosity",
    play: "“See who viewed your profile” or a mystery invoice tempts you to click just to find out.",
    defence: "Curiosity is a weapon. If you didn’t expect it, don’t open it. Go to the source directly.",
  },
  {
    icon: "🙏", name: "Helpfulness",
    play: "“I’m stuck and need this favour urgently.” Most people want to help, so attackers ask for one.",
    defence: "It is fine to verify before helping. A genuine colleague will understand a quick confirmation call.",
  },
];

/* Practical security tips (module 06). */
const TIPS = [
  { h: "Stop and think before you click", s: "Hover over every link to preview its real destination. When unsure, type the address yourself or use a bookmark." },
  { h: "Turn on multi-factor authentication (MFA)", s: "Even if your password is stolen, MFA blocks most account takeovers. Prefer an authenticator app or hardware key over SMS." },
  { h: "Use a password manager", s: "It creates unique passwords and, crucially, will refuse to autofill on a look-alike phishing domain." },
  { h: "Verify unusual requests out of band", s: "Money, gift cards, or credentials? Confirm by phone or in person using contact details you already trust." },
  { h: "Never reuse passwords", s: "One breached site should not unlock the rest of your life. Unique passwords contain the damage." },
  { h: "Keep software and browsers updated", s: "Updates patch the holes that malicious links and attachments try to exploit." },
  { h: "Be wary of attachments", s: "Do not open unexpected files, especially .html, .zip, .exe, or documents that demand you “enable macros”." },
  { h: "Check the real sender address", s: "Expand the display name to see the true email address. A trusted name with a strange domain is a fake." },
  { h: "Report, don’t just delete", s: "Reporting a phish helps your security team warn everyone else and block the campaign." },
];

/* Real-world case studies (module 07). */
const CASES = [
  {
    title: "The $100M invoice scam", year: "2013–2015", tag: "Business Email Compromise",
    loss: "≈ $100M",
    body: "A Lithuanian man posed as a hardware supplier and sent Google and Facebook fake invoices over two years. Believing the emails were from a real vendor, staff wired more than $100 million before the fraud was noticed.",
    lesson: "Even the biggest tech companies fall for well-researched invoice fraud. Verify payment changes through a second channel.",
  },
  {
    title: "The Twitter Bitcoin takeover", year: "2020", tag: "Vishing (phone phishing)",
    loss: "130 accounts",
    body: "Attackers phoned Twitter employees pretending to be IT support and talked them into entering credentials on a fake VPN page. With that access they hijacked 130 high-profile accounts, including those of public figures, to run a Bitcoin scam.",
    lesson: "Phishing isn’t only email. A convincing phone call plus a fake login page is enough. Verify support requests.",
  },
  {
    title: "The RSA SecurID breach", year: "2011", tag: "Spear phishing + attachment",
    loss: "≈ $66M cleanup",
    body: "Employees received an email titled “2011 Recruitment Plan” with a spreadsheet attachment. A single person opened it, running hidden code that ultimately compromised RSA’s prized SecurID tokens.",
    lesson: "One click on one attachment can breach a security company. Treat unexpected files with suspicion.",
  },
  {
    title: "The Colonial Pipeline shutdown", year: "2021", tag: "Stolen credentials",
    loss: "$4.4M ransom",
    body: "Attackers got in using a single leaked password for an old VPN account that lacked MFA, then deployed ransomware that shut down fuel supply to much of the US East Coast for days.",
    lesson: "Unused accounts and missing MFA are open doors. Retire old logins and protect every remaining one.",
  },
];
