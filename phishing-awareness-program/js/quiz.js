/* ============================================================
   quiz.js — question bank for the final knowledge check.
   Each item: question, options[], answer index, explanation.
   ============================================================ */

const QUIZ = [
  {
    q: "An email from your bank says: “Dear Customer, verify your account within 24 hours or it will be closed.” What is the biggest warning sign?",
    options: [
      "It uses a generic greeting and manufactured urgency",
      "Banks never send email at all",
      "The email is too short",
      "It was sent in the afternoon",
    ],
    answer: 0,
    explain: "A generic greeting plus a tight deadline is the classic phishing combination: they don’t know your name and they want you to panic.",
  },
  {
    q: "You hover over a link and the status bar shows https://accounts.google.com.secure-login.ru/verify. Who really owns this site?",
    options: [
      "Google (accounts.google.com)",
      "secure-login.ru",
      "verify.com",
      "Nobody, it’s encrypted",
    ],
    answer: 1,
    explain: "Read the domain right-to-left from the first single slash. The owner is the last two labels before it: secure-login.ru. Everything before is decoration.",
  },
  {
    q: "A website shows a padlock and https:// in the address bar. This proves the site is:",
    options: [
      "Safe and run by a legitimate company",
      "Only that the connection is encrypted, not that the owner is honest",
      "Approved by your bank",
      "Free of all malware",
    ],
    answer: 1,
    explain: "HTTPS and the padlock only mean the traffic is encrypted. Anyone, including criminals, can get a free certificate. It says nothing about trustworthiness.",
  },
  {
    q: "Which of these domains is the safe, genuine one?",
    options: [ "paypa1.com", "secure-paypal-login.com", "paypal.com", "paypal.com.account-verify.net" ],
    answer: 2,
    explain: "paypal.com is exact with no extra words, numbers, or subdomains bolted on. The others are typosquats or subdomain tricks.",
  },
  {
    q: "Your “CEO” emails asking you to urgently buy gift cards and send the codes, keeping it confidential. You should:",
    options: [
      "Buy them quickly to help the CEO",
      "Reply to the email asking for confirmation",
      "Verify by phone or in person using a number you already have",
      "Forward it to all colleagues",
    ],
    answer: 2,
    explain: "Gift-card and secrecy requests are a hallmark of CEO fraud. Confirm through a channel you already trust, never by replying to the suspicious email.",
  },
  {
    q: "Which social-engineering lever is being pulled by “You’ve won a $1,000 gift card, click to claim”?",
    options: [ "Authority", "Greed and reward", "Helpfulness", "Familiarity" ],
    answer: 1,
    explain: "A prize you never entered for exploits greed. If it seems too good to be true, it is.",
  },
  {
    q: "You receive an unexpected email with an attachment named Invoice.html. The safest action is:",
    options: [
      "Open it to see what the invoice is for",
      "Do not open it and verify with the supposed sender first",
      "Enable macros if it asks you to",
      "Forward it to a friend to open",
    ],
    answer: 1,
    explain: "HTML attachments often open a fake login form to steal your password. Never open unexpected attachments; verify with the sender through a known channel.",
  },
  {
    q: "What is the single best protection if your password does get stolen in a phishing attack?",
    options: [
      "A longer password",
      "Multi-factor authentication (MFA)",
      "Changing your password every week",
      "Using the same password everywhere so you remember it",
    ],
    answer: 1,
    explain: "MFA requires a second factor the attacker doesn’t have, so a stolen password alone won’t let them in. It blocks the large majority of account takeovers.",
  },
  {
    q: "A password manager can help spot fake login pages because it:",
    options: [
      "Emails you a warning",
      "Won’t autofill your credentials on a look-alike domain",
      "Blocks the whole website",
      "Calls your bank automatically",
    ],
    answer: 1,
    explain: "A password manager matches the exact domain. If it doesn’t offer to fill in your login, you may be on a fake site, a quiet but powerful warning.",
  },
  {
    q: "You clicked a phishing link and entered your password before realising. What should you do FIRST?",
    options: [
      "Nothing, hope for the best",
      "Change that password immediately from a trusted device and enable MFA, then report it",
      "Wait a week to see if anything happens",
      "Only tell IT if money goes missing",
    ],
    answer: 1,
    explain: "Act fast: change the password from a device you trust, turn on MFA, and report it. Quick reporting limits the damage, and you won’t be blamed for speaking up.",
  },
];
