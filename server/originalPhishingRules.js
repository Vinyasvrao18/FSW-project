const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'account', 'secure', 'banking', 'update', 'wallet',
  'paypal', 'signin', 'support', 'recover', 'free', 'bonus'
];

const SUSPICIOUS_TOP_LEVEL_DOMAINS = ['.xyz', '.top', '.zip', '.click', '.country', '.work', '.kim'];

function analyzeOriginalPhishingRules(url, parsed) {
  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();

  let riskScore = 0;
  const findings = [];

  // 1. IP address hostname check
  const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  if (isIpHost) {
    riskScore += 35;
    findings.push({ rule: 'IP_ADDRESS_AS_HOST', severity: 'HIGH', message: 'Uses raw IP address instead of domain name' });
  }

  // 2. Protocol check
  if (parsed.protocol === 'http:') {
    riskScore += 20;
    findings.push({ rule: 'INSECURE_PROTOCOL', severity: 'MEDIUM', message: 'Insecure plain HTTP protocol' });
  }

  // 3. Excessive subdomains
  const subdomainCount = hostname.split('.').length - 2;
  if (subdomainCount >= 3) {
    riskScore += 25;
    findings.push({ rule: 'EXCESSIVE_SUBDOMAINS', severity: 'HIGH', message: `Multiple deep subdomains detected (${subdomainCount})` });
  }

  // 4. Suspicious TLD
  const matchedTopLevelDomain = SUSPICIOUS_TOP_LEVEL_DOMAINS.find(topLevelDomain => hostname.endsWith(topLevelDomain));
  if (matchedTopLevelDomain) {
    riskScore += 20;
    findings.push({ rule: 'SUSPICIOUS_TLD', severity: 'MEDIUM', message: `High-risk top-level domain: ${matchedTopLevelDomain}` });
  }

  // 5. Sensitive brand/auth keywords in path or subdomain
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(keyword => hostname.includes(keyword) || pathname.includes(keyword));
  if (matchedKeywords.length > 0) {
    riskScore += 15 * Math.min(matchedKeywords.length, 2);
    findings.push({ rule: 'CREDENTIAL_KEYWORD', severity: 'MEDIUM', message: `Target contains credential/security keywords: ${matchedKeywords.join(', ')}` });
  }

  // 6. Excessive length or @ symbol
  if (url.includes('@')) {
    riskScore += 30;
    findings.push({ rule: 'EMBEDDED_CREDENTIALS', severity: 'HIGH', message: 'Contains "@" symbol which can obfuscate host authority' });
  }
  if (url.length > 100) {
    riskScore += 10;
    findings.push({ rule: 'LONG_URL', severity: 'LOW', message: 'Abnormally long URL length' });
  }

  // Normalize risk score to 0 - 100
  riskScore = Math.min(riskScore, 100);
  const classification = riskScore >= 60 ? 'HIGH_RISK' : riskScore >= 30 ? 'SUSPICIOUS' : 'SAFE';

  return { url, riskScore, classification, findings };
}

module.exports = analyzeOriginalPhishingRules;
