const FEATURES = ["url_len", "num_dots", "num_hyphens", "num_digits", "has_at", "has_ip", "num_subdomains", "susp_words", "is_https", "path_len"];
const MEAN = [45.262, 1.788, 1.326, 0.984, 0.074, 0.075, 0.638, 1.683, 0.708, 16.398];
const SCALE = [12.263904598454756, 0.8019077253649572, 1.3415379234296687, 2.6316808317119365, 0.26177089219391914, 0.2633913438213186, 0.7462948478986029, 1.9428100782114457, 0.45468230667137105, 5.533678342657812];
const COEF = [2.8804430281175195, -0.4124129219071222, 1.6131215907487593, 0.5453721537406567, 0.25967227160405976, 1.3836594531675366, -1.4198208075842942, 3.0542005481585957, -0.9183872816127333, -0.800181336643251];
const INTERCEPT = 0.7592452233833575;
const SUSP_WORDS = ["login", "verify", "secure", "update", "account", "free", "bank", "password", "confirm", "suspend", "prize", "winner", "urgent", "unlock", "gift"];
function extractFeatures(url) {
  const u = url.toLowerCase();
  const isHttps = u.startsWith("https://") ? 1 : 0;
  const rest = u.includes("://") ? u.split("://")[1] : u;
  const host = rest.split(/[/?#]/)[0];
  const path = rest.slice(host.length);
  const hasIp = /^\d+\.\d+\.\d+\.\d+$/.test(host) ? 1 : 0;
  const parts = host.split(".");
  const numSub = hasIp ? 0 : Math.max(0, parts.length - 2);
  let susp = 0;
  SUSP_WORDS.forEach(w => { susp += u.split(w).length - 1; });
  const digits = (u.match(/[0-9]/g) || []).length;
  return [u.length, (u.match(/\./g) || []).length, (u.match(/-/g) || []).length,
    digits, u.includes("@") ? 1 : 0, hasIp, numSub, susp, isHttps, path.length];
}
function phishProb(url) {
  const x = extractFeatures(url);
  let z = INTERCEPT;
  const contrib = [];
  for (let i = 0; i < 10; i++) {
    const s = (x[i] - MEAN[i]) / SCALE[i];
    z += s * COEF[i];
    contrib.push({name: FEATURES[i], value: x[i], c: s * COEF[i]});
  }
  const p = 1 / (1 + Math.exp(-z));
  return {prob: p * 100, contrib: contrib, feats: x};
}
console.log(JSON.stringify({url: "https://www.google.com/search?q=laptop", js: phishProb("https://www.google.com/search?q=laptop").prob / 100, py: 0.0007551124896867948}));
console.log(JSON.stringify({url: "https://github.com/HVRGAMING2705/moodlens", js: phishProb("https://github.com/HVRGAMING2705/moodlens").prob / 100, py: 0.014066793825189975}));
console.log(JSON.stringify({url: "https://secure-login-verify.com/login/verify", js: phishProb("https://secure-login-verify.com/login/verify").prob / 100, py: 0.9993494747600605}));
console.log(JSON.stringify({url: "http://185.23.44.19/login/verify", js: phishProb("http://185.23.44.19/login/verify").prob / 100, py: 0.9959588949402572}));
console.log(JSON.stringify({url: "http://google.com@free-gift-card-claim.xyz/free/prize/claim", js: phishProb("http://google.com@free-gift-card-claim.xyz/free/prize/claim").prob / 100, py: 0.9999726612633681}));
console.log(JSON.stringify({url: "https://login.secure.verify.paypal-secure-update.net/secure/update/account", js: phishProb("https://login.secure.verify.paypal-secure-update.net/secure/update/account").prob / 100, py: 0.9999737447953174}));
console.log(JSON.stringify({url: "https://www.amazon.in/products/12345", js: phishProb("https://www.amazon.in/products/12345").prob / 100, py: 0.0015362666576960568}));
