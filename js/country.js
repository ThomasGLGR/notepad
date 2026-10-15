"use strict";
// Manual country entry only: no lookup service and no inference from an address or a domain.
globalThis.SOCCountry = (() => {
  // ISO 3166-1 alpha-2, plus XK (Kosovo), a user-assigned code common in geo fields.
  const CODES = new Set(("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ " +
    "CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR " +
    "GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP " +
    "KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ " +
    "NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW " +
    "SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ " +
    "UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW XK").split(" "));
  // Usual names that differ from the French and English display names supplied by the browser.
  const ALIASES = Object.freeze({
    uk: "GB", "great britain": "GB", britain: "GB", england: "GB", "grande bretagne": "GB", angleterre: "GB",
    usa: "US", america: "US", "united states of america": "US", "etats unis d amerique": "US",
    holland: "NL", hollande: "NL", "the netherlands": "NL", nederland: "NL",
    "russian federation": "RU", "federation de russie": "RU", korea: "KR", "republic of korea": "KR", dprk: "KP",
    "czech republic": "CZ", "republique tcheque": "CZ", turkey: "TR", "ivory coast": "CI", "viet nam": "VN",
    "islamic republic of iran": "IR", macedonia: "MK", macedoine: "MK", burma: "MM", birmanie: "MM", myanmar: "MM",
    "hong kong": "HK", macau: "MO", macao: "MO", palestine: "PS", uae: "AE", emirates: "AE", swaziland: "SZ",
    "cape verde": "CV", drc: "CD", rdc: "CD", bosnia: "BA", bosnie: "BA", vatican: "VA",
    deutschland: "DE", espana: "ES", italia: "IT", belgie: "BE", schweiz: "CH", brasil: "BR"
  });
  const MAX_LENGTH = 64;
  const INDICATORS = /[\u{1F1E6}-\u{1F1FF}]/gu;
  const fold = text => text.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
  let names = null;
  function nameIndex() {
    if (names) return names;
    names = new Map();
    for (const locale of ["fr", "en"]) {
      try {
        const display = new Intl.DisplayNames([locale], { type: "region" });
        for (const code of CODES) {
          const key = fold(display.of(code) || "");
          if (key && key !== code.toLowerCase() && !names.has(key)) names.set(key, code);
        }
      } catch { /* Codes and aliases still work without localized names. */ }
    }
    return names;
  }
  // Regional Indicator symbols only: no image, font or network dependency.
  const flag = code => CODES.has(code) ? String.fromCodePoint(...Array.from(code, letter => 0x1F1E6 + letter.charCodeAt(0) - 65)) : "";
  function code(input) {
    if (typeof input !== "string") return null;
    const symbols = input.match(INDICATORS) || [];
    let text = input.replace(INDICATORS, "").trim();
    // A pasted flag on its own is as explicit as its two letters.
    if (!text && symbols.length === 2) text = symbols.map(symbol => String.fromCharCode(symbol.codePointAt(0) - 0x1F1E6 + 65)).join("");
    if (/^[a-z]{2}$/i.test(text) && CODES.has(text.toUpperCase())) return text.toUpperCase();
    const key = fold(text);
    if (!key) return null;
    return Object.hasOwn(ALIASES, key) ? ALIASES[key] : nameIndex().get(key) || null;
  }
  // Stored form: the ISO code when recognized, otherwise the analyst's own text.
  function normalize(input) {
    if (typeof input !== "string") return "";
    return code(input) || input.replace(INDICATORS, "").replace(/\s+/g, " ").trim().slice(0, MAX_LENGTH);
  }
  const display = value => CODES.has(value) ? value + " " + flag(value) : value || "";
  function name(value, locale) {
    if (!CODES.has(value)) return "";
    try { return new Intl.DisplayNames(locale ? [locale, "en"] : ["en"], { type: "region" }).of(value) || ""; } catch { return ""; }
  }
  const isCode = value => CODES.has(value);
  return Object.freeze({ code, flag, normalize, display, name, isCode, MAX_LENGTH });
})();
if (typeof window !== "undefined" && window.SOCNote) window.SOCNote.country = globalThis.SOCCountry;
if (typeof module !== "undefined") module.exports = globalThis.SOCCountry;
