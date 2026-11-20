"""The two categories ONAA refuses outright in listings, wants and answers to wants (founder, 2026-11-19): illegal
drugs, and firearms (with ammunition, gun parts and explosives). Everything else is report and takedown
(routes/pilot_reports.py), because what is legal differs by country.

Matching is deliberately narrow, to keep false positives low: specific drug and firearm names only, never bare
words like "gun", "drug" or "bullet", and toy or tool phrases ("water gun", "glue gun", "air rifle", "drug store",
"bullet journal", Korean "마약" food and product names) never match. Reports catch what this misses.
"""

from __future__ import annotations

import re
import unicodedata

_DRUGS = (
    r"cocaine", r"crack\s+cocaine", r"heroin", r"fentanyl", r"methamphetamine", r"crystal\s+meth",
    r"mdma", r"molly\s+pills?", r"ecstasy\s+(pills?|tabs?)", r"lsd", r"acid\s+tabs?", r"ketamine", r"psilocybin",
    r"magic\s+mushrooms?", r"shrooms", r"oxycodone", r"oxycontin", r"percocet", r"xanax", r"adderall", r"vicodin",
    r"hydrocodone", r"codeine\s+syrup", r"lean\s+syrup", r"dmt", r"ghb",
    r"cannabis", r"marijuana", r"marihuana", r"meth", r"thc\s+(carts?|cartridges?|vapes?|gumm(y|ies)|edibles?|oil)",
    r"weed(s|z)?(?!\s+(killers?|eaters?|whackers?|wackers?|trimmers?|barriers?|control|block"
    r"|preventers?|pullers?|torch(es)?|fabric|mats?|cutters?))",
    "필로폰", "히로뽕", "코카인", "헤로인", "펜타닐", "엑스터시", "대마초", "마리화나", "메스암페타민",
)
_FIREARMS = (
    r"firearms?", r"handguns?", r"shotguns?", r"assault\s+rifles?", r"sniper\s+rifles?",
    r"hunting\s+rifles?", r"semi[-\s]?auto(matic)?\s+(rifle|pistol)s?", r"machine\s+guns?", r"ghost\s+guns?",
    r"ar[-\s]?15s?", r"ak[-\s]?47s?", r"glock\s*\d*", r"9\s?mm\s+(pistol|handgun|ammo)",
    r"\.?(22|223|308|45)\s+(cal|caliber|ammo)",
    r"ammunition", r"ammo", r"live\s+rounds", r"gun\s+powder", r"gunpowder", r"lower\s+receivers?",
    r"(suppressors?|silencers?)\s+for\s+(a\s+)?(gun|pistol|rifle)s?", r"bump\s+stocks?", r"pipe\s+bombs?",
    r"hand\s+grenades?", r"grenades?", r"dynamite", r"tnt\s+(explosives?|sticks?|blocks?)",
    r"c-?4\s+(explosives?|charges?|blocks?)", r"plastic\s+explosives?", r"semtex", r"detonators?", r"blasting\s+caps?",
    r"explosives", r"gun\s+suppressors?",
    r"(?<!water\s)(?<!squirt\s)(?<!toy\s)(?<!spray\s)(?<!nerf\s)(?<!air\s)(?<!bb\s)(?<!cap\s)(?<!paint\s)"
    r"(?<!caulk\s)(?<!bubble\s)(?<!nozzle\s)pistols?(?!\s+(grip|nozzle|sprayer))",
    r"(?<!air\s)(?<!bb\s)(?<!pellet\s)(?<!toy\s)(?<!nerf\s)(?<!airsoft\s)rifles?(?!\s+(paper|scope))",
    "총기", "권총", "소총", "엽총", "실탄", "탄약", "폭발물", "수류탄", "다이너마이트", "뇌관",
)
_TOY = r"(airsoft|toy|nerf|bb|gel[-\s]?blaster|water|paintball)"
_GUN_NAMES = (r"(guns?|pistols?|rifles?|shotguns?|handguns?|grenades?|ak[-\s]?47s?|ar[-\s]?15s?|glock\s*\d*"
              r"|m4a?1?s?|m16s?|uzis?|desert\s+eagles?)")
_ALLOWED = re.compile(
    r"\b(water|squirt|toy|nerf|glue|heat|nail|staple|spray|massage|bubble|laser\s+tag|foam|dart|airsoft|paintball|cap)"
    r"\s+(guns?|pistols?|rifles?)\b|\bdrug\s*stores?\b|\bshotgun\s+mic(rophone)?s?\b|\bammo\s+(cans?|boxe?s?)\b"
    # A toy word right before or after a gun name (up to two words between): "AK-47 airsoft", "airsoft M4 rifle",
    # "toy Glock 17", "BB ammo". Founder decision 2026-11-19: toys and replicas for play are allowed.
    rf"|\b{_TOY}\s+(\S+\s+){{0,2}}?{_GUN_NAMES}(\s+{_GUN_NAMES})*(?![\w-])"
    rf"|\b{_GUN_NAMES}\s+(\S+\s+){{0,2}}?{_TOY}(\s+{_GUN_NAMES})*(?![\w-])"
    r"|\b(airsoft|bb|nerf|paintball|gel)\s+(ammo|ammunition|grenades?)\b|\bgrenade\s+(protein|bars?|carb)"
    r"|(장난감|비비탄|에어소프트|에어건|모형|물)\s*(권총|소총|총|수류탄)|(권총|소총|총)\s*(장난감|모형)",
    re.I)


def _rx(words: tuple[str, ...]) -> re.Pattern[str]:
    latin = [w for w in words if w.isascii()]
    other = [w for w in words if not w.isascii()]
    parts = [r"(?<![\w-])(?:" + "|".join(latin) + r")(?![\w-])"]
    if other:
        parts.append("|".join(re.escape(w) for w in other))
    return re.compile("|".join(parts), re.I)


_RX = {"illegal drugs": _rx(_DRUGS), "firearms, ammunition or explosives": _rx(_FIREARMS)}


def _normalize(text: str) -> str:
    """What a reader sees: fullwidth and other compatibility forms folded (NFKC), line breaks as spaces, and invisible
    characters (other control and zero-width format characters) dropped, since stored text drops them too. Without
    this, "Coc\\x07aine" or a zero-width space inside a word passed the check and was then stored readable."""
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"[\t\n\r\v\f]", " ", text)
    return "".join(ch for ch in text if unicodedata.category(ch) not in ("Cc", "Cf"))


def check(*texts: str | None) -> str | None:
    """The banned category the text names (None when it is fine)."""
    text = _ALLOWED.sub(" ", _normalize(" ".join(t for t in texts if t)))
    for name, rx in _RX.items():
        if rx.search(text):
            return name
    return None


MESSAGE = ("ONAA does not allow {what} in listings or wants, anywhere. Do not try to reword it to get around this. "
           "If this is something else (for example a toy or a book), describe it plainly.")
