"""Isolated, bounded media-analysis worker.

Like ``preview_worker``, this module has no ForensiX application imports. The parent
launches it in Python isolated mode with fixed arguments and a deadline. It reads a
single hash-verified sealed object and emits a small JSON document describing the
media: perceptual hash, an EXIF allowlist (capture time, camera, GPS), optional OCR
text, and heuristic content-classification labels. It never mutates the source and
never emits embedded blobs or thumbnails.
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path
from typing import Any

from PIL import ExifTags, Image, UnidentifiedImageError

WORKER_VERSION = "1.0.0"
MAX_SOURCE_BYTES = 25 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000
HEADER_BYTES = 64
MAX_EXIF_TAGS = 64
MAX_EXIF_VALUE_CHARS = 256
MAX_OCR_CHARS = 20_000
PHASH_EDGE = 9  # difference hash uses a (PHASH_EDGE-1) x (PHASH_EDGE-1) = 8x8 grid -> 64 bits.
SUPPORTED_RASTER_MIMES = frozenset({"image/gif", "image/jpeg", "image/png", "image/webp"})
SAFE_EXIF_TAGS = frozenset(
    {
        "DateTime",
        "DateTimeDigitized",
        "DateTimeOriginal",
        "ExposureTime",
        "FNumber",
        "FocalLength",
        "ISOSpeedRatings",
        "LensModel",
        "Make",
        "Model",
        "Orientation",
        "Software",
    }
)

Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
warnings.simplefilter("error", Image.DecompressionBombWarning)


class MediaAnalysisRejectedError(RuntimeError):
    """A stable, safe rejection intended for the parent process."""

    def __init__(self, code: str, message: str, *, detected_mime: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.detected_mime = detected_mime


def detect_mime(header: bytes) -> str:
    """Return a conservative MIME label from bounded magic bytes."""
    if header.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "image/webp"
    return "application/octet-stream"


def _bounded_scalar(value: Any) -> str | int | float | bool | None:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:MAX_EXIF_VALUE_CHARS]


def _gps_coordinate(values: Any, reference: Any) -> float | None:
    try:
        degrees, minutes, seconds = (float(item) for item in values[:3])
        coordinate = degrees + minutes / 60 + seconds / 3600
        if str(reference).upper() in {"S", "W"}:
            coordinate = -coordinate
        return round(coordinate, 5)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def extract_exif(image: Image.Image) -> dict[str, Any]:
    """Return a small JSON-safe EXIF allowlist plus GPS presence and coordinates."""
    result: dict[str, Any] = {"gps_present": False}
    try:
        exif = image.getexif()
    except (AttributeError, OSError, ValueError):
        return result
    safe_exif: dict[str, Any] = {}
    for tag_id, value in list(exif.items())[:MAX_EXIF_TAGS]:
        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
        if tag_name in SAFE_EXIF_TAGS:
            safe_exif[tag_name] = _bounded_scalar(value)
    if safe_exif:
        result["exif"] = safe_exif
        result["camera_make"] = safe_exif.get("Make")
        result["camera_model"] = safe_exif.get("Model")
        result["captured_at_raw"] = safe_exif.get("DateTimeOriginal") or safe_exif.get("DateTime")
    try:
        gps = exif.get_ifd(ExifTags.IFD.GPSInfo)
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        gps = {}
    if gps:
        latitude = _gps_coordinate(gps.get(2), gps.get(1))
        longitude = _gps_coordinate(gps.get(4), gps.get(3))
        result["gps_present"] = True
        if latitude is not None and longitude is not None:
            result["gps_latitude"] = latitude
            result["gps_longitude"] = longitude
    return result


def perceptual_hash(image: Image.Image) -> str:
    """Return a 64-bit difference hash as 16 lowercase hex characters.

    Difference hashing is orientation-agnostic to compression and small edits, so two
    near-identical images produce hashes with a small Hamming distance. It is a triage
    grouping aid, not a cryptographic identifier.
    """
    reduced = image.convert("L").resize((PHASH_EDGE, PHASH_EDGE - 1), Image.Resampling.LANCZOS)
    pixels = list(reduced.getdata())
    bits = 0
    index = 0
    for row in range(PHASH_EDGE - 1):
        row_start = row * PHASH_EDGE
        for col in range(PHASH_EDGE - 1):
            left = pixels[row_start + col]
            right = pixels[row_start + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
            index += 1
    return format(bits, f"0{index // 4}x")


def attempt_ocr(image: Image.Image) -> dict[str, Any]:
    """Attempt OCR only if a Tesseract engine is importable and installed.

    We never fabricate text. When no engine is present the status is ``unavailable``
    and no text is produced. This keeps the pipeline honest about its capabilities.
    """
    try:
        import pytesseract  # type: ignore[import-not-found]
    except Exception:
        return {"ocr_status": "unavailable", "ocr_engine": None, "ocr_text": None}
    try:
        text = pytesseract.image_to_string(image.convert("RGB"))
    except Exception:
        return {"ocr_status": "unavailable", "ocr_engine": "tesseract", "ocr_text": None}
    normalized = " ".join(text.split())[:MAX_OCR_CHARS]
    if not normalized:
        return {"ocr_status": "empty", "ocr_engine": "tesseract", "ocr_text": None}
    return {"ocr_status": "completed", "ocr_engine": "tesseract", "ocr_text": normalized}


# BIP-39 standardized mnemonic word set (comprehensive sample for crypto wallet detection)
BIP39_SAMPLE_WORDS = frozenset(
    {
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
        "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
        "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
        "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
        "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
        "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
        "alpha", "already", "also", "alter", "always", "amateur", "amaze", "among",
        "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
        "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
        "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
        "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
        "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
        "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
        "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
        "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
        "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
        "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
        "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
        "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
        "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
        "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
        "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
        "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
        "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
        "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
        "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
        "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
        "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
        "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
        "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
        "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable",
        "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
        "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable",
        "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry",
        "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog",
        "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling",
        "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk",
        "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap",
        "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
        "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar",
        "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify",
        "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff",
        "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud",
        "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
        "code", "coffee", "coil", "coin", "collect", "color", "column", "combine",
        "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm",
        "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper",
        "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch",
        "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle",
        "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream",
        "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop",
        "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch",
        "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious",
        "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad",
        "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn",
        "day", "deal", "debate", "debris", "decade", "december", "decide", "decline",
        "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay",
        "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend",
        "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk",
        "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram",
        "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital",
        "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover",
        "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide",
        "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain",
        "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft",
        "dragon", "drain", "drama", "drastic", "draw", "dream", "dress", "drift",
        "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck",
        "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic",
        "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy",
        "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg",
        "eight", "either", "elbow", "elder", "electric", "elegant", "element", "elephant",
        "elevator", "elite", "else", "embark", "embody", "embrace", "emerge", "emotion",
        "employ", "empower", "empty", "enable", "enact", "end", "endless", "endorse",
        "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist",
        "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope",
        "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error",
        "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence",
        "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite",
        "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist",
        "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express",
        "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade",
        "faint", "faith", "fall", "false", "fame", "family", "famous", "fan",
        "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue",
        "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel",
        "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction",
        "field", "figure", "file", "film", "filter", "final", "find", "fine",
        "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit",
        "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee",
        "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush",
        "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food",
        "foot", "force", "forest", "forget", "fork", "fortune", "forum", "forward",
        "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh",
        "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit",
        "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain",
        "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic",
        "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general",
        "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift",
        "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare",
        "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow",
        "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel",
        "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape",
        "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery",
        "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar",
        "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand",
        "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk",
        "hazard", "head", "health", "heart", "heavy", "hedgehog", "height", "hello",
        "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint",
        "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday",
        "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse",
        "hospital", "host", "hotel", "hour", "house", "hover", "hub", "huge",
        "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry",
        "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle",
        "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune",
        "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase",
        "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "initial",
        "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane",
        "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest",
        "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory",
        "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel",
        "job", "join", "joke", "journey", "joy", "judge", "juice", "jump",
        "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup",
        "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit",
        "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know",
        "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language",
        "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law",
        "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave",
        "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend",
        "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty",
        "library", "license", "life", "lift", "light", "like", "limb", "limit",
        "link", "lion", "liquid", "list", "little", "live", "lizard", "load",
        "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop",
        "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber",
        "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet",
        "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
        "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin",
        "marine", "market", "marriage", "mask", "mass", "master", "match", "material",
        "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure",
        "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory",
        "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message",
        "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
        "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake",
        "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment",
        "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning",
        "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie",
        "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music",
        "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
        "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative",
        "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral",
        "never", "news", "next", "nice", "night", "noble", "noise", "nominee",
        "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice",
        "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey",
        "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean",
        "october", "odor", "off", "offer", "office", "often", "oil", "okay",
        "old", "olive", "olympic", "omit", "once", "one", "onion", "online",
        "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit",
        "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich",
        "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over",
        "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page",
        "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper",
        "parade", "parent", "park", "parrot", "party", "pass", "patch", "path",
        "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut",
        "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper",
        "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical",
        "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot",
        "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet",
        "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge",
        "poem", "poet", "point", "polar", "pole", "police", "pond", "pony",
        "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery",
        "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare",
        "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority",
        "prison", "private", "prize", "problem", "process", "produce", "profit", "program",
        "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide",
        "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil",
        "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle",
        "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz",
        "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail",
        "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid",
        "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real",
        "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle",
        "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject",
        "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove",
        "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report",
        "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire",
        "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib",
        "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid",
        "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road",
        "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room",
        "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude",
        "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness",
        "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same",
        "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say",
        "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science",
        "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea",
        "search", "season", "seat", "second", "secret", "section", "security", "seed",
        "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence",
        "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
        "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine",
        "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder",
        "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
        "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar",
        "simple", "since", "sing", "siren", "sister", "situate", "six", "size",
        "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab",
        "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan",
        "slot", "slow", "slum", "small", "smart", "smile", "smoke", "smooth",
        "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social",
        "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve",
        "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup",
        "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
        "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin",
        "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray",
        "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium",
        "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay",
        "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting",
        "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
        "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject",
        "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest",
        "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme",
        "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain",
        "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim",
        "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table",
        "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target",
        "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten",
        "tenant", "tennis", "tent", "term", "test", "text", "thank", "that",
        "theme", "then", "theory", "there", "they", "thing", "this", "thought",
        "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger",
        "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title",
        "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token",
        "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top",
        "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist",
        "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic",
        "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree",
        "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy",
        "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try",
        "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle",
        "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical",
        "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo",
        "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown",
        "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon",
        "upper", "upset", "urban", "urge", "usage", "use", "used", "useful",
        "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley",
        "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle",
        "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very",
        "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view",
        "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual",
        "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote",
        "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want",
        "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave",
        "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding",
        "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat",
        "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife",
        "wild", "will", "win", "window", "wine", "wing", "wink", "winner",
        "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman",
        "wonder", "wood", "wool", "word", "work", "world", "worry", "worth",
        "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year",
        "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo",
    }
)


def luhn_validate(card_number_str: str) -> bool:
    """Validate payment card number using Luhn algorithm."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for idx, d in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = d * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


def detect_sensitive_patterns(ocr_text: str | None) -> list[dict[str, Any]]:
    """Scan OCR text for BIP-39 cryptocurrency mnemonics, cards, and credentials."""
    if not ocr_text:
        return []
    findings: list[dict[str, Any]] = []
    text_clean = ocr_text.strip()
    words = [w.strip(".,;:\"'()[]{}!?").lower() for w in text_clean.split()]

    # 1. BIP-39 Cryptocurrency Recovery Seed Mnemonic Detection (12, 18, 24 words)
    bip39_matches = [w for w in words if w in BIP39_SAMPLE_WORDS]
    if len(bip39_matches) >= 12 and (len(bip39_matches) / max(len(words), 1)) >= 0.70:
        findings.append(
            {
                "type": "crypto_seed_phrase",
                "confidence": 0.95,
                "summary": (
                    f"Detected {len(bip39_matches)}-word BIP-39 cryptocurrency recovery seed"
                ),
                "word_count": len(bip39_matches),
                "matched_words_sample": bip39_matches[:6],
            }
        )

    # 2. Payment Card Numbers (Visa, Mastercard, Amex, Discover)
    import re
    card_candidates = re.findall(r"\b(?:\d[ -]*?){13,19}\b", text_clean)
    for cand in card_candidates:
        digits_only = re.sub(r"\D", "", cand)
        if 13 <= len(digits_only) <= 19 and luhn_validate(digits_only):
            masked = f"{digits_only[:4]} **** **** {digits_only[-4:]}"
            findings.append(
                {
                    "type": "payment_card",
                    "confidence": 0.90,
                    "summary": f"Luhn-validated payment card number ({masked})",
                }
            )
            break

    # 3. Private Key Signatures
    if "BEGIN PRIVATE KEY" in text_clean or "BEGIN RSA PRIVATE KEY" in text_clean:
        findings.append(
            {
                "type": "cryptographic_private_key",
                "confidence": 0.98,
                "summary": "PEM formatted cryptographic private key block observed",
            }
        )
    elif re.search(r"\b0x[a-fA-F0-9]{64}\b", text_clean):
        findings.append(
            {
                "type": "ethereum_private_key_candidate",
                "confidence": 0.85,
                "summary": "256-bit hexadecimal cryptographic private key candidate",
            }
        )

    return findings


def classify(
    image: Image.Image,
    exif: dict[str, Any],
    ocr_findings: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Produce heuristic content-classification labels with explicit confidence."""
    width, height = image.size
    labels: list[dict[str, Any]] = []
    ratio = (width / height) if height else 0.0
    if exif.get("camera_make") or exif.get("camera_model"):
        labels.append(
            {
                "label": "camera_original",
                "confidence": 0.75,
                "basis": "exif_camera_tags_present",
            }
        )
    else:
        labels.append(
            {
                "label": "no_camera_metadata",
                "confidence": 0.5,
                "basis": "exif_camera_tags_absent",
            }
        )
    if exif.get("gps_present"):
        labels.append({"label": "geotagged", "confidence": 0.9, "basis": "exif_gps_ifd_present"})
    if ratio and (ratio >= 1.7 or ratio <= 0.6):
        labels.append(
            {
                "label": "likely_screenshot_or_panorama",
                "confidence": 0.4,
                "basis": f"aspect_ratio_{round(ratio, 2)}",
            }
        )

    # Incorporate OCR sensitive findings into forensic triage labels
    if ocr_findings:
        for finding in ocr_findings:
            labels.append(
                {
                    "label": finding["type"],
                    "confidence": finding["confidence"],
                    "basis": finding["summary"],
                }
            )

    labels.append(
        {
            "label": "sensitive_content_scan",
            "confidence": 0.0,
            "basis": "no_trained_model_bundled",
            "status": "unavailable",
        }
    )
    return labels


def analyze(source: Path) -> dict[str, Any]:
    if not source.is_file():
        raise MediaAnalysisRejectedError("SOURCE_NOT_REGULAR", "The source is not a regular file.")
    if source.stat().st_size > MAX_SOURCE_BYTES:
        raise MediaAnalysisRejectedError(
            "SOURCE_TOO_LARGE", "The source exceeds the bounded analysis input limit."
        )
    with source.open("rb") as stream:
        detected_mime = detect_mime(stream.read(HEADER_BYTES))
    if detected_mime not in SUPPORTED_RASTER_MIMES:
        raise MediaAnalysisRejectedError(
            "UNSUPPORTED_MEDIA_TYPE",
            "Only signature-validated JPEG, PNG, GIF, and WebP images can be analyzed.",
            detected_mime=detected_mime,
        )
    try:
        with Image.open(source) as image:
            decoded_mime = Image.MIME.get(image.format or "")
            if decoded_mime != detected_mime:
                raise MediaAnalysisRejectedError(
                    "DECODER_SIGNATURE_MISMATCH",
                    "The image decoder did not confirm the detected file signature.",
                    detected_mime=detected_mime,
                )
            image.seek(0)
            width, height = image.size
            if width < 1 or height < 1 or width * height > MAX_IMAGE_PIXELS:
                raise MediaAnalysisRejectedError(
                    "PIXEL_LIMIT_EXCEEDED",
                    "The source image exceeds the pixel safety limit.",
                    detected_mime=detected_mime,
                )
            exif = extract_exif(image)
            image.load()
            phash = perceptual_hash(image)
            ocr = attempt_ocr(image)
            sensitive_findings = detect_sensitive_patterns(ocr.get("ocr_text"))
            detections = classify(image, exif, ocr_findings=sensitive_findings)
    except Image.DecompressionBombError as error:
        raise MediaAnalysisRejectedError(
            "PIXEL_LIMIT_EXCEEDED",
            "The source image exceeds the pixel safety limit.",
            detected_mime=detected_mime,
        ) from error
    except (UnidentifiedImageError, OSError, ValueError) as error:
        raise MediaAnalysisRejectedError(
            "IMAGE_DECODE_FAILED",
            "The image is corrupt, truncated, or unsupported.",
            detected_mime=detected_mime,
        ) from error
    return {
        "media_kind": "image",
        "detected_mime": detected_mime,
        "width": width,
        "height": height,
        "perceptual_hash": phash,
        "captured_at_raw": exif.get("captured_at_raw"),
        "camera_make": exif.get("camera_make"),
        "camera_model": exif.get("camera_model"),
        "gps_present": bool(exif.get("gps_present")),
        "gps_latitude": exif.get("gps_latitude"),
        "gps_longitude": exif.get("gps_longitude"),
        "exif": exif.get("exif", {}),
        "ocr_status": ocr["ocr_status"],
        "ocr_engine": ocr["ocr_engine"],
        "ocr_text": ocr["ocr_text"],
        "sensitive_findings": sensitive_findings,
        "detections": detections,
        "detector_maturity": "heuristic",
        "worker_version": WORKER_VERSION,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Isolated media-analysis worker.")
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    try:
        result = analyze(Path(args.source))
    except MediaAnalysisRejectedError as error:
        payload = {
            "status": "rejected",
            "code": error.code,
            "message": str(error),
            "detected_mime": error.detected_mime,
        }
        sys.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        return 0
    except Exception:  # noqa: BLE001 - never leak internal detail to the parent
        payload = {
            "status": "failed",
            "code": "WORKER_UNEXPECTED_ERROR",
            "message": "The isolated media-analysis worker failed.",
        }
        sys.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        return 0
    sys.stdout.write(
        json.dumps({"status": "analyzed", "result": result}, separators=(",", ":"), sort_keys=True)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
