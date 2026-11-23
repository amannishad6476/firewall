import re
from typing import Dict, Any, List

ZERO_WIDTH_CHARS = {
    '\u200B': 'Zero-Width Space',
    '\u200C': 'Zero-Width Non-Joiner',
    '\u200D': 'Zero-Width Joiner',
    '\uFEFF': 'Zero-Width No-Break Space (BOM)',
    '\u2060': 'Word Joiner',
    '\u200E': 'Left-To-Right Mark',
    '\u200F': 'Right-To-Left Mark',
    '\u202A': 'Left-to-Right Embedding',
    '\u202B': 'Right-to-Left Embedding',
    '\u202C': 'Pop Directional Formatting',
    '\u202D': 'Left-to-Right Override',
    '\u202E': 'Right-to-Left Override (Trojan Source)',
}

HOMOGLYPH_CYRILLIC_LOOKALIKES = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J', 'К': 'K',
    'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X'
}

def inspect_unicode(text: str) -> Dict[str, Any]:
    """
    Scans text for zero-width characters, bidirectional overrides,
    and suspicious homoglyph obfuscation.
    """
    found_zero_width: Dict[str, int] = {}
    total_zw = 0
    zero_width_positions = []
    
    for idx, ch in enumerate(text):
        if ch in ZERO_WIDTH_CHARS:
            name = ZERO_WIDTH_CHARS[ch]
            found_zero_width[name] = found_zero_width.get(name, 0) + 1
            total_zw += 1
            if len(zero_width_positions) < 10:
                zero_width_positions.append({"char_code": hex(ord(ch)), "name": name, "index": idx})

    # Check for Trojan Source Bidi overrides
    has_bidi_override = any(ch in text for ch in ['\u202D', '\u202E', '\u202B', '\u202A'])

    # Check for homoglyph mixing (Cyrillic lookalikes embedded inside ASCII words)
    homoglyph_matches = []
    words = re.findall(r'\b\w+\b', text)
    for word in words:
        has_latin = any('a' <= c.lower() <= 'z' for c in word)
        has_cyrillic = any(c in HOMOGLYPH_CYRILLIC_LOOKALIKES for c in word)
        if has_latin and has_cyrillic:
            homoglyph_matches.append(word)

    detected = total_zw > 0 or has_bidi_override or len(homoglyph_matches) > 0
    
    evidence = []
    if total_zw > 0:
        details = ", ".join(f"{k}: {v}" for k, v in found_zero_width.items())
        evidence.append(f"Detected {total_zw} zero-width unicode character(s) ({details})")
    if has_bidi_override:
        evidence.append("Detected Bidirectional Unicode Override characters (potential Trojan Source attack)")
    if homoglyph_matches:
        evidence.append(f"Detected mixed-script homoglyphs in token(s): {', '.join(homoglyph_matches[:5])}")

    return {
        "detected": detected,
        "total_zero_width_count": total_zw,
        "zero_width_summary": found_zero_width,
        "zero_width_positions": zero_width_positions,
        "has_bidi_override": has_bidi_override,
        "homoglyph_matches": homoglyph_matches,
        "evidence": evidence,
        "clean_text": "".join(c for c in text if c not in ZERO_WIDTH_CHARS)
    }
