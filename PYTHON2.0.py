import tkinter as tk
from tkinter import ttk
import re
import math
import random
import string


# ── Strength logic ────────────────────────────────────────────────────────────

def calculate_entropy(password: str) -> float:
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"\d", password):    charset += 10
    if re.search(r"[^a-zA-Z\d]", password): charset += 32
    return len(password) * math.log2(charset) if charset else 0


def analyze_password(password: str) -> dict:
    if not password:
        return {
            "score": 0, "label": "Empty", "color": "#555555",
            "bar_color": "#333333", "checks": [], "suggestions": []
        }

    checks = [
        ("At least 8 characters",    len(password) >= 8),
        ("At least 12 characters",   len(password) >= 12),
        ("Uppercase letter (A–Z)",   bool(re.search(r"[A-Z]", password))),
        ("Lowercase letter (a–z)",   bool(re.search(r"[a-z]", password))),
        ("Digit (0–9)",              bool(re.search(r"\d", password))),
        ("Special character (!@#…)", bool(re.search(r"[^a-zA-Z\d]", password))),
        ("No repeated chars (aaa)",  not bool(re.search(r"(.)\1{2,}", password))),
        ("No common sequences",      not bool(re.search(
            r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|qwerty|password|admin)",
            password.lower()))),
    ]

    score = sum(v for _, v in checks)
    entropy = calculate_entropy(password)

    if entropy > 60: score = min(score + 1, 8)
    if entropy < 20: score = max(score - 1, 0)

    suggestions = [label for label, passed in checks if not passed]

    if score <= 2:
        label, color, bar_color = "Very Weak",  "#FF3B30", "#FF3B30"
    elif score <= 4:
        label, color, bar_color = "Weak",        "#FF9500", "#FF9500"
    elif score <= 5:
        label, color, bar_color = "Fair",        "#FFCC00", "#FFCC00"
    elif score <= 6:
        label, color, bar_color = "Strong",      "#34C759", "#34C759"
    else:
        label, color, bar_color = "Very Strong", "#00C7BE", "#00C7BE"

    return {
        "score": score, "label": label, "color": color,
        "bar_color": bar_color, "checks": checks,
        "suggestions": suggestions, "entropy": round(entropy, 1)
    }


# ── Related Password Generator ────────────────────────────────────────────────

# Leet-speak substitution table (randomised selection)
_LEET = {
    'a': ['@', '4'],
    'e': ['3'],
    'i': ['!', '1'],
    'o': ['0'],
    's': ['$', '5'],
    't': ['+', '7'],
    'l': ['1'],
    'g': ['9'],
    'b': ['8'],
}

_SPECIAL = "!@#$%^&*-_=+?"
_UPPER   = string.ascii_uppercase
_LOWER   = string.ascii_lowercase
_DIGITS  = string.digits


def _leet_transform(word: str) -> str:
    """Apply random leet-speak substitutions to a word (not every char)."""
    result = []
    for ch in word:
        low = ch.lower()
        if low in _LEET and random.random() < 0.55:
            result.append(random.choice(_LEET[low]))
        else:
            result.append(ch)
    return result


def _capitalise_randomly(chars: list) -> list:
    """Randomly capitalise some alpha characters."""
    return [
        c.upper() if c.isalpha() and random.random() < 0.45 else c
        for c in chars
    ]


def _extract_base(password: str) -> str:
    """
    Pull the most meaningful 'base' from the user's password.
    Priority: longest alphabetic word → any alpha run → raw password stripped.
    """
    # Find all alphabetic runs
    words = re.findall(r"[a-zA-Z]+", password)
    if words:
        base = max(words, key=len)   # longest word / alpha-run
    else:
        # All digits or symbols — use as-is (we'll pad later)
        base = re.sub(r"\s+", "", password)[:8]

    # Also preserve any digit block attached to the word in the original
    # e.g. "john123" → base "john", digits "123"
    digits_after = re.search(re.escape(base) + r"(\d+)", password, re.IGNORECASE)
    digit_suffix = digits_after.group(1) if digits_after else ""

    return base, digit_suffix


def generate_related_password(user_password: str, min_length: int = 14) -> str:
    """
    Generate a strong password that is recognisably derived from
    the user's own password.

    Strategy:
      1. Extract the word/number base from the user's input.
      2. Apply leet substitutions and random capitalisation to the word.
      3. Re-attach (possibly tweaked) digit block.
      4. Inject missing character classes (upper, digit, special).
      5. Pad to min_length with random strong characters if needed.
      6. Shuffle only the *padding* tail so the recognisable part stays
         readable at the front.
    """
    if not user_password:
        # Fallback: fully random strong password
        pool = _LOWER + _UPPER + _DIGITS + _SPECIAL
        base_chars = (
            [random.choice(_LOWER)] * 3 +
            [random.choice(_UPPER)] * 3 +
            [random.choice(_DIGITS)] * 3 +
            [random.choice(_SPECIAL)] * 3
        )
        rest = [random.choice(pool) for _ in range(min_length - len(base_chars))]
        combined = base_chars + rest
        random.shuffle(combined)
        return "".join(combined)

    base_word, digit_suffix = _extract_base(user_password)

    # 1. Leet + capitalise the word
    transformed = _leet_transform(base_word)
    transformed = _capitalise_randomly(transformed)

    # 2. Tweak digit suffix — bump last digit, or add one if missing
    if digit_suffix:
        bumped = str(int(digit_suffix) + random.randint(1, 9)).zfill(len(digit_suffix))
        digit_part = list(bumped)
    else:
        digit_part = [random.choice(_DIGITS), random.choice(_DIGITS)]

    # 3. Build recognisable core
    core = transformed + digit_part

    # 4. Ensure all character classes are present in core
    has_upper   = any(c.isupper() for c in core)
    has_lower   = any(c.islower() for c in core)
    has_digit   = any(c.isdigit() for c in core)
    has_special = any(c in _SPECIAL for c in core)

    injections = []
    if not has_upper:   injections.append(random.choice(_UPPER))
    if not has_lower:   injections.append(random.choice(_LOWER))
    if not has_digit:   injections.append(random.choice(_DIGITS))
    if not has_special: injections.append(random.choice(_SPECIAL))

    # Always inject at least one special for safety
    if not has_special:
        injections.append(random.choice(_SPECIAL))
    else:
        injections.append(random.choice(_SPECIAL))   # extra special

    # 5. Pad to min_length
    pool = _LOWER + _UPPER + _DIGITS + _SPECIAL
    current_len = len(core) + len(injections)
    padding = [random.choice(pool) for _ in range(max(0, min_length - current_len))]

    # 6. Shuffle only injections + padding (keep core readable at front)
    tail = injections + padding
    random.shuffle(tail)

    final = core + tail

    # Safety: trim if somehow too long (shouldn't happen)
    return "".join(final[:max(min_length, len(final))])


# ── GUI ───────────────────────────────────────────────────────────────────────

class PasswordCheckerApp(tk.Tk):

    BG        = "#0F0F13"
    PANEL     = "#1A1A24"
    BORDER    = "#2A2A3A"
    FG        = "#E8E8F0"
    FG_DIM    = "#888899"
    ACCENT    = "#7B61FF"
    GREEN     = "#34C759"
    ORANGE    = "#FF9500"
    FONT_BODY = ("Courier New", 11)
    FONT_SM   = ("Courier New", 9)

    SUGGEST_THRESHOLD = 4   # show panel when score <= this (Weak or below)

    def __init__(self):
        super().__init__()
        self.title("Password Strength Checker")
        self.resizable(False, False)
        self.configure(bg=self.BG)
        self._show_password = False
        self._suggested_password = ""
        self._last_user_pw = ""       # track when base actually changes
        self._build_ui()
        self._center_window(520, 720)

    # ── layout ────────────────────────────────────────────────────────────────

    def _build_ui(self):
        outer = tk.Frame(self, bg=self.BG, padx=28, pady=28)
        outer.pack(fill="both", expand=True)

        tk.Label(outer, text="🔐 PASSWORD", font=("Courier New", 26, "bold"),
                 fg=self.ACCENT, bg=self.BG).pack(anchor="w")
        tk.Label(outer, text="   STRENGTH CHECKER", font=("Courier New", 14),
                 fg=self.FG_DIM, bg=self.BG).pack(anchor="w")

        tk.Frame(outer, bg=self.BORDER, height=1).pack(fill="x", pady=(14, 20))

        tk.Label(outer, text="Enter password:", font=self.FONT_BODY,
                 fg=self.FG_DIM, bg=self.BG).pack(anchor="w")

        entry_frame = tk.Frame(outer, bg=self.PANEL,
                               highlightbackground=self.BORDER,
                               highlightthickness=1)
        entry_frame.pack(fill="x", pady=(6, 0))

        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", lambda *_: self._update())

        self.entry = tk.Entry(entry_frame, textvariable=self.password_var,
                              show="•", font=("Courier New", 14),
                              bg=self.PANEL, fg=self.FG,
                              insertbackground=self.ACCENT,
                              relief="flat", bd=10)
        self.entry.pack(side="left", fill="x", expand=True)

        self.eye_btn = tk.Button(entry_frame, text="👁", font=("Courier New", 12),
                                 bg=self.PANEL, fg=self.FG_DIM,
                                 activebackground=self.PANEL,
                                 activeforeground=self.FG,
                                 relief="flat", bd=0, cursor="hand2",
                                 command=self._toggle_visibility)
        self.eye_btn.pack(side="right", padx=8)

        bar_frame = tk.Frame(outer, bg=self.BG)
        bar_frame.pack(fill="x", pady=(18, 0))

        tk.Label(bar_frame, text="STRENGTH", font=self.FONT_SM,
                 fg=self.FG_DIM, bg=self.BG).pack(side="left")
        self.strength_label = tk.Label(bar_frame, text="—",
                                       font=("Courier New", 9, "bold"),
                                       fg=self.FG_DIM, bg=self.BG)
        self.strength_label.pack(side="right")

        self.bar_canvas = tk.Canvas(outer, bg=self.BG, height=10,
                                    highlightthickness=0)
        self.bar_canvas.pack(fill="x", pady=(4, 0))
        self.bar_canvas.bind("<Configure>", lambda _: self._draw_bar())
        self._last_score = 0
        self._last_bar_color = self.BORDER

        self.entropy_label = tk.Label(outer, text="", font=self.FONT_SM,
                                      fg=self.FG_DIM, bg=self.BG)
        self.entropy_label.pack(anchor="e", pady=(2, 0))

        tk.Frame(outer, bg=self.BORDER, height=1).pack(fill="x", pady=(16, 14))

        tk.Label(outer, text="CHECKS", font=self.FONT_SM,
                 fg=self.FG_DIM, bg=self.BG).pack(anchor="w", pady=(0, 6))

        self.check_frame = tk.Frame(outer, bg=self.BG)
        self.check_frame.pack(fill="x")

        self.check_labels = []
        for text in [
            "At least 8 characters",    "At least 12 characters",
            "Uppercase letter (A–Z)",   "Lowercase letter (a–z)",
            "Digit (0–9)",              "Special character (!@#…)",
            "No repeated chars (aaa)",  "No common sequences",
        ]:
            row = tk.Frame(self.check_frame, bg=self.BG)
            row.pack(fill="x", pady=1)
            icon = tk.Label(row, text="○", font=("Courier New", 11),
                            fg=self.FG_DIM, bg=self.BG, width=2)
            icon.pack(side="left")
            lbl = tk.Label(row, text=text, font=("Courier New", 10),
                           fg=self.FG_DIM, bg=self.BG, anchor="w")
            lbl.pack(side="left")
            self.check_labels.append((icon, lbl))

        tk.Frame(outer, bg=self.BORDER, height=1).pack(fill="x", pady=(16, 10))

        # ── Suggestion panel ──────────────────────────────────────────────────
        self.suggest_outer = tk.Frame(outer, bg=self.BG)

        suggest_header = tk.Frame(self.suggest_outer, bg=self.BG)
        suggest_header.pack(fill="x", pady=(0, 6))

        tk.Label(suggest_header, text="SUGGESTED PASSWORD  (based on yours)",
                 font=self.FONT_SM, fg=self.ORANGE, bg=self.BG).pack(side="left")

        self.regen_btn = tk.Button(
            suggest_header, text="↻ NEW VARIANT",
            font=("Courier New", 8, "bold"),
            bg=self.PANEL, fg=self.FG_DIM,
            activebackground=self.BORDER, activeforeground=self.FG,
            relief="flat", bd=0, padx=8, pady=2, cursor="hand2",
            command=self._regenerate_suggestion
        )
        self.regen_btn.pack(side="right")

        suggest_box = tk.Frame(self.suggest_outer, bg=self.PANEL,
                               highlightbackground=self.BORDER,
                               highlightthickness=1)
        suggest_box.pack(fill="x")

        self.suggest_label = tk.Label(
            suggest_box, text="", font=("Courier New", 13),
            fg=self.GREEN, bg=self.PANEL,
            anchor="w", padx=10, pady=8
        )
        self.suggest_label.pack(side="left", fill="x", expand=True)

        self.copy_btn = tk.Button(
            suggest_box, text="⧉ COPY",
            font=("Courier New", 9, "bold"),
            bg=self.PANEL, fg=self.ACCENT,
            activebackground=self.BORDER, activeforeground=self.FG,
            relief="flat", bd=0, padx=10, pady=8, cursor="hand2",
            command=self._copy_suggestion
        )
        self.copy_btn.pack(side="right")

        # Hint line showing what was detected in user's password
        self.hint_label = tk.Label(
            self.suggest_outer, text="",
            font=("Courier New", 8),
            fg=self.FG_DIM, bg=self.BG, anchor="w"
        )
        self.hint_label.pack(fill="x", pady=(4, 0))

        self.use_btn = tk.Button(
            self.suggest_outer, text="⬆  USE THIS PASSWORD",
            font=("Courier New", 9, "bold"),
            bg=self.PANEL, fg=self.FG_DIM,
            activebackground=self.BORDER, activeforeground=self.FG,
            relief="flat", bd=0, padx=10, pady=5, cursor="hand2",
            command=self._use_suggestion
        )
        self.use_btn.pack(fill="x", pady=(4, 0))

        tk.Frame(outer, bg=self.BORDER, height=1).pack(fill="x", pady=(10, 10))

        tk.Button(outer, text="CLEAR", font=("Courier New", 10, "bold"),
                  bg=self.PANEL, fg=self.FG_DIM,
                  activebackground=self.BORDER, activeforeground=self.FG,
                  relief="flat", bd=0, padx=18, pady=6, cursor="hand2",
                  command=self._clear).pack(anchor="e")

    # ── helpers ───────────────────────────────────────────────────────────────

    def _center_window(self, w, h):
        sx = self.winfo_screenwidth()
        sy = self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sx-w)//2}+{(sy-h)//2}")

    def _toggle_visibility(self):
        self._show_password = not self._show_password
        self.entry.config(show="" if self._show_password else "•")

    def _clear(self):
        self.password_var.set("")
        self.entry.focus_set()

    def _draw_bar(self, score=None, color=None):
        if score is None: score = self._last_score
        if color is None: color = self._last_bar_color
        self._last_score = score
        self._last_bar_color = color

        c = self.bar_canvas
        c.delete("all")
        W = c.winfo_width() or 460
        blocks, gap = 8, 4
        bw = (W - gap * (blocks - 1)) / blocks
        for i in range(blocks):
            x1 = i * (bw + gap)
            fill = color if i < score else self.BORDER
            c.create_rectangle(x1, 0, x1 + bw, 10, fill=fill, outline="")

    def _build_hint(self, pw: str) -> str:
        """Describe what the generator detected in the user's password."""
        base_word, digit_suffix = _extract_base(pw)
        parts = []
        if base_word:
            parts.append(f'word base "{base_word}"')
        if digit_suffix:
            parts.append(f'numbers "{digit_suffix}"')
        has_special = bool(re.search(r"[^a-zA-Z\d]", pw))
        if has_special:
            parts.append("special chars")
        detected = ", ".join(parts) if parts else "your input"
        return f"Detected: {detected}  →  applied leet substitutions + padding"

    def _regenerate_suggestion(self):
        pw = self.password_var.get()
        self._suggested_password = generate_related_password(pw)
        self.suggest_label.config(text=self._suggested_password)
        self.hint_label.config(text=self._build_hint(pw))
        self.copy_btn.config(text="⧉ COPY", fg=self.ACCENT)

    def _copy_suggestion(self):
        if self._suggested_password:
            self.clipboard_clear()
            self.clipboard_append(self._suggested_password)
            self.copy_btn.config(text="✓ COPIED", fg=self.GREEN)
            self.after(2000, lambda: self.copy_btn.config(
                text="⧉ COPY", fg=self.ACCENT))

    def _use_suggestion(self):
        if self._suggested_password:
            self._show_password = True
            self.entry.config(show="")
            self.password_var.set(self._suggested_password)
            self.entry.focus_set()

    # ── main update ──────────────────────────────────────────────────────────

    def _update(self):
        pw = self.password_var.get()
        r  = analyze_password(pw)

        self.strength_label.config(
            text=r["label"] if pw else "—",
            fg=r["color"] if pw else self.FG_DIM)

        self._draw_bar(r["score"] if pw else 0,
                       r["bar_color"] if pw else self.BORDER)

        self.entropy_label.config(
            text=f"Entropy: {r['entropy']} bits" if pw else "",
            fg=self.FG_DIM)

        for (icon, lbl), (text, passed) in zip(self.check_labels, r["checks"]):
            if not pw:
                icon.config(text="○", fg=self.FG_DIM)
                lbl.config(fg=self.FG_DIM)
            elif passed:
                icon.config(text="✓", fg="#34C759")
                lbl.config(fg=self.FG)
            else:
                icon.config(text="✗", fg="#FF3B30")
                lbl.config(fg="#FF3B30")

        # ── Suggestion panel ──────────────────────────────────────────────────
        show = pw and r["score"] <= self.SUGGEST_THRESHOLD

        if show:
            # Regenerate only when the user's actual base changes
            base_word, _ = _extract_base(pw)
            if base_word != self._last_user_pw:
                self._last_user_pw = base_word
                self._suggested_password = generate_related_password(pw)
                self.suggest_label.config(text=self._suggested_password)
                self.hint_label.config(text=self._build_hint(pw))
                self.copy_btn.config(text="⧉ COPY", fg=self.ACCENT)
            self.suggest_outer.pack(fill="x", pady=(0, 4))
        else:
            self.suggest_outer.pack_forget()
            self._last_user_pw = ""


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = PasswordCheckerApp()
    app.mainloop()
