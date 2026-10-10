"""
combat.py — Boss fight damage capture for the website's damage parser

One CombatTracker per character. Every chat line goes through feed(); the
tracker keeps combat lines from the last PREROLL_SECONDS in memory and only
starts handing them out once a watched mob (the server's watchlist) shows up
in a line, so trash fights never leave the PC. It then keeps streaming until
nothing has involved a watched mob for LULL_SECONDS.

Lines are sent raw (the server does the parsing), except misses, which only
count towards a tally per attacker, target and kind (miss, dodge, parry,
riposte, block, invulnerable, rune) since they carry no damage, and pets'
"My leader is Bob." lines, which go into pet_owners along with what Zeal's
target-pet-owner label says (see pet_owner()).

Kinds of line kept
------------------
  hit       "Bob slashes X for 12 points of damage." / "You pierce X …" / "X hits YOU …"
  nonmelee  "Bob hit X for 500 points of non-melee damage."  (a bystander's view of
            someone's nuke, pet spell or damage shield, printed by Zeal; its chat
            type goes along: 1009 for a damage shield, 288 for a spell)
  sourceless "X was hit by non-melee for 500 points of damage."  (our own nuke or
            damage shield, or someone else's; see self_spell below)
  dot       "X has taken 93 damage from your Denon`s Bereavement."  (ours only)
  crit      "Bob scores a critical hit! (48)"  (never added to totals server side)
  land      "X reels in terrible pain. (Saryrn's Scream of Pain)" or "X was pierced
            by thorns." — only right after a sourceless line on the same target,
            so the server can tell our nuke from our damage shield
  death     "You have been slain by X!" / "You died." / "X has been slain by Y!" /
            "You have slain X!" / "X died."  (a watched mob dying ends the fight)
  heal      "Bob performs an exceptional heal! (1200)" / "You have been healed for 400
            points of damage." / "Clank is completely healed. (Complete Healing)"
            (the game shows nothing else about other people's heals)
  chcall    "Drmann shouts, 'AAA - CH - Clank - 87%'" / "You tell your raid, 'BBB CH Clank'"
            (a Complete Heal chain call, in any channel, for the chain timing)
  interrupt "Drmann's casting is interrupted!" / "Your spell is interrupted." / "… fizzles!"
  cast      "Drmann begins to cast a spell." / "You begin casting Complete Healing."
            (when a chain cleric's heal really started)
  zoning    "LOADING, PLEASE WAIT..."
  debuff    "Bertoxxulous yawns. (Turgur's Insects)"  (a spell landing on a watched mob
            during a fight, for debuff uptimes)
  boss      "Bertoxxulous shouts, 'You will all die!'" / "Bertoxxulous raises his arms."
            (anything else a watched mob says or does during a fight, for the timeline)
  mycast    one of our own casts, from Zeal's CastingName and TargetName labels:
            {"ts": when it ended, "spell", "target", "start", "landed": when its land
            line ("Clank feels much better. (Supernal Remedy)") showed, or null}
            (who cast which heal, debuff, nuke or buff on whom)

  resist    "Your target resisted the Lullaby of Morell spell."  (ours; the game shows
            nobody else's) with spell and target, from our cast of that spell

Each batch also carries boss_hp, the watched mobs' HP percent from Zeal's
target labels whenever it changed: [[ts, name, percent], ...], and buffs, our
own buffs from Zeal's buff labels whenever they changed: [[ts, [spell, ...]], ...],
vitals, our own HP and mana percent whenever they changed: [[ts, hp, mana], ...],
locs, where we were from Zeal's player packets whenever we moved LOC_STEP or
more: [[ts, x, y, z], ...], and others' positions the same way: other_locs
[[ts, name, x, y, z], ...] for raid / group members (Zeal's raid and group
packets) and watched mobs we target (the player packet's target_loc, only
sent while it's close). Zeal's x and y are the game's y and x, as in /loc.

Sourceless non-melee lines are ours: the server only sends that text to the
caster or damage shield owner (everyone else gets "Bob hit X for N points of
non-melee damage."). Each one carries self_spells, the spells we cast in the
last CAST_SECONDS from Zeal's CastingName label (the game prints no spell
name when we begin a cast), so the server can sanity-check that against the
land message that follows.
"""

import collections
import re
import threading
import time
from typing import Callable, Optional

PREROLL_SECONDS = 60    # combat kept before a watched mob shows up
LULL_SECONDS    = 30    # no watched mob in a line for this long = fight over
LAND_AFTER      = 1.5   # our spell's land line can show this long after the cast bar ends
CAST_SECONDS    = 20    # a spell we cast counts as "ours" this long (covers song pulses)
LAND_WINDOW     = 1.5   # a land message this soon after a sourceless line belongs to it
OWNER_SECONDS   = 3 * 3600   # a pet owner we learned is kept this long
LOC_STEP        = 3.0   # moving less than this (game units) isn't sent

# Zeal chat types: hits ("You slash…", "Bob slashes…") and Zeal's re-routed
# special attacks (backstab, kick, strike)
HIT_TYPES = {0xFF + 10, 0xFF + 24, 1004, 1005}

# Melee verbs, with the monk / knight two-word skills ("flying kicks", "harm touches")
# so their first word isn't read as part of the attacker's name (same list as the server)
_VERBS = (r"(?:hits?|slash(?:es)?|pierces?|crush(?:es)?|bash(?:es)?|kicks?|backstabs?|"
          r"punch(?:es)?|bites?|claws?|strikes?|gores?|mauls?|stings?|smash(?:es)?|"
          r"slices?|rends?|sweeps?|frenzies on|bludgeons?|stabs?|shoots?|slams?|jabs?|"
          r"gouges?|throws?|chops?|tramples?|pummels?|chomps?|gnaws?|pecks?|stomps?|"
          r"swipes?|thrash(?:es)?|rakes?|tail rakes?|flying kicks?|round kicks?|"
          r"dragon punch(?:es)?|eagle strikes?|tiger claws?|harm touch(?:es)?)")

RE_HIT        = re.compile(rf"^(?P<src>.+?) {_VERBS} (?P<tgt>.+?) for (?P<dmg>\d+)(?: \(\d+\))? "
                           r"points? of damage\.$")
RE_NONMELEE   = re.compile(r"^(?P<src>.+?) hit (?P<tgt>.+?) for (?P<dmg>\d+) points? of non-melee damage\.$")
RE_SOURCELESS = re.compile(r"^(?P<tgt>.+?) was hit by non-melee for (?P<dmg>\d+) points? of damage\.$")
RE_DOT        = re.compile(r"^(?P<tgt>.+?) has taken (?P<dmg>\d+) (?:points of )?damage from your (?P<spell>.+?)\.$")
RE_MISS       = re.compile(r"^(?P<src>.+?) tr(?:y|ies) to \w+ (?P<tgt>.+?), but (?P<how>.+)$")
RE_MISSED     = re.compile(r"^(?P<src>.+?) missed (?P<tgt>[^,.!']+)$")   # the short form: "Gaukr Sandstorm missed Venexia"
RE_CRIT       = re.compile(r"^(?P<src>.+?) (?i:scores? a critical hit|lands? a Crippling Blow|"
                           r"scores? a Deadly Strike|delivers? a critical blast)!? ?\((?P<dmg>\d+)\)$")
RE_LAND       = re.compile(r"\((?P<spell>[^()]+)\)$")
RE_DEATH      = re.compile(r"^(?:You have been slain by (?P<killer>.+?)[!.]|You died\.|"
                           r"You have slain (?P<slain>.+?)!|(?P<died>.+?) (?:has )?died\.|"
                           r"(?P<victim>.+?) has been slain by (?P<by>.+?)!)$")
RE_ZONING     = re.compile(r"^LOADING, PLEASE WAIT", re.IGNORECASE)
RE_HEAL       = re.compile(r"^(?:.+? performs? an exceptional heal! ?\(\d+\)|"
                           r"You have been healed for \d+ points? of damage\.|"
                           r".+? (?:is|are) completely healed\..*)$")
RE_LEADER     = re.compile(r"^(?P<pet>.+?) (?:says|tells you),? '(?:My leader is|my leader is) "
                           r"(?P<owner>[A-Z][a-z]+)\.?'$")
RE_OWNER_NAME = re.compile(r"^[A-Z][a-z]+$")
# A heal chain call: someone (or we) saying a message with "CH" in it, in any channel
RE_CHAIN_CALL = re.compile(r"^(?:You|[A-Z][a-z]+) (?:shouts?|says?(?: out of character)?|tells? (?:the|your) "
                           r"(?:raid|group|party|guild)|auctions?),?\s+'.*\b(?i:ch)\b.*'$")
RE_BEGIN_CAST = re.compile(r"^(?:[A-Z][a-z]+ begins to cast a spell|You begin casting .+)\.$")
RE_INTERRUPT  = re.compile(r"^(?:.+?'s casting is interrupted!|Your spell is interrupted\.|"
                           r".+?'s spell fizzles!|Your spell fizzles!)$")
RE_SPEAKER    = re.compile(r"^(?P<name>[^,']+?) (?:says|shouts|yells|tells (?:you|the raid))\b")
# Damage shield lands on the boss ("Bertoxxulous was pierced by thorns.") and con messages
RE_BOSS_NOISE = re.compile(r"^\S.*? was [^']+\.$| (?:scowls|glares|regards|looks) (?:at |upon )?you")
RE_RESIST     = re.compile(r"^Your target resisted the (?P<spell>.+?) spell\.$")
RE_SPAWN_ID   = re.compile(r" \(\d+\)$")   # Zeal's "/labels showtargetspawnid" suffix

# What stopped a swing, from the end of "X tries to hit Y, but …"
_AVOID = (("invulnerable", "invulnerable"), ("absorbs the blow", "rune"), ("parr", "parry"),
          ("dodge", "dodge"), ("ripost", "riposte"), ("block", "block"))

# A hit shown abbreviated ("backstab a gnoll for 123") or as a bare number, from
# the game's "hits" display options; the server can't read these
RE_ABBREVIATED = re.compile(r"^(?:\d+|.+ for \d+)$")

# Cheap test before the regexes: nearly every chat line fails this
_MAYBE = re.compile(r"damage|tr(?:y|ies) to |critical|Crippling|Deadly|slain|died|"
                    r"LOADING|\)$| missed |resisted the|completely healed|eader is|(?i:\bch\b)|interrupted|fizzles|egins? to cast|egin casting")


class CombatTracker:
    """
    Combat line buffer and boss-fight gate for one character.

    is_watched(name) says whether a mob name is on the server's watchlist.
    feed() and drain() can be called from different threads.
    """

    def __init__(self, character: str, is_watched: Callable[[str], bool]):
        self.character  = character
        self.is_watched = is_watched
        self._lock      = threading.Lock()
        self._buffer: collections.deque = collections.deque()  # (ts, line dict) before a fight
        self._out:    list = []            # lines waiting for the next batch
        self._misses: collections.Counter = collections.Counter()  # (src, tgt, how) → count
        self._buf_misses: collections.deque = collections.deque()  # (ts, src, tgt, how) before a fight
        self._owners: dict = {}            # pet name → (owner, when we learned it)
        self._owners_new = False           # pet_owners changed since the last batch
        self.active       = False          # streaming a fight now
        self.fight_start  = 0.0
        self._last_watched = 0.0           # last line involving a watched mob
        self._ended       = False          # a fight just ended; next batch says so
        self.watched_seen: set = set()     # watched mobs seen this fight
        self._casts: dict = {}             # spell we cast → when we last saw it
        self._cast_now: Optional[dict] = None   # our cast in progress: start, spell, target, landed
        self._cast_done: list = []         # finished casts still waiting for a land line
        self._sourceless: dict = {}        # target (lower) → time of last sourceless line
        self._hp_last: dict = {}           # watched mob → (when, HP percent) from the target labels
        self._hp_out: list = []            # [ts, name, percent] waiting for the next batch
        self._buffs: tuple = ()            # our buffs now, from Zeal's buff labels
        self._buffs_out: list = []         # [ts, [spell, ...]] waiting for the next batch
        self._vitals: Optional[tuple] = None   # (when, hp, mana): ours now
        self._vitals_out: list = []        # [ts, hp, mana] waiting for the next batch
        self._loc: Optional[tuple] = None  # (when, x, y, z): where we were last sent from
        self._locs_out: list = []          # [ts, x, y, z] waiting for the next batch
        self._others: dict = {}            # name → (x, y): where a raid member or boss was last sent from
        self._others_out: list = []        # [ts, name, x, y, z] waiting for the next batch
        self.abbreviated = 0               # abbreviated hit lines seen (see RE_ABBREVIATED)

    # ─── Input ────────────────────────────────

    def feed(self, text: str, now: Optional[float] = None, chat_type: Optional[int] = None):
        """Classify one chat line (with its Zeal chat type, if known) and keep it if it's combat."""
        if chat_type in HIT_TYPES and RE_ABBREVIATED.match(text) and not text.endswith(" damage."):
            self.abbreviated += 1
            return
        if not _MAYBE.search(text) and not self._sourceless and not self._from_boss(text):
            return
        now = now or time.time()
        with self._lock:
            self._check_lull(now)
            self._classify(text, now, chat_type)

    def casting(self, spell: str, now: Optional[float] = None, target: str = ""):
        """
        Zeal's CastingName label: the spell we're casting now ("" when idle),
        with our target then (TargetName; no target means ourselves).
        """
        now = now or time.time()
        spell = (spell or "").strip()
        with self._lock:
            if spell:
                self._casts[spell] = now
            cur = self._cast_now
            if cur and cur["spell"] != spell:
                cur["end"] = now
                self._cast_done.append(cur)
                self._cast_now = None
            if spell and self._cast_now is None:
                target = RE_SPAWN_ID.sub("", (target or "").strip()) or self.character
                self._cast_now = {"start": now, "spell": spell, "target": target, "landed": None}
            self._flush_casts(now)

    def _own_land(self, text: str, now: float) -> bool:
        """A land line for one of our casts: "Clank feels much better. (Supernal Remedy)"."""
        m = RE_LAND.search(text)
        if not m:
            return False
        lower = text.lower()
        for c in ([self._cast_now] if self._cast_now else []) + self._cast_done:
            if (c["landed"] is None and c["spell"] == m.group("spell")
                    and now <= c.get("end", now) + LAND_AFTER
                    and (lower.startswith(c["target"].lower() + " ")
                         or (c["target"] == self.character and lower.startswith("you ")))):
                c["landed"] = now
                return True
        return False

    def _flush_casts(self, now: float):
        """Finished casts whose land had its chance go out as mycast lines."""
        keep = []
        for c in self._cast_done:
            if c["landed"] is None and not c.get("resisted") and now <= c["end"] + LAND_AFTER:
                keep.append(c)
                continue
            line = {"ts": round(c["end"], 2), "kind": "mycast", "text": "", "spell": c["spell"],
                    "target": c["target"], "start": round(c["start"], 2),
                    "landed": round(c["landed"], 2) if c["landed"] is not None else None}
            if c.get("resisted"):
                line["resisted"] = round(c["resisted"], 2)
            if self.active:
                self._out.append(line)
            else:
                self._buffer.append((c["end"], line))
        self._cast_done = keep

    def target_hp(self, name: str, percent: int, now: Optional[float] = None):
        """Zeal's TargetName and TargetHPPerc labels: kept when the target is a watched mob."""
        name = RE_SPAWN_ID.sub("", (name or "").strip())
        if not name or not self.is_watched(name):
            return
        now = now or time.time()
        with self._lock:
            last = self._hp_last.get(name)
            if last and last[1] == percent:
                return
            self._hp_last[name] = (now, percent)
            if self.active:
                self._hp_out.append([round(now, 2), name, percent])

    def buffs(self, spells, now: Optional[float] = None):
        """Zeal's buff labels: our buffs right now, kept when they change during a fight."""
        spells = tuple(sorted(spells))
        with self._lock:
            if spells == self._buffs:
                return
            self._buffs = spells
            if self.active:
                self._buffs_out.append([round(now or time.time(), 2), list(spells)])

    def vitals(self, hp: int, mana: Optional[int], now: Optional[float] = None):
        """Zeal's HP and mana percent labels: kept when they change during a fight."""
        now = now or time.time()
        with self._lock:
            if self._vitals and self._vitals[1:] == (hp, mana):
                return
            self._vitals = (now, hp, mana)
            if self.active:
                self._vitals_out.append([round(now, 2), hp, mana])

    def location(self, x: float, y: float, z: Optional[float], now: Optional[float] = None):
        """Where we are, from Zeal's player packets: kept when we move LOC_STEP during a fight."""
        now = now or time.time()
        with self._lock:
            last = self._loc
            if last and ((x - last[1]) ** 2 + (y - last[2]) ** 2) ** .5 < LOC_STEP:
                return
            self._loc = (now, round(x, 1), round(y, 1), None if z is None else round(z, 1))
            if self.active:
                self._locs_out.append([round(now, 2), *self._loc[1:]])

    def other_location(self, name: str, x: float, y: float, z: Optional[float],
                       now: Optional[float] = None, boss: bool = False):
        """
        A raid / group member's position, or a mob's we have targeted
        (boss=True, kept only for watched mobs). Sent during fights only.
        """
        name = RE_SPAWN_ID.sub("", (name or "").strip())
        if not name or name == self.character or (boss and not self.is_watched(name)):
            return
        with self._lock:
            if not self.active:
                return
            last = self._others.get(name)
            if last and ((x - last[0]) ** 2 + (y - last[1]) ** 2) ** .5 < LOC_STEP:
                return
            self._others[name] = (x, y)
            self._others_out.append([round(now or time.time(), 2), name, round(x, 1), round(y, 1),
                                     None if z is None else round(z, 1)])

    def _from_boss(self, text: str) -> bool:
        """Whether a line starts with the name of a watched mob in the current fight."""
        lower = text.lower()
        if self.active and any(lower.startswith(n.lower() + " ") for n in tuple(self.watched_seen)):
            return True
        m = RE_SPEAKER.match(text)   # a boss talking before the pull is kept with the pre-roll
        return bool(m and self.is_watched(m.group("name")))

    def pet_owner(self, pet: str, owner: str, now: Optional[float] = None):
        """A pet's owner, from Zeal's TargetName and TargetPetOwner labels or a leader line."""
        pet = RE_SPAWN_ID.sub("", pet.strip())
        owner = owner.strip()
        if not pet or not RE_OWNER_NAME.match(owner) or pet == owner:
            return
        with self._lock:
            self._note_owner(pet, owner, now or time.time())

    def _note_owner(self, pet: str, owner: str, now: float):
        old = self._owners.get(pet)
        self._owners[pet] = (owner, now)
        if not old or old[0] != owner:
            self._owners_new = True

    def _classify(self, text: str, now: float, chat_type: Optional[int] = None):
        if text.endswith(")") and (self._cast_now or self._cast_done):
            self._own_land(text, now)   # one of our spells landing; the line is still classified below
        # Sourceless and non-melee first: "X was hit by non-melee…" would
        # otherwise read as a melee "hit" by "X was"
        if m := RE_RESIST.match(text):
            spell, target = m.group("spell"), ""
            for c in ([self._cast_now] if self._cast_now else []) + self._cast_done[::-1]:
                if c["spell"] == spell and not c.get("resisted"):
                    c["resisted"] = now
                    target = c["target"]
                    break
            self._keep(now, "resist", text, "", "", spell=spell, target=target)
        elif m := RE_SOURCELESS.match(text):
            tgt = m.group("tgt")
            self._sourceless = {t: at for t, at in self._sourceless.items()
                                if now - at <= LAND_WINDOW}
            self._sourceless[tgt.lower()] = now
            self._keep(now, "sourceless", text, "", tgt, self_spells=self._recent_casts(now))
        elif m := RE_NONMELEE.match(text):
            extra = {"type": chat_type} if chat_type is not None else {}
            self._keep(now, "nonmelee", text, m.group("src"), m.group("tgt"), **extra)
        elif m := RE_HIT.match(text):
            self._keep(now, "hit", text, m.group("src"), m.group("tgt"))
        elif m := RE_DOT.match(text):
            self._keep(now, "dot", text, self.character, m.group("tgt"))
        elif m := RE_MISS.match(text):
            how = m.group("how").lower()
            self._miss(now, m.group("src"), m.group("tgt"),
                       next((kind for word, kind in _AVOID if word in how), "miss"))
        elif m := RE_MISSED.match(text):
            self._miss(now, m.group("src"), m.group("tgt"))
        elif m := RE_CRIT.match(text):
            self._keep(now, "crit", text, m.group("src"), "")
        elif m := RE_DEATH.match(text):
            victim = m.group("victim") or m.group("slain") or m.group("died") or ""
            self._keep(now, "death", text, "", "")
            if self.active and victim and self._involves_watched(victim):
                self._end_fight()   # the boss died
        elif RE_CHAIN_CALL.match(text):
            self._keep(now, "chcall", text, "", "")
        elif RE_BEGIN_CAST.match(text):
            self._keep(now, "cast", text, "", "")
        elif RE_INTERRUPT.match(text):
            self._keep(now, "interrupt", text, "", "")
        elif RE_HEAL.match(text):
            self._keep(now, "heal", text, "", "")
        elif m := RE_LEADER.match(text):
            self._note_owner(m.group("pet"), m.group("owner"), now)
        elif RE_ZONING.match(text):
            self._keep(now, "zoning", text, "", "")
            if self.active:
                self._end_fight()
        else:
            nuke = self._land(text, now)
            if nuke or not self._from_boss(text):
                return
            # A spell landing on the boss, or the boss saying or doing something
            m = RE_LAND.search(text)
            if m:
                self._keep(now, "debuff", text, "", "", spell=m.group("spell"))
            elif not RE_BOSS_NOISE.search(text):
                self._keep(now, "boss", text, "", "")

    def _land(self, text: str, now: float) -> bool:
        """
        What hit it: "A Klicnik worker reels in terrible pain. (Saryrn's
        Scream of Pain)" for a nuke, "Bertoxxulous was pierced by thorns."
        for our damage shield, right after "… was hit by non-melee …"
        """
        lower = text.lower()
        for tgt, seen in self._sourceless.items():
            if now - seen <= LAND_WINDOW and lower.startswith(tgt + " "):
                m = RE_LAND.search(text)
                self._keep(now, "land", text, "", tgt, spell=m.group("spell") if m else "")
                return True
        return False

    def _recent_casts(self, now: float) -> list:
        return sorted(s for s, at in self._casts.items() if now - at <= CAST_SECONDS)

    def _involves_watched(self, *names: str) -> Optional[str]:
        for name in names:
            if name and name not in ("You", "YOU") and self.is_watched(name):
                return name
        return None

    def _keep(self, now: float, kind: str, text: str, src: str, tgt: str, **extra):
        line = {"ts": round(now, 2), "kind": kind, "text": text, **extra}
        watched = (self._involves_watched(src, tgt)
                   if kind in ("hit", "nonmelee", "sourceless", "dot") else None)
        if watched:
            self._last_watched = now
            self.watched_seen.add(watched)
            if not self.active:
                self._start_fight(now)
        if self.active:
            self._out.append(line)
        else:
            self._buffer.append((now, line))
            self._trim(now)

    def _miss(self, now: float, src: str, tgt: str, how: str = "miss"):
        watched = self._involves_watched(src, tgt)
        if watched:
            self._last_watched = now
            self.watched_seen.add(watched)
            if not self.active:
                self._start_fight(now)
        if self.active:
            self._misses[(src, tgt, how)] += 1
        else:
            self._buf_misses.append((now, src, tgt, how))
            self._trim(now)

    # ─── Fight state ──────────────────────────

    def _trim(self, now: float):
        cutoff = now - PREROLL_SECONDS
        while self._buffer and self._buffer[0][0] < cutoff:
            self._buffer.popleft()
        while self._buf_misses and self._buf_misses[0][0] < cutoff:
            self._buf_misses.popleft()

    def _start_fight(self, now: float):
        """A watched mob turned up: send the pre-roll and start streaming."""
        self._trim(now)
        self.active      = True
        self._ended      = False
        self.fight_start = self._buffer[0][0] if self._buffer else now
        self._out.extend(line for _, line in self._buffer)
        for _, src, tgt, how in self._buf_misses:
            self._misses[(src, tgt, how)] += 1
        self._owners_new = bool(self._owners)   # the server starts a new encounter: tell it again
        self._hp_out = [[round(at, 2), name, pct] for name, (at, pct) in self._hp_last.items()
                        if now - at <= PREROLL_SECONDS]
        self._buffs_out = [[round(now, 2), list(self._buffs)]] if self._buffs else []
        self._vitals_out = [[round(now, 2), *self._vitals[1:]]] if self._vitals else []
        self._locs_out = [[round(now, 2), *self._loc[1:]]] if self._loc else []
        self._others = {}
        self._others_out = []
        self._buffer.clear()
        self._buf_misses.clear()

    def _end_fight(self):
        self.active = False
        self._ended = True

    def _check_lull(self, now: float):
        if self.active and now - self._last_watched > LULL_SECONDS:
            self._end_fight()

    # ─── Output ───────────────────────────────

    def drain(self, now: Optional[float] = None) -> Optional[dict]:
        """
        Everything collected since the last call, as one batch, or None when
        there's nothing to send. Also notices the end of a fight during a lull.
        """
        now = now or time.time()
        with self._lock:
            self._check_lull(now)
            self._flush_casts(now)
            if not self._out and not self._misses and not self._ended and not self._hp_out \
                    and not self._buffs_out and not self._vitals_out and not self._locs_out \
                    and not self._others_out:
                return None
            batch = {
                "lines":   self._out,
                "misses":  [{"src": s, "tgt": t, "how": h, "count": c}
                            for (s, t, h), c in self._misses.items()],
                "fight_start": round(self.fight_start, 2),
                "watched": sorted(self.watched_seen),
                "ended":   self._ended,
            }
            if self._owners_new:
                self._owners = {p: o for p, o in self._owners.items() if now - o[1] <= OWNER_SECONDS}
                batch["pet_owners"] = {p: o for p, (o, _) in self._owners.items()}
                self._owners_new = False
            if self._hp_out:
                batch["boss_hp"] = sorted(self._hp_out)
            if self._buffs_out:
                batch["buffs"] = self._buffs_out
                self._buffs_out = []
            if self._vitals_out:
                batch["vitals"] = self._vitals_out
                self._vitals_out = []
            if self._locs_out:
                batch["locs"] = self._locs_out
                self._locs_out = []
            if self._others_out:
                batch["other_locs"] = self._others_out
                self._others_out = []
            self._out    = []
            self._misses = collections.Counter()
            self._hp_out = []
            if self._ended:
                self._ended = False
                self.watched_seen = set()
            return batch
