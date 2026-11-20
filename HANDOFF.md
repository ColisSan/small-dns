# Handoff: DNS resolver learning project

Last updated: 2026-11-20. Written so a new session (or a new assistant) can pick up exactly where this one stopped.

---

## 1. What this project is

A **DNS resolver written from scratch in Python**, built as a learning project. The goal is to understand networking (DNS, UDP/TCP, bytes on the wire) and Python at the same time.

"Resolver" means: the program itself walks the DNS tree (root servers, then TLD servers like `.com`, then the domain's own authoritative nameservers) to turn a name like `google.com` into IP addresses, instead of asking a public resolver like `1.1.1.1` to do it.

- Local path: `~/sites/dns-resolver`
- GitHub: https://github.com/ColisSan/small-dns (branch `main`)
- Python 3.12, managed with `uv`, packaged ("src layout"), tests with `pytest`

---

## 2. How the user wants to work (important)

These preferences matter more than anything else in this file.

- **The user writes all the code**, including "boring plumbing" (sockets, struct packing, tests). The assistant explains concepts, describes the problems to solve as points, reviews code, and gives hints. Give full solutions only when the user explicitly asks for one.
- **One issue at a time.** When reviewing, name the single most important issue and how to approach it. Do not hand over long prioritized lists; mention the next issue after this one is fixed.
- **Visual learner.** Diagrams, aligned byte layouts, and small tables work well. Show hex dumps with labels under each part.
- **Explain the "why"**, not just the "what". The user asks good design questions ("who should own the query ID?") and wants reasoning.
- **Background:** web developer (PHP/Laravel, JavaScript). Comparisons to PHP/JS help (`tinker` → IPython, `===` → `==`/`is`, `?:` → `a if c else b`).
- **No Claude attribution in git.** Never add `Co-Authored-By: Claude …` or similar to commits or PRs. The user wrote the code and will show this repo publicly. (A previous co-author line was removed and force-pushed away.)
- Commit or push only when the user asks.

---

## 3. Environment and commands

```bash
cd ~/sites/dns-resolver

uv run pytest            # run tests (add -v for per-test output, -s to see print())
uv run pytest -rP        # show captured output of passing tests

uv run python            # plain REPL with the project importable
uv run ipython           # nicer REPL (if ipython was added: uv add --dev ipython)
#   in IPython:  %load_ext autoreload  then  %autoreload 2   → edits are picked up live

uv run python -m dns_resolver.query   # run a module directly
uv run dns-resolver                   # the CLI entry point (main() in __init__.py; currently empty)

uvx ruff check src tests              # lint
uvx ruff format src tests             # auto-format
```

Package layout:

```
dns-resolver/
├── pyproject.toml           # [project.scripts] dns-resolver = "dns_resolver:main"; dev dep: pytest
├── src/dns_resolver/
│   ├── __init__.py          # main() – currently just `return`; still has unused imports (secrets, struct)
│   ├── query.py             # STEP 1 – building query packets (done)
│   └── transport.py         # STEP 2 – send_query (in progress)
└── tests/
    └── test_query.py        # 15 passing tests for query.py
```

`uv run` installs the package in editable mode (a `.pth` file in `.venv` points at `src/`), so `from dns_resolver import query` works in tests and the REPL.

---

## 4. Git / GitHub state

- One commit on `main`: `9aa7517 Build DNS query packets` (author: ColisSan only). Pushed to `origin` = `git@github.com:ColisSan/small-dns.git`.
- **Uncommitted changes** exist in `query.py`, `transport.py`, and `tests/test_query.py` (small: the QCLASS constant use, the start of `send_query`, the build_query tests). Commit when the user asks.
- GitHub's "Contributors" sidebar may still show Claude from the old (removed) commit; the API already lists only ColisSan. It's a cache; the next push usually refreshes it.
- `HANDOFF.md` (this file) is not committed. Ask the user whether they want it in the repo.

---

## 5. Current code (what exists and how it works)

### `query.py` (Step 1, complete and tested)

Constants:

```python
FLAG_SHIFTS: dict[str, tuple[int, int]] = {   # name: (value, shift)
    "qr": (0, 15), "opcode": (0, 11), "aa": (0, 10), "tc": (0, 9),
    "rd": (0, 8), "ra": (0, 7), "z": (0, 4), "rcode": (0, 0),
}
DOMAIN_NAME_ALLOWED_BYTES = 63      # actually the max LABEL length (naming could be clearer)
ENCODED_NAME_END = b"\x00"          # the root / end-of-name byte
NAME_BYTE_LENGTH_LIMIT = 255        # max encoded name length in bytes
QCLASS = 1                          # IN (Internet)
```

Functions:

- `build_header(query_id: int | None = None, rd: int = 0) -> bytes`
  - generates a random ID with `secrets.randbits(16)` if `query_id is None`
  - builds the 16-bit flags int by looping over `FLAG_SHIFTS` and OR-ing `value << shift` (the `rd` value comes from the parameter)
  - packs `>HHHHHH`: ID, flags, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0 → 12 bytes
- `encode_name(name: str) -> bytes`
  - `"."` or `""` → `b"\x00"` (the root)
  - splits on `.`; an empty label is allowed only as the last one (trailing dot), otherwise `ValueError`
  - each label: ASCII-encode, `ValueError` if > 63 bytes, then `bytes([len]) + label_bytes`
  - appends `b"\x00"`; `ValueError` if the total encoded length > 255
  - keeps the original case (decision, see section 7)
  - non-ASCII names raise `UnicodeEncodeError` (IDNA/punycode not handled yet)
- `build_query(name, query_id=None, rd=0, qtype=1) -> bytes`
  - `build_header(query_id, rd) + encode_name(name) + struct.pack('>HH', qtype, QCLASS)`
  - for `google.com` with ID `0xbeef` this is exactly the 28-byte target:

```
be ef 00 00 00 01 00 00 00 00 00 00   header  (ID, flags=0, 1 question, 0/0/0)
06 67 6f 6f 67 6c 65 03 63 6f 6d 00   name    (6 "google" 3 "com" 0)
00 01 00 01                           type A, class IN
```

Verified live: this exact packet sent to `a.root-servers.net` (198.41.0.4) got a valid 488-byte referral back (`be ef 82 00 00 01 00 00 00 0d 00 0b` header: QR=1, TC=1, 13 authority, 11 additional).

### `transport.py` (Step 2, just started)

```python
def send_query(server_ip: str, name: str, qtype: int = 1, rd: int = 0) -> bytes:
    query_id = secrets.randbits(16)
    response = query.build_query(name, query_id, rd, qtype)   # rename: this is the QUERY, not the response
    print(response)
```

Nothing is sent yet; no return value.

### `tests/test_query.py` (15 passing)

- `GOOGLE_QUERY` module constant (the 28 bytes above, split over 3 commented lines)
- `build_header`: explicit ID; rd=1 (`be ef 01 00 …`); random ID (length 12 + `result[2:]` fixed)
- `encode_name`: parametrized table (google.com, trailing dot, `.`, `""`, `Google.COM` keeps case); max lengths (63-byte label exact bytes; 255-byte name accepted); errors (`google..com`, `.google.com`, 64-byte label, 257-byte name)
- `build_query`: full packet; rd passed through (`result[2] == 1`, mask check, rest unchanged); qtype=28 (`result[-4:] == 00 1c 00 01`); random ID; invalid name raises

Small leftovers the user may tidy later (don't dump these as a list on them):
- test names still contain "assert" (`test_assert_build_header_…`) – redundant
- a stray blank line between `@pytest.mark.parametrize` and `def test_encode_name` (works, but unusual)
- error messages don't include the input; "Domain name too long" is really "label too long"
- comment in `query.py` header block still says RD "use 1" (from the Duke primer; wrong for this resolver)
- `__init__.py` has unused imports
- no input validation for `rd` (e.g. `rd=2` silently sets the TC bit) or `query_id` out of range (cryptic `struct.error`)

---

## 6. Roadmap

```
✅ 1. Build a query          build_header, encode_name, build_query + tests
▶  2. Send & receive         send_query over UDP; timeout; ID check          ← HERE
⬜ 2b. Parse the reply header  ID, flags (with >> and & masks), 4 counts; probably a Flags dataclass
⬜ 3. Parse records          names incl. compression pointers (c0 0c), A / AAAA / NS / CNAME / SOA rdata
⬜ 4. Follow referrals       start at a root server, loop: answer → done; CNAME → restart; NS in authority → next server (glue IPs from additional)
⬜ 5. Edge cases             TC=1 → retry over TCP (2-byte length prefix); NS without glue (resolve the NS name's A record); NXDOMAIN (RCODE 3 + SOA); timeouts/retries across servers
⬜ 6. Caching with TTLs      incl. negative caching; lowercase names for cache keys
⬜ 7. Extras                 CLI with trace output, interactive mode (shows caching), local DNS server mode, EDNS, IDNA, 0x20, async
```

Planned modules: `query.py` (build), `response.py` (parse), `transport.py` (UDP/TCP), `resolver.py` (walk + cache), `__init__.py` `main()` (CLI).

Target CLI output for Step 4 (agreed idea):

```
$ uv run dns-resolver google.com
→ asking a.root-servers.net (198.41.0.4)    referral: com. → a.gtld-servers.net (+12)
→ asking a.gtld-servers.net (192.5.6.30)    referral: google.com. → ns1.google.com (+3)
→ asking ns1.google.com (216.239.32.10)     ANSWER (authoritative)
google.com.  300  A  192.178.203.102
```

---

## 7. Design decisions already made (with reasons)

| Decision | Reason |
|---|---|
| **`send_query` owns the query ID.** It generates it, passes it into `build_query`, and verifies the reply's ID matches. `build_query`/`build_header` just accept an optional `query_id` (random fallback). | The code that must verify the ID should be the one that chose it. Building functions stay pure and easy to test (tests pass `0xbeef`). |
| **RD is decided by whoever chooses the server** (resolver / CLI), passed through `send_query` → `build_query` → `build_header`. Default `rd=0`. | RD=0 for iterative queries (root/TLD/authoritative). RD=1 only when asking a recursive resolver (1.1.1.1, router). |
| **Only RD is a parameter among flags.** QR, OPCODE, AA, TC, RA, Z, RCODE are always 0 in a query. | Those are set by servers in responses or are fixed. Narrow signatures prevent nonsense queries. |
| **`build_query` is for requests only.** If server mode ever happens, add a separate `build_response` and generalize the low-level `build_header` (likely via a `Flags` dataclass), not `build_query`. | YAGNI; narrow high-level functions, shared low-level ones. |
| **`qtype` is a parameter (default 1 = A); class is the constant `QCLASS = 1`.** | Type is a real choice (A, AAAA=28, NS=2…); class is effectively always IN. |
| **Names keep their case** in `encode_name`; lowercase later only for cache keys. | DNS is case-insensitive; servers echo the exact bytes; keeps 0x20 possible. Locked in by a test. |
| **Encode labels as ASCII** (`.encode("ascii")`), not UTF-8. | DNS on the wire is ASCII; non-ASCII must become punycode (`"čevapi.ba".encode("idna")` → `xn--…`). ASCII fails loudly instead of sending garbage. IDNA support is a later extra. |
| **UDP first, TCP on TC=1** (Step 5). | Standard behavior (RFC 7766 made TCP mandatory). The resolver can't know what truncation removed, so retrying over TCP is the safe rule. EDNS (advertise 1232 bytes) later to make truncation rare. |

---

## 8. The immediate next task (Step 2, task 1)

Finish `send_query` in `transport.py`. Describe it to the user as points; they write it.

1. Rename the variable `response` → `query`/`packet` (it holds what is sent).
2. Create a UDP socket: `socket.socket(socket.AF_INET, socket.SOCK_DGRAM)` (`AF_INET` = IPv4, `SOCK_DGRAM` = UDP). Don't `bind()`: the OS picks a random source port (good for security).
3. `settimeout(3)` so a lost packet doesn't hang forever.
4. `sendto(query, (server_ip, 53))`.
5. `recvfrom(4096)` → `(data, address)`.
6. Check `data[:2]` equals the ID (pack the ID with `struct.pack(">H", query_id)` to compare, or unpack the reply's first two bytes). Mismatch → raise.
7. Close the socket (a `with socket.socket(...) as sock:` block does this automatically) and return the reply bytes.

Manual check in the REPL:

```python
from dns_resolver.transport import send_query
reply = send_query("1.1.1.1", "google.com", rd=1)       # recursive resolver: final answer in one hop
reply[:12].hex(" ")
reply = send_query("198.41.0.4", "google.com")          # root server: referral (NSCOUNT 13, TC likely 1)
```

Then discuss **testing network code** (it touches the network): options are a separate, clearly marked integration test against a real server, and/or splitting the function so the pure parts (ID check, parsing) are unit-tested with recorded reply bytes. This conversation hasn't happened yet.

After that: Step 2b, parsing the reply header (introduce `>>` and `&` masks to read flags; the user already understands masks conceptually).

---

## 9. What the user has learned (and where they struggled)

Solid now:
- DNS hierarchy and delegation; root → TLD → authoritative; resolvers vs authoritative servers; caching/TTL; negative caching; CNAME vs A; why referrals exist
- the 12-byte header layout, all flag meanings, QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT, the five message sections
- recursive vs iterative queries and why RD differs between the Duke lab (a client asking a resolver) and this project
- `int` vs `str` vs `bytes`; `struct.pack` (`>` big-endian, `H` = 16-bit = 2 bytes, one code per value); `.encode()`; `bytes([n])`; `b"…"` literals and `\x..` escapes; `.hex(" ")`; slicing bytes; indexing bytes returns an int
- bit shifting `<<` and OR `|` to build flags; AND `&` masks to read one bit (explained: clears every bit where the mask is 0)
- hex/binary/decimal are notations of the same number; `0xbeef` is an int; a 16-bit field always packs to 2 bytes
- pytest basics: `test_` prefix, `assert`, `pytest.raises`, parametrize, testing boundaries (63/64, 255/257), "see a test fail once"
- `if __name__ == "__main__":`, dict iteration with `.items()`, tuple unpacking, `is None`, Python ternary, `==` vs `is`, Python is strongly but dynamically typed

Common slip-ups to watch for (gently):
- confusing **bits and bytes** (e.g. "bit 8" vs byte index 8; "16 bytes" vs 16 bits)
- typos between a function and a variable with similar names (`encode_name` vs `encoded_name` happened twice)
- leftover PHP/JS habits: semicolons, `&` instead of `and`, C-style casts `(int)(x)`, UPPERCASE locals
- forgetting to call/return (`return` without a value, discarded results, assigning a string instead of calling the function in a test)
- tests that can't fail (missing `assert`, function name not starting with `test`)

Things the user said they don't fully get yet (revisit when parsing responses):
- the Authority section vs "authoritative server" distinction; how referrals look inside a parsed reply
- TC/truncation and when exactly to retry over TCP

---

## 10. Facts and corrections worth remembering

- The Duke CPS365 "DNS primer" PDF the user reads (https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf) adds **italic course instructions** to RFC 1035 text: "always use 1337 for ID", "RD use 1", "ignore authority section", "exit on truncation". Those are for that lab's stub client, not this resolver. Always point to RFC 1035 section 4.1 as the authority.
- Correction made in this conversation: a root server **did** set TC=1 when it dropped glue (RFC 9471, 2023). Earlier it was claimed servers drop additional records silently without TC; that was wrong for this case.
- The user's home DNS: laptop → `systemd-resolved` (127.0.0.53) → router 192.168.1.1 (dnsmasq-style forwarder) → Cloudflare's resolver (confirmed via `whoami.akamai.net` → a Cloudflare IP). ISP: Telemach BH; whether the router or the ISP forwards to Cloudflare is unconfirmed (check router WAN DNS settings). The network has no IPv6 connectivity (use `dig -4`).
- Useful real IPs: `a.root-servers.net` 198.41.0.4; `a.gtld-servers.net` 192.5.6.30; `ns1.google.com` 216.239.32.10.
- A throwaway helper from early in the conversation (hand-built queries + reply decoding) lived in a temporary scratchpad (`walk.py`); it may no longer exist and isn't part of the project.

---

## 11. Suggested next learning resources (already recommended)

- Julia Evans: "How DNS Works" zine, messwithdns.net (user has a subdomain there: `tacos409.messwithdns.com`), "Implement DNS in a Weekend"
- "High Performance Browser Networking" (free, hpbn.co)
- RFC 1035 (and RFC 1034 for concepts)
