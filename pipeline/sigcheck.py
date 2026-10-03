"""Authenticode signer analysis: who actually signed this driver, and is the
signing certificate a *production* one or a test / private-CA cert?

The old approach ([`index._cert_cns`]) scanned the PKCS#7 blob for every
``commonName`` attribute and returned them as one flat list. That mixes the
signer's leaf certificate, every intermediate CA, the root, *and* the
timestamp-authority chain — so "has a VeriSign/DigiCert name in it" says nothing
about whether the thing was signed by a production code-signing certificate: a
``WDKTestCert`` driver timestamped by a commercial TSA looks identical.

This module parses the PKCS#7 structure properly enough to tell those apart:

  * walk the DER, collecting every X.509 certificate it contains;
  * for each cert pull ``subject`` CN, ``issuer`` CN, the code-signing EKU flag,
    and the basic-constraints CA flag (ordered parse — issuer vs subject are not
    guessed);
  * identify the **signer leaf** (a non-CA cert bearing the code-signing EKU);
  * classify it: ``production`` (leaf whose chain reaches a recognised public CA,
    no test markers), ``test`` (WDK test cert, "Test"/"DO NOT TRUST" markers),
    ``private`` (leaf with no path to a public root — in-house CA), ``unsigned``,
    or ``unknown``.

When a real verifier is available (``signtool`` on Windows, ``osslsigncode`` on
Linux) :func:`verify_file` shells out for an authoritative trust verdict; the
pure-Python classifier is always computed too, as a fallback and for the names.
Pure-stdlib: a small DER TLV reader, no ``cryptography``/``asn1`` dependency.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from . import config

# ---------------------------------------------------------------- OIDs we read
_OID_CN = bytes([0x06, 0x03, 0x55, 0x04, 0x03])           # 2.5.4.3  commonName
_OID_O = bytes([0x06, 0x03, 0x55, 0x04, 0x0A])            # 2.5.4.10 organizationName
_OID_EKU = bytes([0x06, 0x03, 0x55, 0x1D, 0x25])          # 2.5.29.37 extKeyUsage
_OID_BASIC = bytes([0x06, 0x03, 0x55, 0x1D, 0x13])        # 2.5.29.19 basicConstraints
_OID_CODESIGN = bytes([0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03])  # 1.3.6.1.5.5.7.3.3

# Name fragments of certificate authorities that issue *public* code-signing
# certs. Derived from the corpus itself (every production signer in the net
# chains through one of these) plus the other mainstream CAs. Matched against a
# cert's issuer/root CN, case-insensitive. This is the "is it a real public CA"
# test — deliberately a name allowlist, since without live chain building the CN
# is the signal we have; `verify_file` is the authoritative check when present.
_PUBLIC_CA = (
    "verisign", "symantec", "thawte", "digicert", "globalsign", "sectigo",
    "comodo", "entrust", "godaddy", "go daddy", "geotrust", "starfield",
    "usertrust", "addtrust", "baltimore", "identrust", "quovadis", "swisssign",
    "actalis", "unizeto", "certum", "trustwave", "amazon", "google trust",
    "apple", "cybertrust", "network solutions", "tc trustcenter", "keynectis",
    "valicert", "wells fargo", "microsoft",
)

# Substrings that positively mark a NON-production (test / development) signer.
_TEST_MARKERS = re.compile(
    r"wdktest|test cert|do not trust|donottrust|\.test\b|\(test\)|testsign|"
    r"test certificate|internal testing|\bsample\b|\bexample\b",
    re.I,
)


# --------------------------------------------------------------- DER TLV reader


class _Node:
    __slots__ = ("tag", "start", "hlen", "length", "end", "data")

    def __init__(self, tag: int, start: int, hlen: int, length: int, data: bytes):
        self.tag = tag
        self.start = start
        self.hlen = hlen
        self.length = length
        self.end = start + hlen + length
        self.data = data

    @property
    def body(self) -> bytes:
        return self.data[self.start + self.hlen:self.end]

    def children(self) -> list["_Node"]:
        return _parse_seq(self.data, self.start + self.hlen, self.end)


def _read_tlv(data: bytes, off: int, end: int) -> _Node | None:
    """Read one DER TLV at `off`; return None on malformed/truncated input."""
    if off + 2 > end:
        return None
    tag = data[off]
    lb = data[off + 1]
    p = off + 2
    if lb & 0x80:
        nb = lb & 0x7F
        if nb == 0 or p + nb > end:
            return None
        length = int.from_bytes(data[p:p + nb], "big")
        hlen = 2 + nb
    else:
        length = lb
        hlen = 2
    if off + hlen + length > end:
        return None
    return _Node(tag, off, hlen, length, data)


def _parse_seq(data: bytes, off: int, end: int) -> list[_Node]:
    out: list[_Node] = []
    while off < end:
        n = _read_tlv(data, off, end)
        if n is None:
            break
        out.append(n)
        off = n.end
    return out


def _walk(data: bytes, off: int, end: int, depth: int = 0):
    """Yield every TLV node in the tree (constructed nodes are recursed)."""
    if depth > 40:
        return
    for n in _parse_seq(data, off, end):
        yield n
        if n.tag & 0x20:  # constructed
            yield from _walk(data, n.start + n.hlen, n.end, depth + 1)


# ----------------------------------------------------------- certificate model


def _rdn_attr(name_node: _Node, oid: bytes) -> str | None:
    """First value of attribute `oid` within an X.509 Name (RDNSequence)."""
    body = name_node.data[name_node.start + name_node.hlen:name_node.end]
    i = name_node.start + name_node.hlen
    end = name_node.end
    while i < end:
        rdn = _read_tlv(name_node.data, i, end)       # SET
        if rdn is None:
            break
        for atv in rdn.children():                    # SEQUENCE type,value
            kids = atv.children()
            if len(kids) == 2 and name_node.data[kids[0].start:kids[0].end] == oid:
                return kids[1].body.decode("utf-8", "replace").strip()
        i = rdn.end
    return None


class _Cert:
    def __init__(self, seq: _Node):
        self.subject_cn: str | None = None
        self.subject_o: str | None = None
        self.issuer_cn: str | None = None
        self.is_ca = False
        self.code_signing = False
        self.ok = False
        self._parse(seq)

    def _parse(self, seq: _Node) -> None:
        kids = seq.children()
        if not kids:
            return
        tbs = kids[0]
        tkids = tbs.children()
        # version [0] is optional and explicit; serial is the first INTEGER
        idx = 0
        if tkids and (tkids[0].tag & 0xC0) == 0x80:   # [0] EXPLICIT version
            idx = 1
        # order: serial INTEGER, sigAlg SEQUENCE, issuer Name, validity, subject Name
        try:
            # serial
            idx += 1                                   # skip serialNumber
            idx += 1                                   # skip signature AlgId
            issuer = tkids[idx]; idx += 1
            idx += 1                                   # skip validity
            subject = tkids[idx]; idx += 1
        except IndexError:
            return
        self.issuer_cn = _rdn_attr(issuer, _OID_CN)
        self.subject_cn = _rdn_attr(subject, _OID_CN)
        self.subject_o = _rdn_attr(subject, _OID_O)
        # extensions live in [3] EXPLICIT at the tail of tbs
        for n in tkids[idx:]:
            if (n.tag & 0xC0) == 0x80 and (n.tag & 0x1F) == 3:
                self._parse_extensions(n)
        self.ok = True

    def _parse_extensions(self, ext_ctx: _Node) -> None:
        inner = ext_ctx.children()
        if not inner:
            return
        for ext in inner[0].children():               # SEQUENCE OF Extension
            ekids = ext.children()
            if not ekids:
                continue
            oid_raw = ext.data[ekids[0].start:ekids[0].end]
            val = ekids[-1]                            # extnValue OCTET STRING
            payload = val.data[val.start + val.hlen:val.end]
            if oid_raw == _OID_EKU:
                if _OID_CODESIGN in payload:
                    self.code_signing = True
            elif oid_raw == _OID_BASIC:
                # SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
                sub = _read_tlv(payload, 0, len(payload))
                if sub is not None:
                    for c in sub.children():
                        if c.tag == 0x01 and c.body and c.body[0] != 0:
                            self.is_ca = True

    @property
    def name(self) -> str | None:
        return self.subject_cn or self.subject_o


def _collect_certs(der: bytes) -> list[_Cert]:
    """Every X.509 certificate anywhere in the PKCS#7 tree.

    A Certificate is a SEQUENCE whose first child is the tbsCertificate SEQUENCE
    and which carries exactly three children (tbs, sigAlg, sigValue BIT STRING).
    Collecting by shape catches the signer leaf, the intermediate CAs and the
    timestamp chain alike; the caller sorts out which is which.
    """
    certs: list[_Cert] = []
    seen: set[tuple[int, int]] = set()
    for n in _walk(der, 0, len(der)):
        if n.tag != 0x30:                              # SEQUENCE
            continue
        kids = n.children()
        if len(kids) == 3 and kids[0].tag == 0x30 and kids[2].tag == 0x03:
            key = (n.start, n.end)
            if key in seen:
                continue
            c = _Cert(n)
            if c.ok and (c.subject_cn or c.subject_o):
                seen.add(key)
                certs.append(c)
    return certs


# --------------------------------------------------------------- classification


def classify(der: bytes) -> dict:
    """Static signer analysis of a PKCS#7 blob (the Authenticode bCertificate).

    Returns the signer leaf's names and a ``cert_class`` verdict. No network, no
    trust store — a name-and-structure heuristic. :func:`verify_file` is the
    authoritative check when a verifier is installed.
    """
    certs = _collect_certs(der)
    if not certs:
        return {"cert_class": "unknown", "cert_common_names": []}

    all_cns: list[str] = []
    for c in certs:
        if c.subject_cn and c.subject_cn not in all_cns:
            all_cns.append(c.subject_cn)

    subjects = {c.subject_cn for c in certs if c.subject_cn}
    # signer leaf: a non-CA cert carrying the code-signing EKU. Prefer one whose
    # issuer is some *other* cert in the bag (a real chain), else any such leaf.
    leaves = [c for c in certs if c.code_signing and not c.is_ca]
    if not leaves:
        # some older signers omit EKU on the leaf; fall back to a non-CA cert
        # that is nobody's issuer (i.e. a chain tail) and not a timestamp cert.
        issuers = {c.issuer_cn for c in certs}
        leaves = [c for c in certs
                  if not c.is_ca and c.subject_cn and c.subject_cn not in issuers
                  and not _looks_timestamp(c)]
    leaf = None
    for c in leaves:
        if c.issuer_cn in subjects:
            leaf = c
            break
    leaf = leaf or (leaves[0] if leaves else None)

    out: dict = {"cert_common_names": all_cns[:16]}
    if leaf is None:
        out["cert_class"] = "unknown"
        return out

    out["signer_cn"] = leaf.name
    out["issuer_cn"] = leaf.issuer_cn
    out["eku_code_signing"] = leaf.code_signing

    # build the leaf's issuer chain (by CN) to find the root it reaches
    chain_cns = _issuer_chain(leaf, certs)
    out["chain"] = chain_cns

    blob_text = " | ".join(all_cns)
    if _TEST_MARKERS.search(leaf.name or "") or _TEST_MARKERS.search(blob_text):
        out["cert_class"] = "test"
    elif any(_is_public_ca(cn) for cn in chain_cns):
        out["cert_class"] = "production"
    else:
        # a real-looking leaf that never reaches a recognised public root:
        # in-house / private CA (e.g. "OEMR Certificate Authority").
        out["cert_class"] = "private"
    return out


def _looks_timestamp(c: _Cert) -> bool:
    s = (c.subject_cn or "") + " " + (c.issuer_cn or "")
    return bool(re.search(r"time.?stamp|timestamping|tsa\b", s, re.I))


def _is_public_ca(cn: str | None) -> bool:
    if not cn:
        return False
    low = cn.lower()
    return any(frag in low for frag in _PUBLIC_CA)


def _issuer_chain(leaf: _Cert, certs: list[_Cert], limit: int = 10) -> list[str]:
    """Walk issuer -> subject links from the leaf, returning CNs along the way."""
    by_subject: dict[str, _Cert] = {c.subject_cn: c for c in certs if c.subject_cn}
    chain: list[str] = []
    cur = leaf
    seen: set[str] = set()
    for _ in range(limit):
        iss = cur.issuer_cn
        if not iss or iss in seen:
            break
        chain.append(iss)
        seen.add(iss)
        nxt = by_subject.get(iss)
        if nxt is None or nxt is cur:
            break
        cur = nxt
    return chain


# ------------------------------------------------------------- real verifier


def verify_file(path: Path) -> dict | None:
    """Authoritative trust verdict via an external verifier, if one is installed.

    Tries ``signtool verify /pa`` (Windows) then ``osslsigncode verify`` (Linux).
    Returns ``{"tool", "trusted": bool, "detail"}`` or ``None`` when no verifier
    is available (then only the static :func:`classify` verdict stands).
    """
    st = config.signtool()
    if st is not None:
        try:
            r = subprocess.run([str(st), "verify", "/pa", "/q", str(path)],
                               capture_output=True, text=True, timeout=60)
            return {"tool": "signtool", "trusted": r.returncode == 0,
                    "detail": (r.stdout or r.stderr).strip()[:200]}
        except (OSError, subprocess.SubprocessError):
            pass
    oss = _which_osslsigncode()
    if oss is not None:
        try:
            r = subprocess.run([oss, "verify", "-in", str(path)],
                               capture_output=True, text=True, timeout=60)
            txt = (r.stdout or "") + (r.stderr or "")
            trusted = r.returncode == 0 and "Signature verification: ok" in txt
            return {"tool": "osslsigncode", "trusted": trusted,
                    "detail": _osslsigncode_summary(txt)}
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def _which_osslsigncode() -> str | None:
    import shutil
    return shutil.which("osslsigncode")


def _osslsigncode_summary(txt: str) -> str:
    keep = [ln.strip() for ln in txt.splitlines()
            if re.search(r"signature|subject|issuer|timestamp|verification", ln, re.I)]
    return " | ".join(keep)[:300]
