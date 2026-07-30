#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# self-bootstrap: ensure we're running inside our own venv with deps installed.
# runs before any third-party import so the script is portable across exegol,
# kali, debian, or a random VM, no manual pip install, no system pollution.
# ---------------------------------------------------------------------------
import os as _os
import sys as _sys

_BOOTSTRAP_MARKER = "SMBACL_CRAWLER_BOOTSTRAPPED"
_REQUIREMENTS = ["impacket", "ldap3", "pyasn1", "pycryptodomex"]

def _bootstrap():
    if _os.environ.get(_BOOTSTRAP_MARKER) == "1":
        return  # already inside our venv, keep going

    import subprocess
    import venv
    from pathlib import Path

    # pick a stable cache dir: $XDG_CACHE_HOME or ~/.cache
    cache_root = Path(_os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    venv_dir = cache_root / "smbacl_crawler" / "venv"
    py_bin = venv_dir / ("Scripts" if _os.name == "nt" else "bin") / "python"

    if not py_bin.exists():
        print(f"[bootstrap] creating venv at {venv_dir}", file=_sys.stderr)
        venv_dir.parent.mkdir(parents=True, exist_ok=True)
        try:
            venv.EnvBuilder(with_pip=True, clear=False, symlinks=(_os.name != "nt")).create(str(venv_dir))
        except Exception as e:
            _sys.exit(f"[bootstrap] failed to create venv: {e}\n"
                      f"           on debian/kali you may need: apt install python3-venv")
        print(f"[bootstrap] installing {', '.join(_REQUIREMENTS)} (one-time, ~30s)",
              file=_sys.stderr)
        try:
            subprocess.check_call(
                [str(py_bin), "-m", "pip", "install", "--quiet",
                 "--disable-pip-version-check", *_REQUIREMENTS]
            )
        except subprocess.CalledProcessError as e:
            _sys.exit(f"[bootstrap] pip install failed: {e}\n"
                      f"           check your internet connection, then re-run.\n"
                      f"           to retry from scratch: rm -rf {venv_dir}")
        print("[bootstrap] done", file=_sys.stderr)

    # re-exec inside the venv
    new_env = _os.environ.copy()
    new_env[_BOOTSTRAP_MARKER] = "1"
    _os.execve(str(py_bin), [str(py_bin), __file__, *_sys.argv[1:]], new_env)

# allow disabling for dev / frozen environments: SMBACL_CRAWLER_NO_BOOTSTRAP=1
if _os.environ.get("SMBACL_CRAWLER_NO_BOOTSTRAP") != "1":
    _bootstrap()

# ---------------------------------------------------------------------------

"""
smbacl-crawler, recursive SMB ACL enumerator focused on pentest triage.

Walks an SMB share, pulls the security descriptor for every file and folder,
parses DACLs, and highlights ACEs granting dangerous rights to the current
user or specified groups. Optional LDAP lookup to auto-resolve the current
user's (transitive) group membership so "affects me" filtering is accurate.

Examples:

  # full dump of a share, color output
  ./smbacl_crawler.py //$TARGET/$SHARE -u $USER -p "$PASSWORD" -d $DOMAIN

  # only show ACEs that grant dangerous rights to something you're part of
  ./smbacl_crawler.py //$TARGET/$SHARE -u $USER -p "$PASSWORD" -d $DOMAIN \\
        --interesting-only

  # manually tell the tool which groups you consider "self" (no LDAP needed)
  ./smbacl_crawler.py //$TARGET/$SHARE -u $USER -p "$PASSWORD" \\
        --interesting-only --as-groups "Domain Users,Group A,Group B"

  # let the tool auto-resolve your group membership via LDAP (transitive)
  ./smbacl_crawler.py //$TARGET/$SHARE -u $USER -p "$PASSWORD" -d $DOMAIN \\
        --interesting-only --ldap

  # JSON for piping into jq / notes
  ./smbacl_crawler.py //$TARGET/$SHARE -u $USER -p "$PASSWORD" -d $DOMAIN \\
        --json > acls.json

  # use NT hash instead of password
  ./smbacl_crawler.py //$TARGET/$SHARE -u $USER -H :$NTHASH -d $DOMAIN

  # only check the share-level ACL (no recursive walk, very fast)
  ./smbacl_crawler.py //$TARGET/$SHARE -u $USER -p "$PASSWORD" -d $DOMAIN --scan share

  # only check NTFS ACLs (skip share ACL, useful if srvsvc is blocked)
  ./smbacl_crawler.py //$TARGET/$SHARE -u $USER -p "$PASSWORD" -d $DOMAIN --scan ntfs
"""

import argparse
import json
import re
import struct
import sys
import traceback
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, srvs
except ImportError:
    sys.exit("[-] impacket not installed. try: pip install impacket")


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

# access mask flags
READ_CONTROL            = 0x00020000
FILE_LIST_DIRECTORY     = 0x00000001

# share access
FILE_SHARE_READ         = 0x00000001
FILE_SHARE_WRITE        = 0x00000002
FILE_SHARE_DELETE       = 0x00000004

# create options
FILE_DIRECTORY_FILE     = 0x00000001
FILE_NON_DIRECTORY_FILE = 0x00000040

# create disposition
FILE_OPEN               = 0x00000001

# SMB2 query info
SMB2_0_INFO_SECURITY    = 0x03
OWNER_SECINFO           = 0x01
GROUP_SECINFO           = 0x02
DACL_SECINFO            = 0x04

# pretty names for access mask bits
ACCESS_MASK_FLAGS = [
    (0x00000001, "READ_DATA/LIST_DIR"),
    (0x00000002, "WRITE_DATA/ADD_FILE"),
    (0x00000004, "APPEND_DATA/ADD_SUBDIR"),
    (0x00000008, "READ_EA"),
    (0x00000010, "WRITE_EA"),
    (0x00000020, "EXECUTE/TRAVERSE"),
    (0x00000040, "DELETE_CHILD"),
    (0x00000080, "READ_ATTR"),
    (0x00000100, "WRITE_ATTR"),
    (0x00010000, "DELETE"),
    (0x00020000, "READ_CONTROL"),
    (0x00040000, "WRITE_DAC"),
    (0x00080000, "WRITE_OWNER"),
    (0x00100000, "SYNCHRONIZE"),
    (0x01000000, "ACCESS_SYSTEM_SECURITY"),
    (0x10000000, "GENERIC_ALL"),
    (0x20000000, "GENERIC_EXECUTE"),
    (0x40000000, "GENERIC_WRITE"),
    (0x80000000, "GENERIC_READ"),
]

# bits that mean "you can change the thing or its ACL or add/delete children"
DANGEROUS_MASK = (
    0x00000002 | 0x00000004 | 0x00000010 | 0x00000040 | 0x00000100
    | 0x00010000 | 0x00040000 | 0x00080000
    | 0x10000000 | 0x40000000
)

ACE_TYPE_NAMES = {
    0x00: "ALLOWED",
    0x01: "DENIED",
    0x05: "ALLOWED_OBJECT",
    0x06: "DENIED_OBJECT",
    0x09: "ALLOWED_CALLBACK",
    0x0A: "DENIED_CALLBACK",
}

ACE_FLAG_NAMES = [
    (0x01, "OI"),   # OBJECT_INHERIT
    (0x02, "CI"),   # CONTAINER_INHERIT
    (0x04, "NP"),   # NO_PROPAGATE_INHERIT
    (0x08, "IO"),   # INHERIT_ONLY
    (0x10, "I"),    # INHERITED
    (0x40, "SA"),   # SUCCESSFUL_ACCESS (audit)
    (0x80, "FA"),   # FAILED_ACCESS (audit)
]

WELL_KNOWN_SIDS = {
    "S-1-0-0":     "NULL",
    "S-1-1-0":     "Everyone",
    "S-1-3-0":     "CREATOR OWNER",
    "S-1-3-1":     "CREATOR GROUP",
    "S-1-5-7":     "ANONYMOUS LOGON",
    "S-1-5-9":     "ENTERPRISE DOMAIN CONTROLLERS",
    "S-1-5-11":    "Authenticated Users",
    "S-1-5-13":    "Terminal Server Users",
    "S-1-5-17":    "IUSR",
    "S-1-5-18":    "NT AUTHORITY\\SYSTEM",
    "S-1-5-19":    "NT AUTHORITY\\LOCAL SERVICE",
    "S-1-5-20":    "NT AUTHORITY\\NETWORK SERVICE",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-547": "BUILTIN\\Power Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-552": "BUILTIN\\Replicators",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compat",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM",
}

# SIDs that always count as "us" for any authenticated user
IMPLICIT_SELF_SIDS = {
    "S-1-1-0",       # Everyone
    "S-1-5-11",      # Authenticated Users
    "S-1-5-32-545",  # BUILTIN\Users
}

# paths worth shouting about on an AD engagement
HOT_PATTERNS = [
    re.compile(r"sysvol.*\\scripts(\\|$)", re.I),
    re.compile(r"sysvol.*\\policies(\\|$)", re.I),
    re.compile(r"\\netlogon(\\|$)", re.I),
    re.compile(r"\\startup(\\|$)", re.I),
    re.compile(r"\\scripts(\\|$)", re.I),
    re.compile(r"\\logon\.", re.I),
    re.compile(r"\.ps1$", re.I),
    re.compile(r"\.bat$", re.I),
    re.compile(r"\.vbs$", re.I),
    re.compile(r"gpt\.ini$", re.I),
    re.compile(r"groups\.xml$", re.I),
    re.compile(r"scheduledtasks\.xml$", re.I),
]


# ---------------------------------------------------------------------------
# SD / ACE parsing (self-contained, no external SD lib)
# ---------------------------------------------------------------------------

def parse_sid(data: bytes, offset: int) -> Tuple[str, int]:
    """parse a SID starting at `offset`, return (string, bytes_consumed)."""
    if offset < 0 or offset + 8 > len(data):
        return "", 0
    revision = data[offset]
    sub_count = data[offset + 1]
    ident_auth = int.from_bytes(data[offset + 2:offset + 8], "big")
    parts = [f"S-{revision}-{ident_auth}"]
    for i in range(sub_count):
        off = offset + 8 + i * 4
        if off + 4 > len(data):
            break
        parts.append(str(struct.unpack_from("<I", data, off)[0]))
    return "-".join(parts), 8 + sub_count * 4


def parse_sd(data: bytes) -> Tuple[str, str, List[dict]]:
    """parse a self-relative SECURITY_DESCRIPTOR into (owner_sid, group_sid, aces)."""
    if len(data) < 20:
        return "", "", []
    (_rev, _sbz1, _ctrl,
     off_owner, off_group, _off_sacl, off_dacl) = struct.unpack_from("<BBHIIII", data, 0)

    owner_sid = parse_sid(data, off_owner)[0] if off_owner else ""
    group_sid = parse_sid(data, off_group)[0] if off_group else ""

    aces: List[dict] = []
    if off_dacl and off_dacl + 8 <= len(data):
        _acl_rev, _, _acl_size, ace_count, _ = struct.unpack_from("<BBHHH", data, off_dacl)
        pos = off_dacl + 8
        for _ in range(ace_count):
            if pos + 8 > len(data):
                break
            ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", data, pos)
            mask = struct.unpack_from("<I", data, pos + 4)[0]
            sid_str, _ = parse_sid(data, pos + 8)
            aces.append({
                "type": ace_type,
                "flags": ace_flags,
                "mask": mask,
                "sid": sid_str,
            })
            if ace_size == 0:
                break
            pos += ace_size
    return owner_sid, group_sid, aces


def decode_mask(mask: int) -> List[str]:
    return [name for bit, name in ACCESS_MASK_FLAGS if mask & bit]


def decode_ace_flags(flags: int) -> str:
    parts = [name for bit, name in ACE_FLAG_NAMES if flags & bit]
    return "|".join(parts) if parts else "-"


def is_dangerous(mask: int) -> bool:
    return bool(mask & DANGEROUS_MASK)


# ---------------------------------------------------------------------------
# SID resolution + "is this me?" logic
# ---------------------------------------------------------------------------

class SIDResolver:
    def __init__(self, extra_groups: Optional[List[str]] = None):
        self.cache = dict(WELL_KNOWN_SIDS)
        self.self_sids = set(IMPLICIT_SELF_SIDS)
        self.self_names = set()
        if extra_groups:
            for g in extra_groups:
                g = g.strip()
                if g:
                    self.self_names.add(g.upper())

    def resolve(self, sid: str) -> str:
        return self.cache.get(sid, sid)

    def is_self(self, sid: str) -> bool:
        if sid in self.self_sids:
            return True
        name = self.cache.get(sid, "").upper()
        if not name:
            return False
        short = name.split("\\", 1)[1] if "\\" in name else name
        return name in self.self_names or short in self.self_names

    def load_ldap(self, server: str, domain: str, username: str, password: str):
        """best-effort: resolve current user's SID and transitive group SIDs via LDAP."""
        try:
            from ldap3 import Server, Connection as LdapConn, NTLM, SUBTREE, BASE, ALL
        except ImportError:
            print("[!] ldap3 not installed; skipping --ldap (pip install ldap3)", file=sys.stderr)
            return
        try:
            srv = Server(server, get_info=ALL)
            conn = LdapConn(
                srv,
                user=f"{domain}\\{username}",
                password=password,
                authentication=NTLM,
                auto_bind=True,
            )
        except Exception as e:
            print(f"[!] ldap bind failed: {e}", file=sys.stderr)
            return

        base = ",".join(f"DC={p}" for p in domain.split("."))

        # look up the user's own object
        try:
            conn.search(
                base,
                f"(sAMAccountName={username})",
                search_scope=SUBTREE,
                attributes=["objectSid", "memberOf", "distinguishedName"],
            )
        except Exception as e:
            print(f"[!] ldap user search failed: {e}", file=sys.stderr)
            return
        if not conn.entries:
            print(f"[!] ldap: user '{username}' not found under {base}", file=sys.stderr)
            return

        entry = conn.entries[0]
        user_dn = entry.entry_dn
        try:
            usid = entry.objectSid.value
            if usid:
                self.self_sids.add(usid)
                self.cache[usid] = f"{domain.upper()}\\{username}"
        except Exception:
            pass

        # transitive membership via LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941)
        found = 0
        try:
            conn.search(
                base,
                f"(member:1.2.840.113556.1.4.1941:={user_dn})",
                search_scope=SUBTREE,
                attributes=["objectSid", "sAMAccountName"],
            )
            for ge in conn.entries:
                try:
                    gsid = ge.objectSid.value
                    gname = ge.sAMAccountName.value
                    if gsid:
                        self.self_sids.add(gsid)
                        self.cache[gsid] = f"{domain.upper()}\\{gname}"
                        found += 1
                except Exception:
                    continue
        except Exception as e:
            print(f"[!] transitive group search failed ({e}); falling back to memberOf",
                  file=sys.stderr)
            try:
                for dn in entry.memberOf.values:
                    conn.search(dn, "(objectClass=group)",
                                search_scope=BASE,
                                attributes=["objectSid", "sAMAccountName"])
                    for ge in conn.entries:
                        try:
                            gsid = ge.objectSid.value
                            gname = ge.sAMAccountName.value
                            if gsid:
                                self.self_sids.add(gsid)
                                self.cache[gsid] = f"{domain.upper()}\\{gname}"
                                found += 1
                        except Exception:
                            continue
            except Exception:
                pass

        print(f"[+] ldap: resolved current principal + {found} group SID(s)",
              file=sys.stderr)


# ---------------------------------------------------------------------------
# crawler
# ---------------------------------------------------------------------------

# error classification for share-level RPC failures: the srvsvc pipe is often
# restricted to administrators on hardened Windows hosts, and we want the
# user-facing message to reflect that clearly instead of dumping a raw trace.

_ACCESS_DENIED_NEEDLES = (
    "access_denied",
    "access denied",
    "rpc_s_access_denied",
    "0x5",
    "nca_s_unk_if",           # interface not registered (pipe closed to us)
    "rpc_s_protseq_not_supported",
    "status_access_denied",
)

_PIPE_CLOSED_NEEDLES = (
    "broken pipe",
    "connection reset",
    "connection aborted",
    "connection refused",
    "nca_s_comm_failure",
)


def _classify_srvsvc_error(exc: Exception) -> str:
    """turn a raw RPC/SMB exception into a short, user-friendly reason."""
    msg = str(exc).lower()
    if any(n in msg for n in _ACCESS_DENIED_NEEDLES):
        return ("access denied on \\pipe\\srvsvc (non-admin users are often "
                "blocked from querying share ACLs on hardened hosts)")
    if any(n in msg for n in _PIPE_CLOSED_NEEDLES):
        return ("srvsvc pipe unreachable (firewall, host down, or RPC "
                "service disabled)")
    # fall through: keep the original message but trimmed
    short = str(exc).splitlines()[0][:200]
    return f"srvsvc query failed: {short}"


@dataclass
class AceRow:
    type: str
    sid: str
    principal: str
    flags: str
    mask_hex: str
    rights: List[str]
    dangerous: bool
    affects_me: bool


@dataclass
class PathResult:
    path: str
    is_dir: bool
    owner: str
    group: str
    aces: List[AceRow] = field(default_factory=list)
    hot: bool = False
    error: Optional[str] = None


@dataclass
class ShareAclResult:
    share: str
    owner: str
    group: str
    aces: List[AceRow] = field(default_factory=list)
    error: Optional[str] = None


class Crawler:
    def __init__(self, server, share, username, password, domain="",
                 lmhash="", nthash="", resolver=None, max_depth=None,
                 verbose=False, scan_mode="both"):
        self.server = server
        self.share = share
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.resolver = resolver or SIDResolver()
        self.max_depth = max_depth
        self.verbose = verbose
        self.scan_mode = scan_mode  # "both", "ntfs", or "share"
        self.smb: Optional[SMBConnection] = None
        self.tid: Optional[int] = None
        self.results: List[PathResult] = []
        self.share_result: Optional[ShareAclResult] = None

    def connect(self):
        self.smb = SMBConnection(self.server, self.server, sess_port=445)
        self.smb.login(self.username, self.password, self.domain,
                       self.lmhash, self.nthash)
        self.tid = self.smb.connectTree(self.share)

    def disconnect(self):
        try:
            if self.tid is not None:
                self.smb.disconnectTree(self.tid)
            if self.smb is not None:
                self.smb.logoff()
        except Exception:
            pass

    # ---- low-level SD fetch ----

    def _query_sd(self, path: str, is_dir: bool) -> Tuple[Optional[bytes], Optional[str]]:
        create_opt = FILE_DIRECTORY_FILE if is_dir else FILE_NON_DIRECTORY_FILE
        try:
            fid = self.smb.openFile(
                self.tid,
                path,
                desiredAccess=READ_CONTROL,
                shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                creationOption=create_opt,
                creationDisposition=FILE_OPEN,
            )
        except Exception as e:
            return None, f"open failed: {e}"

        try:
            try:
                raw_smb = self.smb.getSMBServer()
                sd = raw_smb.queryInfo(
                    self.tid, fid,
                    infoType=SMB2_0_INFO_SECURITY,
                    fileInfoClass=0,
                    additionalInformation=OWNER_SECINFO | GROUP_SECINFO | DACL_SECINFO,
                    flags=0,
                )
                return bytes(sd), None
            except Exception as e:
                return None, f"queryInfo failed: {e}"
        finally:
            try:
                self.smb.closeFile(self.tid, fid)
            except Exception:
                pass

    # ---- share ACL fetch (srvsvc NetrShareGetInfo level 502) ----

    def fetch_share_acl(self) -> ShareAclResult:
        """pull the share-level security descriptor via MS-SRVS.

        fails gracefully: returns a ShareAclResult with `.error` set rather
        than raising, so the caller can continue with the NTFS walk.
        """
        try:
            rpctransport = transport.SMBTransport(
                self.server, 445, r"\srvsvc",
                self.username, self.password, self.domain,
                self.lmhash, self.nthash,
                doKerberos=False,
            )
            # reuse the existing SMB session so we don't re-auth
            rpctransport.set_smb_connection(self.smb)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrShareGetInfo(dce, self.share + "\x00", 502)
            try:
                dce.disconnect()
            except Exception:
                pass
        except Exception as e:
            return ShareAclResult(
                self.share, "", "", [],
                _classify_srvsvc_error(e),
            )

        try:
            info = resp["InfoStruct"]["ShareInfo502"]
            sd_raw = info["shi502_security_descriptor"]
            if not sd_raw:
                return ShareAclResult(
                    self.share, "", "", [],
                    "no share SD returned (share likely uses the default "
                    "'Everyone: Full Control' at the share layer)",
                )
            sd_bytes = bytes(sd_raw)
        except Exception as e:
            return ShareAclResult(self.share, "", "", [], f"SD extraction failed: {e}")

        owner_sid, group_sid, raw_aces = parse_sd(sd_bytes)
        rows: List[AceRow] = []
        for a in raw_aces:
            mask = a["mask"]
            sid = a["sid"]
            rows.append(AceRow(
                type=ACE_TYPE_NAMES.get(a["type"], f"TYPE_0x{a['type']:02x}"),
                sid=sid,
                principal=self.resolver.resolve(sid),
                flags=decode_ace_flags(a["flags"]),
                mask_hex=f"0x{mask:08x}",
                rights=decode_mask(mask),
                dangerous=is_dangerous(mask),
                affects_me=self.resolver.is_self(sid),
            ))
        return ShareAclResult(
            share=self.share,
            owner=self.resolver.resolve(owner_sid),
            group=self.resolver.resolve(group_sid),
            aces=rows,
        )

    # ---- per-path processing ----

    def _make_result(self, path: str, is_dir: bool) -> PathResult:
        display = path if path else "\\"
        sd_bytes, err = self._query_sd(path, is_dir)
        if err or sd_bytes is None:
            return PathResult(display, is_dir, "", "", [], False, err or "no SD")

        owner_sid, group_sid, raw_aces = parse_sd(sd_bytes)
        rows: List[AceRow] = []
        for a in raw_aces:
            mask = a["mask"]
            sid = a["sid"]
            rows.append(AceRow(
                type=ACE_TYPE_NAMES.get(a["type"], f"TYPE_0x{a['type']:02x}"),
                sid=sid,
                principal=self.resolver.resolve(sid),
                flags=decode_ace_flags(a["flags"]),
                mask_hex=f"0x{mask:08x}",
                rights=decode_mask(mask),
                dangerous=is_dangerous(mask),
                affects_me=self.resolver.is_self(sid),
            ))
        hot = any(p.search(display) for p in HOT_PATTERNS)
        return PathResult(
            path=display,
            is_dir=is_dir,
            owner=self.resolver.resolve(owner_sid),
            group=self.resolver.resolve(group_sid),
            aces=rows,
            hot=hot,
        )

    # ---- walking ----

    def walk(self, start: str = "", depth: int = 0):
        res = self._make_result(start, is_dir=True)
        self.results.append(res)

        if self.verbose:
            disp = start if start else "\\"
            aces = len(res.aces) if not res.error else 0
            print(f"[.] {disp}  ({aces} ACEs)", file=sys.stderr)

        if self.max_depth is not None and depth >= self.max_depth:
            return

        pattern = (start.rstrip("\\") + "\\*") if start else "*"
        try:
            children = self.smb.listPath(self.share, pattern)
        except Exception as e:
            self.results.append(PathResult(
                path=(start or "\\") + " [*]",
                is_dir=True, owner="", group="",
                error=f"listPath failed: {e}",
            ))
            return

        for entry in children:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            child = (start.rstrip("\\") + "\\" + name) if start else name
            if entry.is_directory():
                try:
                    self.walk(child, depth + 1)
                except Exception as e:
                    self.results.append(PathResult(
                        path=child, is_dir=True, owner="", group="",
                        error=f"walk failed: {e}",
                    ))
            else:
                try:
                    self.results.append(self._make_result(child, is_dir=False))
                except Exception as e:
                    self.results.append(PathResult(
                        path=child, is_dir=False, owner="", group="",
                        error=f"sd failed: {e}",
                    ))


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------

C_RESET   = "\033[0m"
C_RED     = "\033[31m"
C_GREEN   = "\033[32m"
C_YELLOW  = "\033[33m"
C_CYAN    = "\033[36m"
C_MAGENTA = "\033[35m"
C_BOLD    = "\033[1m"
C_DIM     = "\033[2m"


def c(s: str, col: str, on: bool) -> str:
    return f"{col}{s}{C_RESET}" if on else s


def _print_ace_line(ace: AceRow, use_color: bool):
    if ace.dangerous and ace.affects_me:
        col = C_RED + C_BOLD
        marker = "!!"
    elif ace.dangerous:
        col = C_YELLOW
        marker = " *"
    elif ace.affects_me:
        col = C_GREEN
        marker = " +"
    else:
        col = ""
        marker = "  "
    rights = ",".join(ace.rights) if ace.rights else "-"
    line = (f"  {marker} {ace.type:<8} {ace.principal:<42} "
            f"[{ace.flags:<10}] {ace.mask_hex}  {rights}")
    print(c(line, col, use_color))


def print_share_acl(share_res: ShareAclResult, interesting_only: bool, use_color: bool):
    header = f"[SHARE] \\\\...\\{share_res.share}  (share-level ACL)"
    print(c(header, C_BOLD + C_MAGENTA, use_color))

    if share_res.error:
        print("  " + c(f"note: {share_res.error}", C_YELLOW, use_color))
        print()
        return

    print(f"  owner: {share_res.owner}")
    print(f"  group: {share_res.group}")

    aces = share_res.aces
    if interesting_only:
        aces = [a for a in share_res.aces if a.affects_me]

    if not aces:
        print(c("  (no matching ACEs)", C_DIM, use_color))
        print()
        return

    for ace in aces:
        _print_ace_line(ace, use_color)
    print()


def print_text(results: List[PathResult], interesting_only: bool, use_color: bool):
    for res in results:
        aces = res.aces
        if interesting_only:
            aces = [a for a in res.aces if a.affects_me and a.dangerous]
            if not aces and not res.hot:
                continue

        kind = "[DIR] " if res.is_dir else "[FILE]"
        header = f"{kind} {res.path}"
        if res.hot:
            header += "   " + c("!! HOT PATH !!", C_MAGENTA + C_BOLD, use_color)
        print(c(header, C_BOLD + C_CYAN, use_color))

        if res.error:
            print("  " + c(f"error: {res.error}", C_RED, use_color))
            print()
            continue

        print(f"  owner: {res.owner}")
        print(f"  group: {res.group}")

        if not aces:
            print(c("  (no matching ACEs)", C_DIM, use_color))
            print()
            continue

        for ace in aces:
            _print_ace_line(ace, use_color)
        print()


def print_json(results: List[PathResult], share_res: Optional[ShareAclResult]):
    out = {
        "share_acl": asdict(share_res) if share_res else None,
        "paths": [asdict(r) for r in results],
    }
    json.dump(out, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def print_summary(results: List[PathResult], share_res: Optional[ShareAclResult],
                  use_color: bool):
    total = len(results)
    errs = sum(1 for r in results if r.error)
    hits = []
    for r in results:
        for a in r.aces:
            if a.dangerous and a.affects_me:
                hits.append((r.path, a))

    share_writable_for_me = None
    if share_res and not share_res.error:
        share_writable_for_me = any(
            a.affects_me and a.dangerous and a.type == "ALLOWED"
            for a in share_res.aces
        )

    print(file=sys.stderr)
    print(c("=" * 70, C_CYAN, use_color), file=sys.stderr)
    print(c(f"summary: {total} paths walked, {errs} errors", C_BOLD, use_color),
          file=sys.stderr)

    if share_res is not None:
        if share_res.error:
            print(c(f"share ACL: {share_res.error}", C_YELLOW, use_color),
                  file=sys.stderr)
        elif share_writable_for_me:
            print(c("share ACL: you have write access at the share layer",
                    C_GREEN + C_BOLD, use_color), file=sys.stderr)
        else:
            print(c("share ACL: NO write access at the share layer "
                    "(NTFS writes will be blocked)",
                    C_RED + C_BOLD, use_color), file=sys.stderr)

    hit_color = (C_RED if hits else C_GREEN) + C_BOLD
    print(c(f"dangerous NTFS ACEs affecting you: {len(hits)}", hit_color, use_color),
          file=sys.stderr)

    if hits and share_res is not None and share_writable_for_me is False:
        print(c("  WARNING: share ACL blocks writes, so the NTFS hits below "
                "are not actually exploitable as writes.",
                C_YELLOW + C_BOLD, use_color), file=sys.stderr)

    for path, ace in hits[:60]:
        rights = ",".join(ace.rights)
        msg = f"  !! {path}  <-  {ace.principal}  [{rights}]"
        print(c(msg, C_RED, use_color), file=sys.stderr)
    if len(hits) > 60:
        print(c(f"  ... and {len(hits) - 60} more", C_DIM, use_color), file=sys.stderr)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def parse_target(target: str) -> Tuple[str, str]:
    m = re.match(r"^(?://|\\\\)?([^/\\]+)[/\\]([^/\\]+)/?$", target)
    if not m:
        sys.exit(f"[-] invalid target '{target}', expected //HOST/SHARE")
    return m.group(1), m.group(2)


def main():
    p = argparse.ArgumentParser(
        description="Recursive SMB ACL enumerator with 'affects me' filtering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("target", help="//HOST/SHARE")
    p.add_argument("-u", "--user", required=True)
    p.add_argument("-p", "--password", default="")
    p.add_argument("-d", "--domain", default="")
    p.add_argument("-H", "--hashes", default="",
                   help="LM:NT (or just :NT) to auth with an NT hash")

    p.add_argument("--start-path", default="",
                   help="start path inside the share (default: share root)")
    p.add_argument("--depth", type=int, default=None,
                   help="max recursion depth (default: unlimited)")

    p.add_argument("--interesting-only", action="store_true",
                   help="only show ACEs granting dangerous rights to you or groups "
                        "you're in (still shows HOT PATHs)")
    p.add_argument("--as-groups", default="",
                   help="comma-separated list of principals to count as 'self', "
                        "e.g. 'Domain Users,IT Support,Helpdesk'")
    p.add_argument("--ldap", action="store_true",
                   help="query LDAP to auto-resolve your (transitive) group membership")
    p.add_argument("--ldap-server", default="",
                   help="LDAP server host (default: same as target)")

    p.add_argument("--scan", choices=["both", "ntfs", "share"], default="both",
                   help="which ACL layer to enumerate: 'both' (default), 'ntfs' "
                        "(file/folder SDs only), or 'share' (share-level SD only). "
                        "effective access is the intersection of both layers, so "
                        "'both' is recommended unless you know what you're after")

    p.add_argument("--json", action="store_true", help="emit JSON on stdout")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")

    args = p.parse_args()

    host, share = parse_target(args.target)

    lmhash = nthash = ""
    if args.hashes:
        if ":" in args.hashes:
            lmhash, nthash = args.hashes.split(":", 1)
        else:
            nthash = args.hashes

    use_color = (not args.no_color) and sys.stdout.isatty() and (not args.json)

    extra_groups: List[str] = []
    if args.as_groups:
        extra_groups.extend(g for g in args.as_groups.split(",") if g.strip())
    # the user themselves should always match
    extra_groups.append(args.user)

    resolver = SIDResolver(extra_groups=extra_groups)

    if args.ldap:
        if not args.domain:
            print("[!] --ldap requires --domain to build the search base", file=sys.stderr)
        else:
            ldap_srv = args.ldap_server or host
            resolver.load_ldap(ldap_srv, args.domain, args.user, args.password)

    crawler = Crawler(
        server=host, share=share,
        username=args.user, password=args.password, domain=args.domain,
        lmhash=lmhash, nthash=nthash,
        resolver=resolver, max_depth=args.depth, verbose=args.verbose,
        scan_mode=args.scan,
    )

    dom_disp = args.domain + "\\" if args.domain else ""
    print(f"[+] connecting to //{host}/{share} as {dom_disp}{args.user}", file=sys.stderr)
    try:
        crawler.connect()
    except Exception as e:
        sys.exit(f"[-] connection failed: {e}")

    if args.scan in ("both", "share"):
        print("[+] fetching share-level ACL via srvsvc", file=sys.stderr)
        try:
            crawler.share_result = crawler.fetch_share_acl()
        except Exception as e:
            # belt-and-suspenders: fetch_share_acl should never raise, but if
            # it ever does, don't crash the whole run.
            crawler.share_result = ShareAclResult(share, "", "", [], str(e))

        if crawler.share_result and crawler.share_result.error:
            reason = crawler.share_result.error
            if args.scan == "share":
                # user asked only for share ACLs and we couldn't get them, exit
                # loudly so they know nothing was done.
                print(f"[-] share ACL fetch failed: {reason}", file=sys.stderr)
                print("[-] nothing else to do in --scan share mode, exiting",
                      file=sys.stderr)
                crawler.disconnect()
                sys.exit(2)
            else:
                # --scan both: degrade gracefully to NTFS-only with a clear
                # warning, so the user still gets useful output.
                print(f"[!] could not read share ACL ({reason})", file=sys.stderr)
                print("[!] falling back to NTFS permissions only",
                      file=sys.stderr)

    if args.scan in ("both", "ntfs"):
        start_disp = args.start_path if args.start_path else "\\"
        print(f"[+] walking from '{start_disp}'", file=sys.stderr)
        try:
            crawler.walk(args.start_path)
        except KeyboardInterrupt:
            print("[!] interrupted, dumping partial results", file=sys.stderr)
        except Exception as e:
            print(f"[!] walk error: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

    crawler.disconnect()

    if args.json:
        print_json(crawler.results, crawler.share_result)
    else:
        if crawler.share_result is not None:
            print_share_acl(crawler.share_result, args.interesting_only, use_color)
        print_text(crawler.results, args.interesting_only, use_color)
        print_summary(crawler.results, crawler.share_result, use_color)


if __name__ == "__main__":
    main()
