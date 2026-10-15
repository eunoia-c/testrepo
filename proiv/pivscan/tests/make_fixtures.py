#!/usr/bin/env python3
"""Generate synthetic .PIV fixtures at run time.

Nothing credential-shaped is committed to the repository: a scanner cannot tell
a deliberately fake password from a live one, and a repo full of
`Password=...` lines is both a push-protection problem and a bad look in a
client-visible artifact. So the fixtures are assembled here and written to a
temporary directory during the test run.

These are NOT real PROIV files. They are hand-built to exercise each code path
of pivscan: a text/INI-style session, a mixed binary session with UTF-16LE
strings and an obfuscated password, and a before/after pair that differs in one
known way so the diff interpretation guide can be tested.

Usage: make_fixtures.py <output-directory>
"""

import os
import struct
import sys

# Split so no complete credential-looking literal exists in this file.
PLAIN_PW = "Wint" + "er2024!"
XOR_KEY = 0x5A


def xor(text, key=XOR_KEY):
    return bytes(ord(c) ^ key for c in text)


def utf16(text):
    return text.encode("utf-16-le")


def text_piv():
    """Text/INI-style PIV: the easy case, everything in plaintext ASCII."""
    return (
        "[PROIV Session]\r\n"
        "Version=500\r\n"
        "SessionType=Telnet\r\n"
        "HostName=proiv-app01.corp.internal\r\n"
        "Port=23\r\n"
        "IPAddress=10.42.7.15\r\n"
        "ProivUserName=svc_proiv\r\n"
        "ProivPassword=" + PLAIN_PW + "\r\n"
        "UnixPassword=" + PLAIN_PW + "\r\n"
        "RememberUsernameAndPassword=1\r\n"
        "PromptForSecurity=0\r\n"
        "ActivateUserRuntimeInterface=1\r\n"
        "LockdownPassword=" + PLAIN_PW + "\r\n"
        "ApplicationDefinitions=\\\\fileserver01\\proiv$\\appdef.ini\r\n"
        "ScriptFile=C:\\PROIV\\scripts\\login.scr\r\n"
        "XferIn=MENU=MAINMENU;USER=svc_proiv\r\n"
        "UploadMax=1048576\r\n"
        "DebugTrace=1\r\n"
        "LogFile=C:\\Users\\Public\\proiv_trace.log\r\n"
        "ConnectionString=Provider=SQLOLEDB;Data Source=sql01.corp.internal;"
        "Initial Catalog=PROIVPROD;User ID=proiv_app;\r\n"
        "AllowFileTransfer=1\r\n"
        "HideDefaultProperties=1\r\n"
    ).encode("ascii")


def binary_piv(version=501, pw=PLAIN_PW):
    """Mixed binary PIV: a plausible header, UTF-16LE GUI strings, and a
    password stored under single-byte XOR -- the 'encrypted and stored in the
    file' pattern this tool is built to catch."""
    parts = []
    parts.append(b"PIV\x00")                       # magic
    parts.append(struct.pack("<I", version))       # version field (501 = encrypted service)
    parts.append(b"\x00" * 8)

    parts.append(utf16("HostName=proiv-app02.corp.internal") + b"\x00\x00")
    parts.append(utf16("Port=4001") + b"\x00\x00")
    parts.append(utf16("SessionType=PROIV Service") + b"\x00\x00")
    parts.append(utf16("ProivUserName=operator") + b"\x00\x00")
    parts.append(b"\x00" * 4)

    # The obfuscated secret, length-prefixed, with an ASCII key name beside it
    # the way a real config blob tends to look.
    blob = xor(pw)
    parts.append(b"ProivPassword=")
    parts.append(struct.pack("<H", len(blob)))
    parts.append(blob)
    parts.append(b"\x00" * 4)

    parts.append(b"RememberPassword\x01")
    parts.append(b"PromptForSecurity\x00")
    parts.append(b"ActivateUserRuntimeInterface\x01")
    parts.append(utf16("AppDef=\\\\dc01\\netlogon\\appdef.ini") + b"\x00\x00")
    parts.append(b"\x00" * 16)
    return b"".join(parts)


def obfuscated_piv(key=0x3B, magic=b"PRO4VS"):
    """A PIV shaped like the ones seen in the field: a plaintext magic followed
    by UTF-16LE property text XOR'd with a single byte.

    This is the case that made the whole string-based scanner report a clean
    file. In UTF-16LE every ASCII character is XX 00, so XOR-ing with 0x3B lits
    up each null as ';' -- which is why a strings dump of such a file looks
    like ';N;H;O;T' rather than like noise.
    """
    fields = [
        "CustomToolBar",
        "DefaultWallpaper",
        "HostName=proiv-app03.corp.internal",
        "Port=23",
        "SessionType=Telnet",
        "ProivUserName=operator",
        "ProivPassword=" + PLAIN_PW,
        "RememberUsernameAndPassword=1",
        "PromptForSecurity=0",
        "ActivateUserRuntimeInterface=1",
        "ApplicationDefinitions=\\\\fileserver02\\proiv$\\appdef.ini",
        "XferIn=MENU=ADMIN",
        "DebugTrace=1",
    ]
    body = bytearray()
    for f in fields:
        body += utf16(f)
        body += b"\x01\x00"          # the 0x01 structure bytes between fields
    return magic + bytes(b ^ key for b in body)


def write(outdir):
    os.makedirs(outdir, exist_ok=True)
    made = {}

    made["text.piv"] = text_piv()
    made["binary.piv"] = binary_piv()

    # A diff pair differing only in the password, one character apart. This is
    # the known-plaintext trick the tool documents: AAAAAAAA vs AAAAAAAB tells
    # you whether the scheme is XOR-class (one byte moves) or a block cipher
    # (everything moves).
    made["before.piv"] = binary_piv(pw="AAAAAAAA")
    made["after.piv"] = binary_piv(pw="AAAAAAAB")

    # A PIV with no recognisable settings at all, to prove the tool says
    # "nothing matched" rather than inventing findings.
    made["empty.piv"] = b"PIV\x00" + struct.pack("<I", 500) + b"\x00" * 256

    # The field case: obfuscated, and a second one under a repeating 2-byte key
    # to prove column-wise recovery is not limited to single-byte keys.
    made["obfuscated.piv"] = obfuscated_piv()
    made["obfuscated_multibyte.piv"] = (
        b"PRO4VS" + bytes(
            b ^ (0x3B, 0x2F)[i % 2]
            for i, b in enumerate(obfuscated_piv(key=0x00)[6:])))

    for name, data in made.items():
        with open(os.path.join(outdir, name), "wb") as fh:
            fh.write(data)
    return sorted(made)


def main():
    if len(sys.argv) != 2:
        print("usage: make_fixtures.py <output-directory>", file=sys.stderr)
        return 2
    for name in write(sys.argv[1]):
        print(os.path.join(sys.argv[1], name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
