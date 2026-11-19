# SPDX-License-Identifier: Apache-2.0
"""What a binary file really is, and the text it carries beside its picture or sound.

A suffix proves nothing: a text payload can be named ``.mp3``.  :func:`sniff` checks the magic
bytes of each accepted media type, and :func:`metadata_texts` returns every text the file holds
outside its sample data (ID3 frames, PNG text chunks, JPEG comment and APPn segments, and every
printable run of the formats that are not parsed), so the gate can scan it like any other text.  A
file that does not parse is refused (:class:`MediaError`), never skipped.  Standard library only.
"""

from __future__ import annotations

import re
import struct
import zlib
from pathlib import Path

MAX_MEDIA_BYTES = 256 * 1024 * 1024
_RUN = re.compile(rb"[\x20-\x7e\t\r\n]{6,}")
_RUN16LE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_RUN16BE = re.compile(rb"(?:\x00[\x20-\x7e]){6,}")
PNG_SIG = b"\x89PNG\r\n\x1a\n"

#: magic bytes that no text file may start with (a binary named as text is refused)
BINARY_MAGICS = (
    PNG_SIG,
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"ID3",
    b"wOFF",
    b"wOF2",
    b"PK\x03\x04",
    b"%PDF",
    b"MZ",
    b"\x7fELF",
    b"\x1f\x8b",
)


class MediaError(ValueError):
    pass


def printable_text(data: bytes) -> str:
    """Every printable run of 6 bytes or more (ASCII, UTF-16 either way), one per line."""
    out = [m.group().decode("ascii") for m in _RUN.finditer(data)]
    out += [m.group().decode("utf-16-le") for m in _RUN16LE.finditer(data)]
    out += [m.group().decode("utf-16-be") for m in _RUN16BE.finditer(data)]
    return "\n".join(out)


def sniff(suffix: str, data: bytes) -> bool:
    """Whether ``data`` starts as a file of this suffix's type does."""
    head = data[:12]
    if suffix == ".mp3":
        return head.startswith(b"ID3") or (
            len(head) >= 2 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0
        )
    if suffix == ".png":
        return head.startswith(PNG_SIG)
    if suffix in (".jpg", ".jpeg"):
        return head.startswith(b"\xff\xd8\xff")
    if suffix == ".ico":
        return head[:4] == b"\x00\x00\x01\x00"
    return False


def looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:65536] or data.startswith(BINARY_MAGICS)


def _syncsafe(b: bytes) -> int:
    if any(x & 0x80 for x in b):
        raise MediaError("a size that is not syncsafe")
    n = 0
    for x in b:
        n = (n << 7) | x
    return n


_ENC = {0: "latin-1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}


_ENC = {0: "latin-1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}
_TEXT_FRAMES = ("T", "W")
_OTHER_FRAMES = ("COMM", "USLT", "APIC", "COM", "ULT", "PIC")
# the registered ancillary PNG chunks; anything else (a private chunk) is refused
_PNG_KNOWN = frozenset(
    {
        b"tRNS",
        b"gAMA",
        b"cHRM",
        b"sRGB",
        b"sBIT",
        b"bKGD",
        b"hIST",
        b"pHYs",
        b"sPLT",
        b"tIME",
        b"tEXt",
        b"zTXt",
        b"iTXt",
        b"eXIf",
        b"iCCP",
        b"cICP",
        b"mDCV",
        b"cLLI",
        b"acTL",
        b"fcTL",
        b"fdAT",
    }
)
_PNG_CRITICAL = frozenset({b"IHDR", b"PLTE", b"IDAT", b"IEND"})


def _id3_frame_text(fid: str, payload: bytes) -> str:
    out = [printable_text(payload)]
    if fid[0] == "T" or fid in ("COMM", "USLT", "COM", "ULT"):
        enc = _ENC.get(payload[0]) if payload else None
        if enc is None:
            raise MediaError("an unknown text encoding")
        out.append(payload[1:].decode(enc, errors="replace").replace("\x00", "\n"))
    elif fid[0] == "W":
        out.append(payload.decode("latin-1"))
    elif fid in ("APIC", "PIC"):  # an attached picture is read as the image it is, or refused
        for sig, suffix in ((PNG_SIG, ".png"), (b"\xff\xd8\xff", ".jpg")):
            at = payload.find(sig)
            if at >= 0:
                out += metadata_texts_of(suffix, payload[at:])
                break
        else:
            raise MediaError("an attached picture that is not a PNG or a JPEG")
    return "\n".join(out)


def _mp3(data: bytes) -> list[str]:
    texts: list[str] = []
    if data.startswith(b"ID3"):
        if len(data) < 10:
            raise MediaError("a truncated ID3 header")
        ver, flags = data[3], data[5]
        if ver not in (2, 3, 4):
            raise MediaError("an unknown ID3 version")
        if flags & 0x80:
            raise MediaError("an unsynchronised ID3 tag")
        size = _syncsafe(data[6:10])
        tag = data[10 : 10 + size]
        if len(tag) != size:
            raise MediaError("an ID3 tag longer than the file")
        pos = 0
        if flags & 0x40 and ver >= 3:  # extended header
            ext = _syncsafe(tag[:4]) if ver == 4 else struct.unpack(">I", tag[:4])[0] + 4
            pos = ext
        idlen, hdr = (3, 6) if ver == 2 else (4, 10)
        while pos + hdr <= len(tag):
            if tag[pos] == 0:
                if any(tag[pos:]):
                    raise MediaError("data after ID3 padding")
                break
            fid = tag[pos : pos + idlen].decode("latin-1")
            if not re.fullmatch(r"[A-Z0-9]+", fid):
                raise MediaError("an ID3 frame id that is not an id")
            if not (fid.startswith(_TEXT_FRAMES) or fid in _OTHER_FRAMES):
                raise MediaError("an ID3 frame type outside the accepted set")
            raw = tag[pos + idlen : pos + hdr - (0 if ver == 2 else 2)]
            fsize = int.from_bytes(raw, "big") if ver != 4 else _syncsafe(raw)
            if ver >= 3:
                f2 = tag[pos + 9]
                compressed, encrypted = (
                    (f2 & 0x80, f2 & 0x40) if ver == 3 else (f2 & 0x08, f2 & 0x04)
                )
                if compressed or encrypted or (ver == 4 and f2 & 0x03):
                    raise MediaError("a compressed, encrypted or unsynchronised ID3 frame")
            body = tag[pos + hdr : pos + hdr + fsize]
            if len(body) != fsize:
                raise MediaError("an ID3 frame longer than its tag")
            texts.append(_id3_frame_text(fid, body))
            pos += hdr + fsize
        if len(tag) and not texts and any(tag):
            raise MediaError("an ID3 tag with no frame")
    if len(data) >= 128 and data[-128:-125] == b"TAG":
        texts.append(data[-128:].decode("latin-1"))
    return texts


def _png(data: bytes) -> list[str]:
    texts: list[str] = []
    pos, seen_end = 8, False
    while pos + 12 <= len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        ctype = data[pos + 4 : pos + 8]
        body = data[pos + 8 : pos + 8 + length]
        crc = data[pos + 8 + length : pos + 12 + length]
        if len(body) != length or len(crc) != 4:
            raise MediaError("a PNG chunk longer than the file")
        if struct.unpack(">I", crc)[0] != zlib.crc32(ctype + body):
            raise MediaError("a PNG chunk with a bad checksum")
        if ctype not in _PNG_CRITICAL and ctype not in _PNG_KNOWN:
            raise MediaError("a PNG chunk that is not registered (private or unknown)")
        if ctype == b"tEXt":
            texts.append(body.decode("latin-1").replace("\x00", "\n"))
        elif ctype == b"zTXt":
            kw, _, rest = body.partition(b"\x00")
            texts.append(kw.decode("latin-1") + "\n" + _inflate(rest[1:]))
        elif ctype == b"iCCP":
            kw, _, rest = body.partition(b"\x00")
            texts.append(kw.decode("latin-1") + "\n" + printable_text(_inflate_bytes(rest[1:])))
        elif ctype == b"iTXt":
            kw, _, rest = body.partition(b"\x00")
            if len(rest) < 2:
                raise MediaError("a short iTXt chunk")
            flag, rest = rest[0], rest[2:]
            _lang, _, rest = rest.partition(b"\x00")
            _tr, _, text = rest.partition(b"\x00")
            texts.append(
                kw.decode("latin-1")
                + "\n"
                + (_inflate(text) if flag else text.decode("utf-8", "replace"))
            )
        elif ctype not in _PNG_CRITICAL:
            texts.append(printable_text(body))
        pos += 12 + length
        if ctype == b"IEND":
            seen_end = True
            break
    if not seen_end:
        raise MediaError("a PNG without IEND")
    if pos != len(data):
        raise MediaError("bytes after the PNG IEND chunk")
    return texts


def _inflate_bytes(blob: bytes) -> bytes:
    d = zlib.decompressobj()
    try:
        out = d.decompress(blob, 1 << 20)
    except zlib.error as exc:
        raise MediaError("compressed data that does not inflate") from exc
    if d.unconsumed_tail:
        raise MediaError("compressed data over 1 MiB")
    return out


def _inflate(blob: bytes) -> str:
    return _inflate_bytes(blob).decode("utf-8", "replace")


def _jpeg(data: bytes) -> list[str]:
    if not data.endswith(b"\xff\xd9"):
        raise MediaError("a JPEG without its end marker as the last bytes (or bytes after it)")
    texts: list[str] = []
    pos = 2
    while pos + 2 <= len(data):
        if data[pos] != 0xFF:
            raise MediaError("a JPEG segment without a marker")
        marker = data[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xD9:
            if pos + 2 != len(data):
                raise MediaError("bytes after the JPEG end marker")
            return texts
        if pos + 4 > len(data):
            raise MediaError("a truncated JPEG segment")
        (length,) = struct.unpack(">H", data[pos + 2 : pos + 4])
        seg = data[pos + 4 : pos + 2 + length]
        if length < 2 or len(seg) != length - 2:
            raise MediaError("a JPEG segment longer than the file")
        if marker == 0xFE or 0xE0 <= marker <= 0xEF:
            texts.append(printable_text(seg))
        if marker == 0xDA:  # entropy-coded data follows, to the end marker checked above
            return texts
        pos += 2 + length
    raise MediaError("a JPEG with no end")


def metadata_texts(suffix: str, path: Path) -> list[str]:
    """The texts a media file carries; raises :class:`MediaError` for what cannot be read."""
    if path.stat().st_size > MAX_MEDIA_BYTES:
        raise MediaError("a media file over the size cap")
    return metadata_texts_of(suffix, path.read_bytes())


def metadata_texts_of(suffix: str, data: bytes) -> list[str]:
    """Every text in the file: the structured metadata, and every printable run of the WHOLE file
    (a payload placed anywhere is found).  Data hidden inside compressed sample or pixel data is
    out of scope; so is any format not accepted at all (GIF, WebP, fonts are refused outright)."""
    if not sniff(suffix, data):
        raise MediaError("content that is not the type its suffix says")
    if suffix == ".ico" and PNG_SIG in data:
        raise MediaError("an icon that holds a compressed PNG image")
    try:
        if suffix == ".mp3":
            texts = _mp3(data)
        elif suffix == ".png":
            texts = _png(data)
        elif suffix in (".jpg", ".jpeg"):
            texts = _jpeg(data)
        else:
            texts = []
    except (struct.error, IndexError) as exc:
        raise MediaError("a structure that does not parse") from exc
    texts.append(printable_text(data))
    return texts
