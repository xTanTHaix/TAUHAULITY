"""Pillar 1 - AEGIS-VMI: live memory map, executable page and pointer table integrity.

Why this pillar exists: a compromised interpreter is not detected by reading files
on disk, because the attack already lives in the mapped image. This probe therefore
asks the kernel for the real permission map of the running process and checks the
two cheap, high signal invariants that a hook must break:

1. Writability of the pointer table. On Linux the .got.plt / .plt.got entries come
   from the dynamic section (DT_PLTGOT); on Windows the import address table comes
   from the PE import directory. If the page holding those entries is writable
   after startup, a foreign thread can redirect library calls without touching a
   single byte of code.
2. Write-and-execute mappings. An executable mapping that is also writable is a
   live code injection site. JIT engines legitimately create such mappings, but
   they are rare in a CPython process and the finding stays explicit about the
   count instead of hiding it.

Platform traps that shape the implementation:
* /proc/self/maps is the only portable Linux view. It is cheap (a few KiB) and
  does not need root, which keeps the probe usable in a plain developer shell.
* VirtualQueryEx must be walked in RegionSize steps. Reading memory whose
  PAGE_GUARD bit is set raises a hardware exception, so guarded and PAGE_NOACCESS
  pages are filtered before any read and reported as unreadable.
* Reading our own pages with ctypes.string_at is legal for mapped pages, but the
  probe still caps the byte budget: a full .text hash of every native library
  would cost hundreds of megabytes and blow the three second scan budget.
* The native engine is optional. It is asked for page digests first because it can
  hash without copying, and hashlib is used when the engine is absent so the
  pillar never depends on a sibling module that may not be installed yet.
"""

from __future__ import annotations

import ctypes
import functools
import hashlib
import importlib.machinery
import json
import os
import platform
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Final, Mapping, Sequence

from tauhaulity.core.contracts import Finding, PillarSpec, ScanContext, SPEC_BY_KEY, make_finding
from tauhaulity.core.policy import policy_dir

SPEC: PillarSpec = SPEC_BY_KEY["aegis_vmi"]

PAGE_SIZE: Final[int] = 4096
_MAX_HASH_PAGES: Final[int] = 96
_MAX_HASH_BYTES: Final[int] = 8 * 1024 * 1024

# Windows protection and state constants used by the VirtualQueryEx walk.
_MEM_COMMIT: Final[int] = 0x1000
_MEM_IMAGE: Final[int] = 0x1000000
_PAGE_GUARD: Final[int] = 0x100
_WIN_PROTECT_PERMS: Final[dict[int, str]] = {
    0x00: "---p",
    0x01: "---p",  # PAGE_NOACCESS
    0x02: "r--p",  # PAGE_READONLY
    0x04: "rw-p",  # PAGE_READWRITE
    0x08: "rw-p",  # PAGE_WRITECOPY
    0x10: "--xp",  # PAGE_EXECUTE
    0x20: "r-xp",  # PAGE_EXECUTE_READ
    0x40: "rwxp",  # PAGE_EXECUTE_READWRITE
    0x80: "rwxp",  # PAGE_EXECUTE_WRITECOPY
}


class MemoryInspectionError(RuntimeError):
    """Raised when the process memory map cannot be read on this host."""


@dataclass(frozen=True, slots=True)
class MemoryRegion:
    """One mapped virtual memory range with its effective permissions.

    Attributes:
        start: First address of the mapping, inclusive.
        end: End address of the mapping, exclusive.
        perms: Four character permission string in rwxp / rwxs form.
        offset: File offset of the mapping (zero for anonymous memory).
        path: Backing file path or a bracketed pseudo name.
    """

    start: int
    end: int
    perms: str
    offset: int = 0
    path: str = ""

    @property
    def size(self) -> int:
        """Byte length of the mapping."""

        return max(0, self.end - self.start)

    @property
    def executable(self) -> bool:
        """True when the mapping may execute code."""

        return "x" in self.perms

    @property
    def writable(self) -> bool:
        """True when the mapping may be written."""

        return "w" in self.perms

    @property
    def readable(self) -> bool:
        """True when the mapping may be read."""

        return "r" in self.perms

    @property
    def private(self) -> bool:
        """True for copy-on-write private mappings, False for shared ones."""

        return "s" not in self.perms

    @property
    def anonymous(self) -> bool:
        """True when the mapping has no file backing."""

        return not self.path or self.path.startswith("[")


def parse_proc_maps(text: str) -> list[MemoryRegion]:
    """Parse the textual content of /proc/self/maps into regions.

    Lines that do not match the expected six column layout are skipped instead of
    raising, because the kernel adds columns over time and a diagnostic pillar
    must degrade rather than abort a scan on a newer kernel.
    """

    regions: list[MemoryRegion] = []
    for line in text.splitlines():
        parts = line.split(maxsplit=5)
        if len(parts) < 5:
            continue
        address, perms, offset, _device, _inode = parts[:5]
        path = parts[5].strip() if len(parts) > 5 else ""
        start_text, separator, end_text = address.partition("-")
        if not separator:
            continue
        try:
            start = int(start_text, 16)
            end = int(end_text, 16)
            file_offset = int(offset, 16)
        except ValueError:
            continue
        if end <= start or len(perms) < 4:
            continue
        regions.append(MemoryRegion(start, end, perms[:4], file_offset, path))
    return regions


def _win_protect_to_perms(protect: int) -> str:
    """Translate a Win32 Protect value into the shared permission string.

    PAGE_GUARD is folded into "no access" because touching a guarded page raises
    STATUS_GUARD_PAGE_VIOLATION; treating it as readable would crash a read of our
    own memory map.
    """

    if protect & _PAGE_GUARD:
        return "---p"
    base = protect & 0xFF
    return _WIN_PROTECT_PERMS.get(base, "---p")


def _walk_windows_regions() -> list[MemoryRegion]:
    """Walk the current process address space with VirtualQueryEx.

    The walk advances by RegionSize and stops at the first failed query, which is
    the kernel's way of saying the address space is exhausted.
    """

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _MemoryBasicInformation(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_ulonglong),
            ("AllocationBase", ctypes.c_ulonglong),
            ("AllocationProtect", ctypes.c_uint32),
            ("alignment1", ctypes.c_uint32),
            ("RegionSize", ctypes.c_ulonglong),
            ("State", ctypes.c_uint32),
            ("Protect", ctypes.c_uint32),
            ("Type", ctypes.c_uint32),
            ("alignment2", ctypes.c_uint32),
        ]

    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.VirtualQueryEx.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(_MemoryBasicInformation),
        ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    process = kernel32.GetCurrentProcess()
    info = _MemoryBasicInformation()
    regions: list[MemoryRegion] = []
    address = 0
    # 64-bit user space is at most 2**47 bytes; the cap only guards against a
    # kernel that reports a zero region size and would otherwise spin forever.
    for _ in range(1_000_000):
        written = kernel32.VirtualQueryEx(
            process, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)
        )
        if written == 0:
            break
        size = int(info.RegionSize)
        if size <= 0:
            break
        if int(info.State) == _MEM_COMMIT:
            perms = _win_protect_to_perms(int(info.Protect))
            path = ""
            if int(info.Type) == _MEM_IMAGE:
                path = _windows_module_path(kernel32, int(info.AllocationBase))
            regions.append(
                MemoryRegion(
                    start=int(info.BaseAddress),
                    end=int(info.BaseAddress) + size,
                    perms=perms,
                    offset=0,
                    path=path,
                )
            )
        address += size
        if address <= 0:
            break
    return regions


def _windows_module_path(kernel32, allocation_base: int) -> str:
    """Best effort module path for an image mapping; empty on failure."""

    try:
        buffer = ctypes.create_unicode_buffer(32768)
        kernel32.GetModuleFileNameW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        kernel32.GetModuleFileNameW.restype = ctypes.c_uint32
        length = kernel32.GetModuleFileNameW(
            ctypes.c_void_p(allocation_base),
            buffer,
            ctypes.sizeof(buffer) // ctypes.sizeof(ctypes.c_wchar),
        )
        if length:
            return str(buffer.value)
    except (OSError, AttributeError, ValueError):
        return ""
    return ""


@dataclass(frozen=True, slots=True)
class PointerTableView:
    """Where the interpreter keeps its indirect call table and how it is protected.

    Attributes:
        address: Runtime address of the first pointer entry, or None when unresolved.
        readable: Whether the containing page may be read.
        writable: Whether the containing page may be written.
        source: How the address was obtained (ELF dynamic table, PE import table).
        detail: One line explanation safe to render in the dossier.
    """

    address: int | None
    readable: bool
    writable: bool
    source: str
    detail: str

    @property
    def resolved(self) -> bool:
        """True when a pointer table address was located."""

        return self.address is not None

    @property
    def sealed(self) -> bool:
        """True when the table exists and is mapped read-only."""

        return self.address is not None and self.readable and not self.writable


@dataclass(frozen=True, slots=True)
class PageDigestReport:
    """Digest coverage produced by the executable page hasher.

    Attributes:
        method: "native" when the Rust engine hashed the pages, else "hashlib".
        pages: Number of pages hashed.
        total_bytes: Number of bytes hashed.
        digests: Hex SHA-256 digest per hashed page, in address order.
        failures: Number of regions that could not be read, with no exception raised.
    """

    method: str
    pages: int
    total_bytes: int
    digests: tuple[str, ...]
    failures: int

    @property
    def sample(self) -> str:
        """First digest or an empty string when nothing could be hashed."""

        return self.digests[0] if self.digests else ""


@dataclass(frozen=True, slots=True)
class DirtyExecReport:
    """MMU assisted view of executable pages that were modified after mapping.

    Attributes:
        available: True when the kernel exposed soft-dirty bits to this process.
        method: pagemap-soft-dirty on Linux, getwritewatch on Windows.
        sampled_pages: Number of executable pages whose pagemap entry was read.
        dirty_pages: Sampled pages whose soft-dirty bit (bit 55) is set.
        anonymous_dirty: Dirty pages with no file backing; a writable anonymous
            executable page is the classic injection artefact.
        file_backed_dirty: Dirty pages backed by a file, which a loader may also
            produce through copy-on-write relocation, so it is advisory only.
        detail: One line explanation safe to render in the dossier.
    """

    available: bool
    method: str
    sampled_pages: int
    dirty_pages: int
    anonymous_dirty: int
    file_backed_dirty: int
    detail: str


def _load_engine():
    """Import the shared engine handle; return None when the module is absent.

    The import is deliberately local: the loader belongs to a sibling package that
    may be missing in a partial checkout. The handle is returned even when the
    native tier is unavailable, because the ctypes tier still exposes page
    protection probes; _engine_is_native decides whether digests may be labelled
    native.
    """

    try:
        from tauhaulity.primitives.loader import get_engine
    except (ImportError, OSError, RuntimeError):
        return None
    try:
        engine = get_engine()
    except (ImportError, OSError, RuntimeError, ValueError):
        return None
    return engine


def _engine_is_native(engine: object) -> bool:
    """True when the engine is backed by the verified Rust cdylib."""

    flag = getattr(engine, "available", None)
    if callable(flag):
        try:
            flag = flag()
        except (OSError, RuntimeError, ValueError):
            flag = False
    if flag:
        return True
    return str(getattr(engine, "backend", "")).lower() == "rust"


class MemoryInspector:
    """Read the live process memory map and audit pointer-table protection.

    The region list is cached after the first read because every helper would
    otherwise re-read /proc/self/maps; call refresh() to force a new snapshot when
    the caller expects mappings to have changed.
    """

    def __init__(self, page_size: int = PAGE_SIZE) -> None:
        if page_size <= 0:
            raise ValueError("page_size must be positive")
        self.page_size = int(page_size)
        self._regions: list[MemoryRegion] | None = None
        self._error: str | None = None

    def refresh(self) -> None:
        """Re-read the region map, recording a degraded state instead of raising."""

        self._regions = None
        self._error = None
        try:
            self._regions = self._read_regions()
        except (OSError, MemoryInspectionError, ValueError) as exc:
            self._error = f"{type(exc).__name__}: {exc}"
            self._regions = []

    @property
    def error(self) -> str | None:
        """Reason the region map is unavailable, or None when it was read."""

        return self._error

    def _read_regions(self) -> list[MemoryRegion]:
        if os.name == "nt":
            try:
                return _walk_windows_regions()
            except (OSError, AttributeError, ValueError) as exc:
                raise MemoryInspectionError(f"VirtualQueryEx walk failed: {exc}") from exc
        maps_path = Path("/proc/self/maps")
        try:
            text = maps_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise MemoryInspectionError(f"cannot read /proc/self/maps: {exc}") from exc
        regions = parse_proc_maps(text)
        if not regions:
            raise MemoryInspectionError("/proc/self/maps parsed to zero regions")
        return regions

    def regions(self) -> list[MemoryRegion]:
        """Return the cached memory map, reading it on first use."""

        if self._regions is None:
            self.refresh()
        return list(self._regions or [])

    def executable_regions(self) -> list[MemoryRegion]:
        """Return every executable mapping, shared and private."""

        return [region for region in self.regions() if region.executable]

    def executable_private_regions(self) -> list[MemoryRegion]:
        """Return executable mappings that are private (copy-on-write) pages."""

        return [region for region in self.regions() if region.executable and region.private]

    def writable_executable_regions(self) -> list[MemoryRegion]:
        """Return live write-and-execute mappings; these are injection sites."""

        return [region for region in self.regions() if region.executable and region.writable]

    def find_region(self, address: int) -> MemoryRegion | None:
        """Return the mapping containing address, or None when unmapped."""

        for region in self.regions():
            if region.start <= address < region.end:
                return region
        return None

    def permissions_at(self, address: int) -> str | None:
        """Return the permission string of the page containing address."""

        region = self.find_region(address)
        return region.perms if region is not None else None

    def pointer_table(self) -> PointerTableView:
        """Locate the interpreter GOT/IAT and report its effective protection."""

        try:
            resolved = self._resolve_pointer_table()
        except (OSError, ValueError, struct.error) as exc:
            return PointerTableView(
                None, False, False, "unresolved", f"pointer table resolution failed: {exc}"
            )
        return resolved

    def _resolve_pointer_table(self) -> PointerTableView:
        if os.name == "nt":
            return self._resolve_windows_iat()
        return self._resolve_linux_got()

    def _resolve_windows_iat(self) -> PointerTableView:
        """Resolve the IAT of the main module through the PE import directory.

        GetModuleHandleW(None) returns the executable image base, which is the only
        module guaranteed to exist in every Python process. The IAT lives in the
        .idata section; the first import descriptor FirstThunk is a valid
        representative address for the writable/read-only question.
        """

        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GetModuleHandleW.restype = ctypes.c_void_p
            kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
            base = int(kernel32.GetModuleHandleW(None) or 0)
        except (OSError, AttributeError, ValueError) as exc:
            return PointerTableView(None, False, False, "pe", f"GetModuleHandleW failed: {exc}")
        if base <= 0:
            return PointerTableView(None, False, False, "pe", "main module base unavailable")
        try:
            dos = ctypes.string_at(base, 64)
            if dos[:2] != b"MZ":
                return PointerTableView(None, False, False, "pe", "main image has no MZ signature")
            pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
            nt = ctypes.string_at(base + pe_offset, 264)
            if nt[:4] != b"PE\x00\x00":
                return PointerTableView(None, False, False, "pe", "main image has no PE signature")
            magic = struct.unpack_from("<H", nt, 24)[0]
            # The data directory lives inside the optional header, which itself
            # starts 24 bytes into the NT headers (4 byte signature + 20 byte file
            # header). Forgetting that 24 byte shift yields a plausible looking but
            # unrelated RVA, so the offset is written out explicitly here.
            if magic == 0x20B:  # PE32+
                directory_base = 24 + 112
            elif magic == 0x10B:  # PE32
                directory_base = 24 + 96
            else:
                return PointerTableView(
                    None, False, False, "pe", f"unknown PE optional header {magic:#x}"
                )
            import_rva, import_size = struct.unpack_from("<II", nt, directory_base + 8)
            if import_rva == 0:
                return PointerTableView(None, False, False, "pe", "main image imports no DLLs")
            address = base + import_rva
            first_thunk = struct.unpack_from("<I", ctypes.string_at(address + 16, 4))[0]
            table_address = base + (first_thunk or import_rva)
            perms = self.permissions_at(table_address) or ""
            return PointerTableView(
                address=table_address,
                readable="r" in perms,
                writable="w" in perms,
                source="pe-import-directory",
                detail=(
                    f"IAT at {table_address:#x} ({perms or 'unmapped'}), "
                    f"{import_size} bytes of import descriptors"
                ),
            )
        except (OSError, ValueError, struct.error) as exc:
            return PointerTableView(None, False, False, "pe", f"PE import directory parse failed: {exc}")

    def _resolve_linux_got(self) -> PointerTableView:
        """Resolve DT_PLTGOT from the dynamic section of the main ELF image.

        The main executable of a Python process is often /usr/bin/python3 (or the
        interpreter itself), which is a normal PIE ELF. The dynamic segment yields
        the GOT virtual address; the load bias is recovered by matching the first
        file mapping of the same inode, and the final runtime address is checked
        against the kernel permission map.
        """

        candidates = self._elf_image_candidates()
        if not candidates:
            return PointerTableView(
                None, False, False, "elf", "no ELF image mapping found for the interpreter"
            )
        errors: list[str] = []
        for path, bias in candidates:
            try:
                file_bytes = Path(path).read_bytes()
            except OSError as exc:
                errors.append(f"{path}: {exc}")
                continue
            try:
                offset = _elf_got_offset(file_bytes)
            except (ValueError, struct.error) as exc:
                errors.append(f"{path}: {exc}")
                continue
            if offset is None:
                errors.append(f"{path}: no DT_PLTGOT")
                continue
            address = bias + offset
            perms = self.permissions_at(address) or ""
            return PointerTableView(
                address=address,
                readable="r" in perms,
                writable="w" in perms,
                source="elf-dynamic-dt_pltgot",
                detail=f"GOT at {address:#x} ({perms or 'unmapped'}) in {os.path.basename(path)}",
            )
        return PointerTableView(None, False, False, "elf", "cannot resolve GOT: " + "; ".join(errors[:2]))

    def _elf_image_candidates(self) -> list[tuple[str, int]]:
        """Return (path, load_bias) for file-backed mappings.

        The load bias depends on the ELF type, which is why the header is read
        before the mapping arithmetic is trusted: for a PIE image (ET_DYN) the
        first mapping starts at the bias and the file offset must be subtracted,
        while a non-PIE ET_EXEC image is mapped at its link-time addresses and the
        bias is zero. Getting this wrong produces an address that looks plausible
        but lands outside the mapping, which is exactly what a "sealed GOT" report
        must never do.
        """

        seen: dict[str, int] = {}
        for region in self.regions():
            if region.anonymous or not region.readable:
                continue
            if "/" not in region.path and os.sep not in region.path:
                continue
            try:
                resolved = os.path.realpath(region.path)
            except (OSError, ValueError):
                continue
            if not os.path.isfile(resolved):
                continue
            bias = _elf_load_bias(_read_elf_type(resolved), region.start, region.offset)
            if bias is None or bias < 0:
                continue
            seen.setdefault(resolved, bias)
        ordered = sorted(
            seen.items(),
            key=lambda item: (
                0 if "libpython" in os.path.basename(item[0]) else 1,
                0 if os.access(item[0], os.X_OK) else 1,
            ),
        )
        return ordered

    def dirty_executable_pages(self, max_pages: int = 256) -> DirtyExecReport:
        """Count executable pages the MMU marked as written since process start.

        This is the cheap hardware assisted alternative to hashing every page: on
        Linux the soft-dirty bit in /proc/self/pagemap is set by the CPU on the
        first write to a page. The bit is only cleared by writing to clear_refs,
        so the count is a since-start snapshot, not a per-second delta. Anonymous
        dirty executable pages are treated as an injection artefact by the probe;
        file backed ones are advisory because a loader can legitimately dirty a
        relocated page.
        """

        if os.name == "nt":
            return DirtyExecReport(
                False,
                "getwritewatch",
                0,
                0,
                0,
                0,
                "GetWriteWatch only reports regions registered with MEM_WRITE_WATCH at allocation time",
            )
        return self._linux_dirty_exec_pages(max_pages)

    def _linux_dirty_exec_pages(self, max_pages: int) -> DirtyExecReport:
        """Read soft-dirty bits for a bounded sample of executable pages."""

        try:
            fd = os.open("/proc/self/pagemap", os.O_RDONLY)
        except OSError as exc:
            return DirtyExecReport(
                False, "pagemap", 0, 0, 0, 0, f"pagemap unavailable: {type(exc).__name__}"
            )
        sampled = dirty = anonymous_dirty = file_backed_dirty = 0
        budget = max(0, int(max_pages))
        try:
            for region in self.executable_regions():
                if budget <= 0:
                    break
                if not region.readable:
                    continue
                address = region.start
                while address < region.end and budget > 0:
                    entry = _read_pagemap_entry(fd, address, self.page_size)
                    budget -= 1
                    if entry is not None and entry & (1 << 63):
                        sampled += 1
                        if entry & (1 << 55):
                            dirty += 1
                            if region.anonymous:
                                anonymous_dirty += 1
                            else:
                                file_backed_dirty += 1
                    address += self.page_size
        except OSError as exc:
            return DirtyExecReport(
                False,
                "pagemap",
                sampled,
                dirty,
                anonymous_dirty,
                file_backed_dirty,
                f"pagemap read failed: {type(exc).__name__}",
            )
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        if sampled == 0:
            return DirtyExecReport(
                False,
                "pagemap",
                0,
                0,
                0,
                0,
                "pagemap entries are masked for this process: no present executable page was visible",
            )
        if dirty == sampled:
            # WSL2 kernels have been observed to leave the soft-dirty bit set on
            # every sampled file mapping, which makes the bit useless as a "fresh
            # write" signal. Saying so keeps the dossier honest instead of
            # implying that every executable page was recently modified.
            detail = (
                f"soft-dirty bit is set on all {sampled} sampled executable pages, so the bit "
                "does not identify a fresh write on this kernel; anonymous pages stay the only signal"
            )
        else:
            detail = (
                f"{dirty} of {sampled} sampled executable pages are soft-dirty "
                f"({anonymous_dirty} anonymous, {file_backed_dirty} file-backed)"
            )
        return DirtyExecReport(
            True,
            "pagemap-soft-dirty",
            sampled,
            dirty,
            anonymous_dirty,
            file_backed_dirty,
            detail,
        )

    def page_digests(
        self,
        max_pages: int = _MAX_HASH_PAGES,
        max_bytes: int = _MAX_HASH_BYTES,
    ) -> PageDigestReport:
        """Hash executable pages and return per-page SHA-256 digests.

        The native engine is used when it exposes a page hashing primitive so the
        bytes never cross the ctypes boundary. Every other case falls back to
        hashlib over ctypes.string_at copies, which is slower but always available
        and needs no shared library.
        """

        targets = self._hash_targets(max_pages, max_bytes)
        engine = _load_engine()
        if engine is not None and _engine_is_native(engine):
            native = _native_page_digests(engine, targets, self.page_size)
            if native is not None:
                return native
        return _hashlib_page_digests(targets, self.page_size)

    def _hash_targets(self, max_pages: int, max_bytes: int) -> list[tuple[int, int]]:
        """Select (address, length) chunks from readable executable mappings."""

        targets: list[tuple[int, int]] = []
        pages_left = max(0, int(max_pages))
        bytes_left = max(0, int(max_bytes))
        for region in self.executable_regions():
            if pages_left <= 0 or bytes_left <= 0:
                break
            if not region.readable:
                continue
            page_count = min(pages_left, max(1, region.size // self.page_size))
            length = min(page_count * self.page_size, region.size, bytes_left)
            if length <= 0:
                continue
            targets.append((region.start, length))
            pages_left -= max(1, length // self.page_size)
            bytes_left -= length
        return targets


def _read_elf_type(path: str) -> int | None:
    """Return the ELF e_type field (2 = ET_EXEC, 3 = ET_DYN) or None.

    Only the first eighteen bytes are read: the pillar needs the header type, not
    the image, and a 15 MiB interpreter binary must not be loaded just to compute
    a load bias.
    """

    try:
        with open(path, "rb") as handle:
            header = handle.read(18)
    except OSError:
        return None
    if len(header) < 18 or header[:4] != b"ELF":
        return None
    endian = "<" if header[5] == 1 else ">"
    try:
        return int(struct.unpack_from(endian + "H", header, 16)[0])
    except struct.error:
        return None


def _elf_load_bias(elf_type: int | None, mapping_start: int, mapping_offset: int) -> int | None:
    """Return the runtime load bias for one file mapping.

    ET_EXEC images are linked at their final virtual addresses, so their bias is
    zero. ET_DYN images (PIE executables and every shared object) are placed by
    the loader, so the bias is start - file offset. An unknown type returns None
    because guessing would silently mis-resolve the pointer table.
    """

    if elf_type == 2:  # ET_EXEC
        return 0
    if elf_type == 3:  # ET_DYN
        return mapping_start - mapping_offset
    return None


def _read_pagemap_entry(fd: int, address: int, page_size: int) -> int | None:
    """Read one 64-bit pagemap entry for address, or None when unreadable.

    os.pread is used when available because it leaves the shared file offset
    untouched; the lseek fallback keeps the code path valid on a platform whose
    os module omits pread.
    """

    offset = (address // page_size) * 8
    try:
        pread = getattr(os, "pread", None)
        if pread is not None:
            raw = pread(fd, 8, offset)
        else:
            os.lseek(fd, offset, os.SEEK_SET)
            raw = os.read(fd, 8)
    except OSError:
        return None
    if len(raw) != 8:
        return None
    return int(struct.unpack("<Q", raw)[0])


def _hashlib_page_digests(targets: Sequence[tuple[int, int]], page_size: int) -> PageDigestReport:
    """Hash process pages with the standard library."""

    digests: list[str] = []
    total = 0
    failures = 0
    for address, length in targets:
        try:
            data = ctypes.string_at(address, length)
        except (OSError, ValueError, ctypes.ArgumentError):
            failures += 1
            continue
        for offset in range(0, len(data), page_size):
            page = data[offset : offset + page_size]
            if not page:
                continue
            digests.append(hashlib.sha256(page).hexdigest())
            total += len(page)
    return PageDigestReport("hashlib", len(digests), total, tuple(digests), failures)


def _native_page_digests(
    engine: object,
    targets: Sequence[tuple[int, int]],
    page_size: int,
) -> PageDigestReport | None:
    """Ask the native engine for page digests; None when its API does not match.

    The engine is an optional sibling component, so several plausible call shapes
    are attempted. A TypeError means the shape is wrong, not that hashing is
    impossible, and the caller then falls back to hashlib.
    """

    if not targets:
        return PageDigestReport("native", 0, 0, (), 0)
    for name in ("sha256_pages", "page_digests", "hash_pages", "digest_pages"):
        method = getattr(engine, name, None)
        if not callable(method):
            continue
        attempts = (
            (list(targets), page_size),
            ([address for address, _ in targets], [length for _, length in targets], page_size),
            ([address for address, _ in targets], page_size),
        )
        for call_args in attempts:
            try:
                raw = method(*call_args)
            except TypeError:
                continue
            except (OSError, RuntimeError, ValueError):
                return None
            parsed = _coerce_native_digests(raw)
            if parsed is not None:
                total = sum(length for _, length in targets)
                return PageDigestReport("native", len(parsed), total, parsed, 0)
    # The shipped engine exposes a single buffer sha256 rather than a page batch
    # helper, so the pages are read once and hashed through the native code. If
    # the digest shape is wrong the caller falls back to hashlib instead of
    # putting unverified bytes into the dossier.
    sha256 = getattr(engine, "sha256", None)
    if callable(sha256):
        digests: list[str] = []
        total = 0
        failures = 0
        for address, length in targets:
            try:
                data = ctypes.string_at(address, length)
            except (OSError, ValueError, ctypes.ArgumentError):
                failures += 1
                continue
            for offset in range(0, len(data), page_size):
                page = data[offset : offset + page_size]
                if not page:
                    continue
                try:
                    digest = sha256(page)
                except (TypeError, ValueError, OSError, RuntimeError):
                    return None
                if not isinstance(digest, (bytes, bytearray)) or len(digest) != 32:
                    return None
                digests.append(bytes(digest).hex())
                total += len(page)
        return PageDigestReport("native", len(digests), total, tuple(digests), failures)
    return None


def _coerce_native_digests(raw: object) -> tuple[str, ...] | None:
    """Normalize an engine digest result into lowercase hex strings."""

    if raw is None:
        return None
    items: list[object]
    if isinstance(raw, (bytes, bytearray, memoryview)):
        material = bytes(raw)
        if len(material) % 32 != 0 or not material:
            return None
        items = [material[index : index + 32] for index in range(0, len(material), 32)]
    elif isinstance(raw, (list, tuple)):
        items = list(raw)
    else:
        return None
    digests: list[str] = []
    for item in items:
        if isinstance(item, (bytes, bytearray, memoryview)):
            material = bytes(item)
            if len(material) != 32:
                return None
            digests.append(material.hex())
        elif isinstance(item, str) and len(item) == 64:
            digests.append(item.lower())
        else:
            return None
    return tuple(digests)


def _elf_got_offset(data: bytes) -> int | None:
    """Return the DT_PLTGOT virtual address from a 32/64-bit ELF image.

    Only the program header and the dynamic table are parsed: the pillar needs one
    address, not a full ELF reader, and skipping section parsing keeps this usable
    on stripped binaries that still carry a dynamic segment.
    """

    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF image")
    elf_class = data[4]
    endian = "<" if data[5] == 1 else ">"
    if elf_class == 2:  # 64-bit
        header = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
    elif elf_class == 1:  # 32-bit
        header = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
    else:
        raise ValueError(f"unknown ELF class {elf_class}")
    _etype, _machine, _version, _entry, phoff, _shoff, _flags, _ehsize, phentsize, phnum = header[:10]
    if phentsize <= 0 or phnum <= 0 or phoff <= 0:
        raise ValueError("ELF has no program headers")
    dynamic_vaddr: int | None = None
    dynamic_size = 0
    for index in range(min(phnum, 512)):
        offset = phoff + index * phentsize
        if offset + phentsize > len(data):
            break
        if elf_class == 2:
            p_type, _flags, _p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = struct.unpack_from(
                endian + "IIQQQQQQ", data, offset
            )
        else:
            p_type, _p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _flags, _p_align = struct.unpack_from(
                endian + "IIIIIIII", data, offset
            )
        if p_type == 2:  # PT_DYNAMIC
            dynamic_vaddr = p_vaddr
            dynamic_size = p_filesz
            break
    if dynamic_vaddr is None or dynamic_size <= 0:
        return None
    dynamic_offset = _vaddr_to_offset(data, endian, elf_class, dynamic_vaddr)
    if dynamic_offset is None:
        return None
    entry_size = 16 if elf_class == 2 else 8
    tag_format = endian + ("qQ" if elf_class == 2 else "iI")
    for offset in range(
        dynamic_offset, min(dynamic_offset + dynamic_size, len(data)) - entry_size + 1, entry_size
    ):
        tag, value = struct.unpack_from(tag_format, data, offset)
        if tag == 0:  # DT_NULL terminates the table
            break
        if tag == 3:  # DT_PLTGOT
            return int(value)
    return None


def _vaddr_to_offset(data: bytes, endian: str, elf_class: int, vaddr: int) -> int | None:
    """Translate a virtual address to a file offset through PT_LOAD segments."""

    if len(data) < 64:
        return None
    if elf_class == 2:
        header = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
        phoff, phentsize, phnum = header[4], header[8], header[9]
    else:
        header = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
        phoff, phentsize, phnum = header[4], header[8], header[9]
    for index in range(min(phnum, 512)):
        offset = phoff + index * phentsize
        if offset + phentsize > len(data):
            return None
        if elf_class == 2:
            p_type, _flags, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = struct.unpack_from(
                endian + "IIQQQQQQ", data, offset
            )
        else:
            p_type, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _flags, _p_align = struct.unpack_from(
                endian + "IIIIIIII", data, offset
            )
        if p_type != 1:  # PT_LOAD
            continue
        if p_vaddr <= vaddr < p_vaddr + max(p_filesz, 1):
            return int(p_offset + (vaddr - p_vaddr))
    return None


# ---------------------------------------------------------------------------
# Memory tamper baseline
#
# The live map and page digests above answer "what is protected right now". They
# cannot answer "did this module change since the process started", because a
# hook inside a read-only .text page leaves the permission map untouched. The
# baseline below closes that gap: it records page digests of every executable
# file-backed module image while the process is known clean, and a later probe
# re-reads the same mapped pages and compares them.
#
# Reading the mapped pages instead of the file on disk is the whole point. A
# modified file on disk is a supply-chain concern for other pillars; a modified
# page in memory is an inline hook, and only the in-memory read can see it
# because file mappings are copy-on-write after the loader has mapped them.
# ---------------------------------------------------------------------------

BASELINE_SCHEMA: Final[int] = 1
BASELINE_FILENAME: Final[str] = "memory_baseline.json"
DEFAULT_BASELINE_TOTAL_BYTES: Final[int] = 32 * 1024 * 1024
DEFAULT_BASELINE_PER_MODULE_BYTES: Final[int] = 4 * 1024 * 1024
DEFAULT_BASELINE_MAX_MODULES: Final[int] = 512
_MAX_REFUSED_REMEMBERED: Final[int] = 32
_DELTA_ORDER: Final[tuple[str, ...]] = ("changed", "missing", "new")
_HEX_DIGEST_LENGTH: Final[int] = 64
_EXTENSION_SUFFIXES: Final[tuple[str, ...]] = tuple(
    sorted({*importlib.machinery.EXTENSION_SUFFIXES, ".pyd", ".so", ".dll", ".dylib"})
)


class BaselineStoreError(RuntimeError):
    """Raised when a memory baseline record cannot be persisted."""


@dataclass(frozen=True, slots=True)
class BaselineBudget:
    """Byte and module limits applied while hashing module images.

    The budget exists so a baseline can never turn into a multi-hundred-megabyte
    scan. A module larger than the per-module allowance is hashed up to the
    allowance and marked truncated; the truncation is recorded so a later run
    with the same budget produces the same page list instead of a false change.

    Attributes:
        total_bytes: Maximum bytes hashed across every module of one capture.
        per_module_bytes: Maximum bytes hashed for any single module.
        page_size: Page granularity used for the per-page digests.
        max_modules: Maximum number of module images recorded by one capture.
    """

    total_bytes: int = DEFAULT_BASELINE_TOTAL_BYTES
    per_module_bytes: int = DEFAULT_BASELINE_PER_MODULE_BYTES
    page_size: int = PAGE_SIZE
    max_modules: int = DEFAULT_BASELINE_MAX_MODULES

    def __post_init__(self) -> None:
        for field_name in ("total_bytes", "per_module_bytes", "page_size", "max_modules"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{field_name} must be an integer")
            if value <= 0:
                raise ValueError(f"{field_name} must be positive")


@dataclass(frozen=True, slots=True)
class ModuleBaseline:
    """Page digests of one executable module image captured while it was clean.

    Attributes:
        module: Stable module identifier, normally the dotted module name.
        path: Resolved path of the backing image.
        size: Number of bytes actually hashed (not the file size).
        digest: SHA-256 hex digest over the hashed image bytes.
        pages: SHA-256 hex digest for every page of the hashed image.
        captured_at: UTC timestamp of the capture.
        truncated: True when the byte budget stopped the hash early.
    """

    module: str
    path: str
    size: int
    digest: str
    pages: tuple[str, ...]
    captured_at: str
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class BaselineRecord:
    """A persisted set of module baselines plus its integrity digest.

    Attributes:
        schema: Store schema version; a mismatch is reported, never guessed.
        captured_at: UTC timestamp of the capture that produced the record.
        target: Project directory the record belongs to (informational).
        page_size: Page granularity shared by every module in the record.
        total_bytes: Total byte budget used by the capture.
        per_module_bytes: Per module byte budget used by the capture.
        max_modules: Module cap used by the capture.
        modules: Module baselines in deterministic order.
        digest: SHA-256 over the canonical record payload, so a partial write is
            detectable without trusting the file length.
        refused: Human readable reasons for candidate paths that were not
            baselined because they are outside the interpreter and its modules.
    """

    schema: int
    captured_at: str
    target: str
    page_size: int
    total_bytes: int
    per_module_bytes: int
    max_modules: int
    modules: tuple[ModuleBaseline, ...]
    digest: str
    refused: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MemoryDelta:
    """One difference between a current capture and a stored baseline.

    Attributes:
        kind: changed, missing or new.
        module: Module identifier the delta refers to.
        path: Path recorded for the module, useful for the operator.
        page_offset: Byte offset of the first differing page inside the hashed
            module image, or None when the delta is not a page change.
        digest_changed: True when the whole module digest differs; always False
            for a module that is only missing or newly appeared.
        detail: One line explanation that never contains page bytes.
    """

    kind: str
    module: str
    path: str
    page_offset: int | None = None
    digest_changed: bool = False
    detail: str = ""


@dataclass(frozen=True, slots=True)
class BaselineLoadResult:
    """Outcome of reading the baseline store, including why it was rejected.

    Attributes:
        record: Parsed record, or None when the store is absent or unusable.
        reason: Human readable reason; "ok" only when a record was returned.
        present: True when a store file existed (even if it was corrupt).
        path: Store path that was inspected.
    """

    record: BaselineRecord | None
    reason: str
    present: bool
    path: Path

    @property
    def ok(self) -> bool:
        """True when a usable record was loaded."""

        return self.record is not None


@dataclass(frozen=True, slots=True)
class BaselineOutcome:
    """Probe facing summary of the baseline comparison.

    Attributes:
        state: absent, corrupt, clean, changed, missing, new or error.
        risk: Risk contribution the probe should use for that state.
        detail: One line explanation safe to render in the dossier.
    """

    state: str
    risk: float
    detail: str


def baseline_path(target: Path) -> Path:
    """Return the baseline store path for a project directory.

    The path intentionally mirrors the shared policy directory so a project has a
    single hidden state folder instead of one location per subsystem.
    """

    return policy_dir(target) / BASELINE_FILENAME


def _utc_now() -> str:
    """Return the current UTC time in a stable, sortable ISO-8601 form."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@functools.lru_cache(maxsize=1)
def _baseline_roots() -> tuple[str, ...]:
    """Return the directories whose images may be baselined.

    sys.prefix and base_prefix cover the interpreter and its standard library;
    sys.path entries cover virtual environment site-packages. The result is cached
    because a capture inspects many paths and resolving the roots per path would
    dominate the cost.
    """

    roots: set[str] = set()
    candidates = (
        sys.prefix,
        sys.base_prefix,
        sys.exec_prefix,
        getattr(sys, "base_exec_prefix", ""),
        os.path.dirname(sys.executable),
    )
    for candidate in candidates:
        if not candidate:
            continue
        try:
            roots.add(os.path.realpath(candidate))
        except (OSError, ValueError):
            continue
    for entry in sys.path:
        if not entry:
            continue
        try:
            resolved = os.path.realpath(entry)
        except (OSError, ValueError):
            continue
        if os.path.isdir(resolved):
            roots.add(resolved)
    return tuple(sorted(roots))


def _is_under(path: str, root: str) -> bool:
    """Return True when path is root or lies below it."""

    try:
        return os.path.commonpath([path, root]) == root
    except (OSError, ValueError):
        return False


def _baseline_candidate(path: str | os.PathLike[str]) -> tuple[bool, str]:
    """Decide whether a mapped image belongs to the interpreter or its modules.

    Only images inside the interpreter prefixes, inside a sys.path entry or
    carrying a native extension suffix are eligible. Anything else (a random
    library mapped by a host application, for example) is refused so the baseline
    never turns into a hash of unrelated address space.

    Returns:
        (eligible, reason) where reason explains the decision.
    """

    try:
        resolved = os.path.realpath(os.fspath(path))
    except (OSError, ValueError, TypeError):
        return False, "path cannot be resolved"
    for root in _baseline_roots():
        if _is_under(resolved, root):
            return True, f"inside {root}"
    lowered = resolved.replace("\\", "/").lower()
    if lowered.endswith(_EXTENSION_SUFFIXES):
        return True, "native extension suffix"
    return False, "outside sys.prefix/sys.path and no native extension suffix"


def _hashlib_hex(data: bytes) -> str:
    """SHA-256 hex digest through the standard library."""

    return hashlib.sha256(data).hexdigest()


def _resolve_hasher() -> tuple[Callable[[bytes], str], str]:
    """Return the fastest trusted SHA-256 implementation plus its label.

    The native engine is used only when it is the verified Rust tier and it
    reproduces hashlib on a known vector. A stale library must degrade the
    baseline, never poison it with a wrong digest.
    """

    engine = _load_engine()
    if engine is not None and _engine_is_native(engine):
        native = getattr(engine, "sha256", None)
        if callable(native):

            def native_hex(data: bytes) -> str:
                digest = native(data)
                if not isinstance(digest, (bytes, bytearray)) or len(digest) != 32:
                    raise ValueError("native sha256 returned an unexpected digest length")
                return bytes(digest).hex()

            try:
                if native_hex(b"abc") == hashlib.sha256(b"abc").hexdigest():
                    return native_hex, "native"
            except (OSError, RuntimeError, ValueError, TypeError):
                pass
    return _hashlib_hex, "hashlib"


def _page_digests(data: bytes, page_size: int, hasher: Callable[[bytes], str]) -> tuple[str, ...]:
    """Split a byte image into pages and hash every page."""

    return tuple(
        hasher(data[offset : offset + page_size])
        for offset in range(0, len(data), page_size)
        if data[offset : offset + page_size]
    )


def hash_module_files(
    entries: Sequence[tuple[str, str | os.PathLike[str]]],
    *,
    budget: BaselineBudget | None = None,
) -> tuple[tuple[ModuleBaseline, ...], tuple[str, ...]]:
    """Hash module files on disk, applying both budgets and eligibility rules.

    This helper exists for tests and for tooling that has to baseline a set of
    files rather than live mappings. The live capture does not use it, because
    re-reading a file from disk would hide an in-memory inline hook.

    Parameters:
        entries: (module name, file path) pairs.
        budget: Byte and module limits; the default budget is used when omitted.

    Returns:
        (module baselines, refused reasons) with refusals bounded to 32 entries.
    """

    active = budget if budget is not None else BaselineBudget()
    hasher, _backend = _resolve_hasher()
    captured_at = _utc_now()
    modules: list[ModuleBaseline] = []
    refused: list[str] = []
    remaining_total = active.total_bytes
    for module, raw_path in sorted(entries, key=lambda item: (item[0], str(item[1]))):
        path_text = str(raw_path)
        if len(modules) >= active.max_modules:
            refused.append(f"{path_text} (module limit {active.max_modules} reached)")
            continue
        allowed, reason = _baseline_candidate(path_text)
        if not allowed:
            refused.append(f"{path_text} ({reason})")
            continue
        try:
            file_size = os.path.getsize(path_text)
        except OSError as exc:
            refused.append(f"{path_text} (unreadable: {type(exc).__name__})")
            continue
        allowance = min(active.per_module_bytes, max(0, remaining_total))
        data = b""
        if allowance > 0:
            try:
                with open(path_text, "rb") as handle:
                    data = handle.read(allowance)
            except OSError as exc:
                refused.append(f"{path_text} (unreadable: {type(exc).__name__})")
                continue
        remaining_total -= len(data)
        modules.append(
            ModuleBaseline(
                module=module,
                path=os.path.realpath(path_text),
                size=len(data),
                digest=hasher(data),
                pages=_page_digests(data, active.page_size, hasher),
                captured_at=captured_at,
                truncated=len(data) < file_size,
            )
        )
    return tuple(modules), tuple(refused[:_MAX_REFUSED_REMEMBERED])


def hash_module_file(
    module: str,
    path: str | os.PathLike[str],
    *,
    budget: BaselineBudget | None = None,
) -> ModuleBaseline:
    """Hash one module file and return its baseline.

    Raises:
        ValueError: When the path is refused by the eligibility rules.
    """

    modules, refused = hash_module_files([(module, path)], budget=budget)
    if not modules:
        raise ValueError(f"refused to baseline {path}: {refused[0] if refused else 'unknown reason'}")
    return modules[0]


def _build_payload(
    target: str,
    captured_at: str,
    page_size: int,
    total_bytes: int,
    per_module_bytes: int,
    max_modules: int,
    modules: Sequence[ModuleBaseline],
    refused: Sequence[str],
) -> dict[str, object]:
    """Build the canonical payload hashed for record integrity.

    The payload deliberately excludes the digest itself so the digest can be
    recomputed from the parsed document and compared.
    """

    return {
        "target": target,
        "captured_at": captured_at,
        "page_size": page_size,
        "total_bytes": total_bytes,
        "per_module_bytes": per_module_bytes,
        "max_modules": max_modules,
        "refused": list(refused),
        "modules": [
            {
                "module": item.module,
                "path": item.path,
                "size": item.size,
                "digest": item.digest,
                "pages": list(item.pages),
                "captured_at": item.captured_at,
                "truncated": item.truncated,
            }
            for item in modules
        ],
    }


def _canonical_json(payload: object) -> bytes:
    """Serialize a payload deterministically for digesting."""

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _record_digest(payload: Mapping[str, object]) -> str:
    """Digest the canonical form of a record payload."""

    return hashlib.sha256(_canonical_json(dict(payload))).hexdigest()


def _record_payload(record: BaselineRecord) -> dict[str, object]:
    """Rebuild the canonical payload of an existing record."""

    return _build_payload(
        record.target,
        record.captured_at,
        record.page_size,
        record.total_bytes,
        record.per_module_bytes,
        record.max_modules,
        record.modules,
        record.refused,
    )


def _is_hex_digest(value: object) -> bool:
    """True when value is a 256-bit hex digest string."""

    if not isinstance(value, str) or len(value) != _HEX_DIGEST_LENGTH:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _validate_module(module: ModuleBaseline) -> None:
    """Validate one module baseline before it enters a record.

    Raises:
        ValueError: When a field is malformed; a corrupt record must never be
            silently accepted.
    """

    if not isinstance(module.module, str) or not module.module:
        raise ValueError("module name must be a non-empty string")
    if not isinstance(module.path, str) or not module.path:
        raise ValueError(f"module {module.module!r} path must be a non-empty string")
    if isinstance(module.size, bool) or not isinstance(module.size, int) or module.size < 0:
        raise ValueError(f"module {module.module!r} size must be a non-negative integer")
    if not _is_hex_digest(module.digest):
        raise ValueError(f"module {module.module!r} digest must be a 256-bit hex string")
    if not isinstance(module.pages, tuple) or not all(_is_hex_digest(page) for page in module.pages):
        raise ValueError(f"module {module.module!r} pages must be 256-bit hex strings")
    if not isinstance(module.captured_at, str) or not module.captured_at:
        raise ValueError(f"module {module.module!r} captured_at must be a non-empty string")
    if not isinstance(module.truncated, bool):
        raise ValueError(f"module {module.module!r} truncated must be a boolean")


def _normalize_modules(
    modules: Sequence[ModuleBaseline],
    max_modules: int,
) -> tuple[ModuleBaseline, ...]:
    """Validate, de-duplicate and order module baselines.

    Raises:
        ValueError: On a malformed entry or when the module cap is exceeded.
    """

    unique: dict[str, ModuleBaseline] = {}
    for module in modules:
        if not isinstance(module, ModuleBaseline):
            raise ValueError("modules must be ModuleBaseline instances")
        _validate_module(module)
        unique.setdefault(module.module, module)
    ordered = tuple(sorted(unique.values(), key=lambda item: (item.module, item.path)))
    if len(ordered) > max_modules:
        raise ValueError(f"record holds {len(ordered)} modules but the budget allows {max_modules}")
    return ordered


def make_record(
    target: Path,
    modules: Sequence[ModuleBaseline],
    *,
    budget: BaselineBudget | None = None,
    refused: Sequence[str] = (),
    captured_at: str | None = None,
) -> BaselineRecord:
    """Assemble a validated record with its integrity digest.

    Raises:
        ValueError: When a module entry or a budget value is malformed.
    """

    active = budget if budget is not None else BaselineBudget()
    normalized = _normalize_modules(modules, active.max_modules)
    stamp = captured_at if captured_at is not None else _utc_now()
    refused_list = tuple(str(reason) for reason in refused)[:_MAX_REFUSED_REMEMBERED]
    payload = _build_payload(
        str(Path(target)),
        stamp,
        active.page_size,
        active.total_bytes,
        active.per_module_bytes,
        active.max_modules,
        normalized,
        refused_list,
    )
    return BaselineRecord(
        schema=BASELINE_SCHEMA,
        captured_at=stamp,
        target=str(Path(target)),
        page_size=active.page_size,
        total_bytes=active.total_bytes,
        per_module_bytes=active.per_module_bytes,
        max_modules=active.max_modules,
        modules=normalized,
        digest=_record_digest(payload),
        refused=refused_list,
    )


def _module_from_entry(entry: object) -> ModuleBaseline:
    """Build and validate one module baseline from a parsed JSON entry.

    Raises:
        ValueError: When the entry is not an object or a field is malformed.
    """

    if not isinstance(entry, Mapping):
        raise ValueError("module entry must be a JSON object")
    pages = entry.get("pages")
    if not isinstance(pages, list):
        raise ValueError("module entry pages must be a list")
    module = ModuleBaseline(
        module=entry.get("module"),  # type: ignore[arg-type]
        path=entry.get("path"),  # type: ignore[arg-type]
        size=entry.get("size"),  # type: ignore[arg-type]
        digest=entry.get("digest"),  # type: ignore[arg-type]
        pages=tuple(pages),
        captured_at=entry.get("captured_at"),  # type: ignore[arg-type]
        truncated=entry.get("truncated", False),  # type: ignore[arg-type]
    )
    _validate_module(module)
    return module


def _record_from_payload(payload: Mapping[str, object]) -> BaselineRecord:
    """Rebuild and validate a record from a parsed JSON payload.

    Raises:
        ValueError: When the payload is malformed.
    """

    target = payload.get("target")
    captured_at = payload.get("captured_at")
    page_size = payload.get("page_size")
    total_bytes = payload.get("total_bytes")
    per_module_bytes = payload.get("per_module_bytes")
    max_modules = payload.get("max_modules")
    if not isinstance(target, str) or not target:
        raise ValueError("payload.target must be a non-empty string")
    if not isinstance(captured_at, str) or not captured_at:
        raise ValueError("payload.captured_at must be a non-empty string")
    for field_name, value in (
        ("page_size", page_size),
        ("total_bytes", total_bytes),
        ("per_module_bytes", per_module_bytes),
        ("max_modules", max_modules),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"payload.{field_name} must be a positive integer")
    modules_raw = payload.get("modules")
    if not isinstance(modules_raw, list):
        raise ValueError("payload.modules must be a list")
    refused_raw = payload.get("refused", [])
    if not isinstance(refused_raw, list) or not all(isinstance(item, str) for item in refused_raw):
        raise ValueError("payload.refused must be a list of strings")
    modules = tuple(_module_from_entry(entry) for entry in modules_raw)
    return BaselineRecord(
        schema=BASELINE_SCHEMA,
        captured_at=captured_at,
        target=target,
        page_size=page_size,
        total_bytes=total_bytes,
        per_module_bytes=per_module_bytes,
        max_modules=max_modules,
        modules=modules,
        digest=_record_digest(dict(payload)),
        refused=tuple(refused_raw[:_MAX_REFUSED_REMEMBERED]),
    )


def save_baseline(target: Path, record: BaselineRecord) -> Path:
    """Write a baseline record atomically and return the store path.

    The write goes to a sibling temporary file first and is then moved into place
    with os.replace, so a crashed capture leaves the previous baseline intact.
    The record digest is recomputed from the content and a stale digest is
    rejected instead of being written.

    Raises:
        BaselineStoreError: When the record is inconsistent or cannot be written.
    """

    path = baseline_path(target)
    payload = _record_payload(record)
    digest = _record_digest(payload)
    if record.digest and record.digest != digest:
        raise BaselineStoreError("baseline record digest does not match its content")
    document = {"schema": BASELINE_SCHEMA, "digest": digest, "payload": payload}
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    temp_path = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(temp_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except OSError as exc:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except OSError:
            pass
        raise BaselineStoreError(
            f"cannot write memory baseline {path}: {type(exc).__name__}: {exc}"
        ) from exc
    return path


def load_baseline_ex(target: Path) -> BaselineLoadResult:
    """Read the baseline store and report a reason for every rejection path.

    Every failure is reported as data, never raised: a scan must keep working
    when a previous run left a truncated or hand-edited file behind.
    """

    path = baseline_path(target)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return BaselineLoadResult(None, "no baseline file recorded", False, path)
    except OSError as exc:
        return BaselineLoadResult(
            None, f"cannot read {path.name}: {type(exc).__name__}", True, path
        )
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        return BaselineLoadResult(
            None,
            f"corrupt baseline JSON in {path.name}: {exc.msg} at line {exc.lineno}",
            True,
            path,
        )
    except (TypeError, ValueError) as exc:
        return BaselineLoadResult(
            None, f"corrupt baseline document: {type(exc).__name__}", True, path
        )
    if not isinstance(document, Mapping):
        return BaselineLoadResult(None, "baseline document is not a JSON object", True, path)
    schema = document.get("schema")
    if schema != BASELINE_SCHEMA:
        return BaselineLoadResult(
            None,
            f"unsupported baseline schema {schema!r} (expected {BASELINE_SCHEMA})",
            True,
            path,
        )
    payload = document.get("payload")
    stored_digest = document.get("digest")
    if not isinstance(payload, Mapping) or not isinstance(stored_digest, str):
        return BaselineLoadResult(
            None, "baseline document is missing its payload or digest", True, path
        )
    try:
        computed = _record_digest(payload)
    except (TypeError, ValueError):
        return BaselineLoadResult(None, "baseline payload is not canonicalisable", True, path)
    if computed != stored_digest.lower():
        return BaselineLoadResult(
            None,
            "record digest mismatch: the baseline is partial or corrupt",
            True,
            path,
        )
    try:
        record = _record_from_payload(payload)
    except (KeyError, TypeError, ValueError) as exc:
        return BaselineLoadResult(None, f"invalid baseline payload: {exc}", True, path)
    return BaselineLoadResult(record, "ok", True, path)


def load_baseline(target: Path) -> BaselineRecord | None:
    """Return the stored baseline record, or None when absent or unusable."""

    return load_baseline_ex(target).record


def baseline_exists(target: Path) -> bool:
    """True when a usable memory baseline is stored for the target."""

    return load_baseline(target) is not None


def compare_baseline(current: BaselineRecord, previous: BaselineRecord) -> list[MemoryDelta]:
    """Compare a fresh capture against a stored baseline.

    Only the module digest and its page list are compared; a module that is
    present in both records with the same digest is silent. Deltas are ordered
    changed, missing, new so the most severe fact is printed first.

    Parameters:
        current: Fresh capture of the loaded module images.
        previous: Stored baseline record.

    Returns:
        Deltas sorted by severity and module name; empty when nothing changed.
    """

    page_size = previous.page_size or current.page_size or PAGE_SIZE
    current_by = {module.module: module for module in current.modules}
    previous_by = {module.module: module for module in previous.modules}
    deltas: list[MemoryDelta] = []
    for module_name in sorted(previous_by):
        before = previous_by[module_name]
        after = current_by.get(module_name)
        if after is None:
            deltas.append(
                MemoryDelta(
                    kind="missing",
                    module=module_name,
                    path=before.path,
                    page_offset=None,
                    digest_changed=False,
                    detail=f"module {module_name} is no longer part of the current image",
                )
            )
            continue
        digest_changed = after.digest != before.digest
        if not digest_changed and after.size == before.size:
            continue
        offset = _first_difference(before.pages, after.pages, page_size)
        deltas.append(
            MemoryDelta(
                kind="changed",
                module=module_name,
                path=after.path,
                page_offset=offset,
                digest_changed=digest_changed,
                detail=(
                    f"module {module_name} changed at page offset {offset}"
                    if offset is not None
                    else f"module {module_name} changed size from {before.size} to {after.size}"
                ),
            )
        )
    for module_name in sorted(set(current_by) - set(previous_by)):
        after = current_by[module_name]
        deltas.append(
            MemoryDelta(
                kind="new",
                module=module_name,
                path=after.path,
                page_offset=None,
                digest_changed=False,
                detail=f"module {module_name} appeared after the baseline was captured",
            )
        )
    rank = {kind: index for index, kind in enumerate(_DELTA_ORDER)}
    return sorted(deltas, key=lambda delta: (rank.get(delta.kind, len(_DELTA_ORDER)), delta.module))


def _first_difference(
    previous_pages: Sequence[str],
    current_pages: Sequence[str],
    page_size: int,
) -> int | None:
    """Return the byte offset of the first differing page, or None.

    A length difference counts as a change at the first page that exists on only
    one side, so a truncated or extended module never reports "unchanged".
    """

    for index in range(min(len(previous_pages), len(current_pages))):
        if previous_pages[index] != current_pages[index]:
            return index * page_size
    if len(previous_pages) != len(current_pages):
        return min(len(previous_pages), len(current_pages)) * page_size
    return None


def _module_name_map() -> dict[str, str]:
    """Map resolved image paths to the shortest module name that owns them."""

    names: dict[str, str] = {}

    def register(raw_path: object, name: str) -> None:
        if not isinstance(raw_path, str) or not raw_path:
            return
        try:
            resolved = os.path.realpath(raw_path)
        except (OSError, ValueError):
            return
        current = names.get(resolved)
        if current is None or len(name) < len(current):
            names[resolved] = name

    for module_name, module in list(sys.modules.items()):
        register(getattr(module, "__file__", None), module_name)
    register(sys.executable, "interpreter")
    return names


def _fallback_module_name(path: str) -> str:
    """Return a stable module label when no sys.modules entry owns the image."""

    return os.path.basename(path) or path


def _group_executable_images(
    inspector: MemoryInspector,
) -> tuple[dict[str, list[MemoryRegion]], tuple[str, ...]]:
    """Group executable file-backed mappings by resolved image path.

    Returns:
        (groups, refused) where groups maps a resolved path to its regions and
        refused carries the paths that failed the eligibility rules.
    """

    groups: dict[str, list[MemoryRegion]] = {}
    refused: list[str] = []
    seen_refused: set[str] = set()
    for region in inspector.executable_regions():
        if region.anonymous or not region.readable or not region.path:
            continue
        try:
            resolved = os.path.realpath(region.path)
        except (OSError, ValueError):
            continue
        allowed, reason = _baseline_candidate(resolved)
        if not allowed:
            if resolved not in seen_refused and len(refused) < _MAX_REFUSED_REMEMBERED:
                seen_refused.add(resolved)
                refused.append(f"{resolved} ({reason})")
            continue
        groups.setdefault(resolved, []).append(region)
    return groups, tuple(refused)


def _capture_live_modules(
    inspector: MemoryInspector,
    budget: BaselineBudget,
) -> tuple[tuple[ModuleBaseline, ...], tuple[str, ...]]:
    """Hash the live mapped executable images of the interpreter's modules.

    The read goes through the mapped pages, never the file, so an inline hook
    written into a clean page is part of the next digest. Both budgets are applied
    before any read, which is what keeps a capture bounded.

    Returns:
        (module baselines, refused reasons).
    """

    hasher, _backend = _resolve_hasher()
    captured_at = _utc_now()
    names = _module_name_map()
    groups, refused = _group_executable_images(inspector)
    modules: list[ModuleBaseline] = []
    remaining_total = budget.total_bytes
    ordered_paths = sorted(groups, key=lambda item: (names.get(item) or _fallback_module_name(item), item))
    for path in ordered_paths:
        if len(modules) >= budget.max_modules:
            if len(refused) < _MAX_REFUSED_REMEMBERED:
                refused += (f"{path} (module limit {budget.max_modules} reached)",)
            break
        regions = sorted(groups[path], key=lambda region: region.start)
        image_size = sum(region.size for region in regions)
        allowance = min(budget.per_module_bytes, max(0, remaining_total))
        chunks: list[bytes] = []
        read_failed = False
        for region in regions:
            if allowance <= 0:
                break
            length = min(region.size, allowance)
            try:
                chunks.append(ctypes.string_at(region.start, length))
            except (OSError, ValueError, ctypes.ArgumentError):
                read_failed = True
                break
            allowance -= length
        if read_failed:
            if len(refused) < _MAX_REFUSED_REMEMBERED:
                refused += (f"{path} (mapped executable page could not be read)",)
            continue
        image = b"".join(chunks)
        remaining_total -= len(image)
        modules.append(
            ModuleBaseline(
                module=names.get(path) or _fallback_module_name(path),
                path=path,
                size=len(image),
                digest=hasher(image),
                pages=_page_digests(image, budget.page_size, hasher),
                captured_at=captured_at,
                truncated=len(image) < image_size,
            )
        )
    return tuple(modules), refused


def _capture_for_probe(previous: BaselineRecord) -> tuple[ModuleBaseline, ...]:
    """Capture a fresh module snapshot using the stored record's own budget.

    Reusing the stored budgets matters: a module truncated at 4 MiB during the
    baseline must be truncated at 4 MiB during every later comparison, otherwise
    a budget change alone would look like tampering.
    """

    budget = BaselineBudget(
        total_bytes=previous.total_bytes,
        per_module_bytes=previous.per_module_bytes,
        page_size=previous.page_size,
        max_modules=previous.max_modules,
    )
    modules, _refused = _capture_live_modules(MemoryInspector(), budget)
    return modules


def _evaluate_baseline(target: Path) -> BaselineOutcome:
    """Load the baseline and compare it with the live module images.

    The function never writes and never raises; a comparison failure is reported
    as state "error" with the exception class named so the probe can degrade to
    its honest WARNING path.
    """

    result = load_baseline_ex(target)
    if result.record is None:
        if result.present:
            return BaselineOutcome("corrupt", 0.0, result.reason)
        return BaselineOutcome("absent", 0.0, "no baseline recorded")
    record = result.record
    try:
        modules = _capture_for_probe(record)
        budget = BaselineBudget(
            total_bytes=record.total_bytes,
            per_module_bytes=record.per_module_bytes,
            page_size=record.page_size,
            max_modules=record.max_modules,
        )
        current = make_record(target, modules, budget=budget, refused=())
        deltas = compare_baseline(current, record)
    except (OSError, ValueError, TypeError, RuntimeError, MemoryError, ctypes.ArgumentError) as exc:
        return BaselineOutcome(
            "error", 3.0, f"baseline comparison unavailable: {type(exc).__name__}"
        )
    changed = [delta for delta in deltas if delta.kind == "changed"]
    missing = [delta for delta in deltas if delta.kind == "missing"]
    new = [delta for delta in deltas if delta.kind == "new"]
    if changed:
        first = changed[0]
        offset = "an unknown page offset" if first.page_offset is None else f"page offset {first.page_offset}"
        return BaselineOutcome(
            "changed", 8.0, f"baseline mismatch: module {first.module} first differs at {offset}"
        )
    if missing:
        names = ", ".join(delta.module for delta in missing[:3])
        return BaselineOutcome(
            "missing", 4.0, f"{len(missing)} module(s) missing from the current image ({names})"
        )
    if new:
        names = ", ".join(delta.module for delta in new[:3])
        return BaselineOutcome(
            "new", 3.0, f"{len(new)} module(s) appeared after the baseline ({names})"
        )
    return BaselineOutcome(
        "clean",
        0.0,
        f"{len(record.modules)} module(s) verified against the baseline captured at {record.captured_at}",
    )


def capture_baseline(target: Path, *, budget: BaselineBudget | None = None) -> BaselineRecord:
    """Capture, persist and return a baseline for the current interpreter.

    The store is append-only in the sense that a module already known to the
    stored record is kept even when it is not loaded by this capture, so a module
    that disappears later is reported as missing instead of forgotten. When a
    record already exists its budgets are reused, which keeps page lists
    comparable across captures.

    Raises:
        BaselineStoreError: When the record cannot be written.
        ValueError: When the budget is invalid.
    """

    requested = budget if budget is not None else BaselineBudget()
    previous = load_baseline(target)
    if previous is not None:
        # Reuse the stored byte budgets so page lists stay comparable, but never
        # shrink the module cap: an append-only capture that keeps a known module
        # and adds new ones must not fail because the old cap was smaller.
        active = BaselineBudget(
            total_bytes=previous.total_bytes,
            per_module_bytes=previous.per_module_bytes,
            page_size=previous.page_size,
            max_modules=max(requested.max_modules, previous.max_modules),
        )
    else:
        active = requested
    modules, refused = _capture_live_modules(MemoryInspector(), active)
    merged: dict[str, ModuleBaseline] = {}
    if previous is not None:
        for module in previous.modules:
            merged[module.module] = module
    for module in modules:
        merged[module.module] = module
    record = make_record(target, tuple(merged.values()), budget=active, refused=refused)
    save_baseline(target, record)
    return record


def memory_baseline_capture(target: Path, *, budget: BaselineBudget | None = None) -> str:
    """Capture a baseline and return one English status line for the CLI.

    This is the function the command dispatcher calls; it converts every failure
    into a printable line so the CLI baseline command never traces back.
    """

    try:
        record = capture_baseline(target, budget=budget)
    except (BaselineStoreError, OSError, ValueError, RuntimeError) as exc:
        return f"memory baseline failed: {type(exc).__name__}: {exc}"
    total = sum(module.size for module in record.modules)
    truncated = sum(1 for module in record.modules if module.truncated)
    return (
        f"memory baseline: {len(record.modules)} module(s), "
        f"{total / (1024 * 1024):.1f} MiB hashed, {truncated} truncated, "
        f"{len(record.refused)} refused path(s), stored at {baseline_path(target)}"
    )


def _jit_executable_expected() -> bool:
    """Return True when this interpreter may legitimately own W^X memory.

    CPython 3.13 shipped an experimental JIT (PEP 744) and 3.15 enables it on
    supported builds. Such a runtime allocates executable pages that can also be
    writable while a trace is being emitted, so an anonymous write+execute
    mapping is normal there. The capability probe itself is unreliable across
    builds (the uv 3.15.0rc2 wheel exposes no usable sys._jit state yet still
    allocates that memory), so the runtime version is the primary signal and the
    sys._jit probe only refines it.

    Reporting CRITICAL for expected interpreter behaviour would teach users to
    ignore the pillar, which costs more than the theoretical detection it buys.

    Returns:
        True when an anonymous write+execute mapping should be treated as
        expected rather than as an injection artifact.
    """

    if sys.version_info >= (3, 13):
        return True
    jit = getattr(sys, "_jit", None)
    if jit is None:
        return False
    for probe_name in ("is_available", "is_enabled"):
        probe = getattr(jit, probe_name, None)
        if callable(probe):
            try:
                return bool(probe())
            except (AttributeError, RuntimeError):
                return False
    return False


def probe(ctx: ScanContext) -> Finding:
    """Run the AEGIS-VMI checks against the live interpreter process.

    The status ladder is deliberately narrow so the dossier stays actionable:
    CRITICAL means a concrete hook was found (writable pointer table, an
    anonymous dirty executable page, or a write-and-execute mapping on a runtime
    that has no JIT), SAFE means the pointer table is read-only or the native
    sealer is available, and WARNING covers the honest "could not observe"
    outcomes such as an unreadable memory map or JIT owned executable pages.

    When a stored memory baseline exists the probe also re-reads the executable
    module pages and compares them: a changed page is CRITICAL, a module that
    disappeared is a WARNING and a module that appeared after the baseline is a
    WARNING. The probe never writes the baseline; capturing it belongs to the CLI
    command, so a routine scan cannot quietly move its own goalposts.
    """

    inspector = MemoryInspector()
    regions = inspector.regions()
    exe_private = inspector.executable_private_regions()
    w_x = inspector.writable_executable_regions()
    table = inspector.pointer_table()
    digests = inspector.page_digests()
    dirty = inspector.dirty_executable_pages()
    sealer_available = _engine_can_seal()
    # Only surface the soft-dirty evidence when it discriminates: an anonymous
    # dirty page or a partial dirty set. A uniformly set bit (see the WSL note in
    # _linux_dirty_exec_pages) carries no information and must not read as alarm.
    informative_dirty = dirty.available and (
        dirty.anonymous_dirty > 0 or 0 < dirty.dirty_pages < dirty.sampled_pages
    )
    dirty_note = f"; {dirty.detail}" if informative_dirty else ""

    risk = 0.0
    # A file-backed write+execute mapping means a module image was rewritten in
    # place: that is a concrete hook and stays CRITICAL on every runtime. An
    # anonymous one on a JIT-era interpreter is the runtime's own scratch memory.
    runtime_owns_wx = _jit_executable_expected()
    anonymous_wx = [region for region in w_x if not region.path]
    file_backed_wx = [region for region in w_x if region.path]
    if file_backed_wx:
        status = "CRITICAL"
        risk = 8.5 if table.writable else 7.0
        detail = (
            f"{len(file_backed_wx)} writable executable module mapping(s) present "
            f"({file_backed_wx[0].path} at {file_backed_wx[0].start:#x}); "
            f"pointer table {_table_label(table)}"
        )
    elif anonymous_wx and runtime_owns_wx:
        # Expected interpreter scratch memory; named in the detail so a reader
        # knows the check ran and saw it, without driving the verdict.
        status = "SAFE"
        risk = 0.0
        detail = (
            f"{len(anonymous_wx)} anonymous write+execute mapping(s) owned by this "
            f"runtime ({anonymous_wx[0].start:#x}); pointer table {_table_label(table)}; not escalated"
        )
    elif anonymous_wx:
        status = "CRITICAL"
        risk = 8.5 if table.writable else 7.0
        detail = (
            f"{len(anonymous_wx)} anonymous write+execute mapping(s) on "
            f"{sys.implementation.name} {platform.python_version()} "
            f"({anonymous_wx[0].start:#x}); pointer table {_table_label(table)}"
        )
    elif dirty.available and dirty.anonymous_dirty:
        status = "CRITICAL"
        risk = 7.5
        detail = (
            f"{dirty.anonymous_dirty} anonymous executable page(s) marked soft-dirty, "
            f"which is a live code injection artefact; pointer table {_table_label(table)}"
        )
    elif table.resolved and table.writable:
        status = "CRITICAL"
        risk = 9.0
        detail = (
            f"writable pointer table: {table.detail}; "
            f"{len(exe_private)} executable private mapping(s)"
        )
    elif table.sealed or sealer_available:
        status = "SAFE"
        risk = 0.0
        detail = (
            f"pointer table read-only: {table.detail}; "
            f"{len(exe_private)} executable private mapping(s); "
            f"{digests.pages} page digest(s) via {digests.method}{dirty_note}"
        )
    elif not regions:
        status = "WARNING"
        risk = 3.0
        detail = f"memory map unavailable: {inspector.error or 'no regions'}"
    else:
        status = "WARNING"
        risk = 2.5
        detail = (
            f"pointer table not sealed: {table.detail}; "
            f"{len(exe_private)} executable private mapping(s); no native sealer{dirty_note}"
        )

    # Baseline integration. The live ladder above is authoritative for concrete
    # tamper artefacts (a writable pointer table or a W+X mapping) and is never
    # downgraded by a clean baseline. Every other state is reported through the
    # documented baseline ladder.
    ladder_status, ladder_risk, ladder_detail = status, risk, detail
    outcome = _evaluate_baseline(ctx.target)
    if outcome.state == "absent":
        detail = f"{ladder_detail}; no baseline recorded (run tauhaulity baseline --memory)"
    elif outcome.state == "corrupt":
        detail = f"{ladder_detail}; memory baseline unreadable: {outcome.detail}"
    elif outcome.state == "error":
        detail = f"{ladder_detail}; {outcome.detail}"
        if ladder_status != "CRITICAL":
            status = "WARNING"
            risk = max(ladder_risk, outcome.risk)
    elif outcome.state == "changed":
        detail = f"{outcome.detail}; {ladder_detail}"
        if ladder_status != "CRITICAL":
            status = "CRITICAL"
            risk = 8.0
    elif outcome.state in {"missing", "new"}:
        detail = f"{outcome.detail}; {ladder_detail}"
        if ladder_status != "CRITICAL":
            status = "WARNING"
            risk = outcome.risk
    else:  # clean
        detail = f"{outcome.detail}; {ladder_detail}"
        if ladder_status != "CRITICAL":
            status = "SAFE"
            risk = 0.0

    return make_finding(
        SPEC,
        status,
        detail,
        risk=risk,
        slots={"detail": detail},
        repro_hint="Dump the process memory map, inspect the pointer table, then diff the module baseline.",
    )


def _engine_can_seal() -> bool:
    """True when the engine advertises a working page protection primitive.

    The shipped engine reports capability through page_seal_status(), which
    exercises mprotect/VirtualProtect on an engine owned anonymous mapping. A
    legacy sealing method name is still honoured so a differently wired engine
    build keeps the pillar honest.
    """

    engine = _load_engine()
    if engine is None:
        return False
    for name in ("seal_pointer_table", "seal_got", "seal_iat", "seal_pages"):
        if callable(getattr(engine, name, None)):
            return True
    status_probe = getattr(engine, "page_seal_status", None)
    if callable(status_probe):
        try:
            status = status_probe()
        except (OSError, RuntimeError, ValueError, TypeError):
            return False
        if isinstance(status, dict) and status.get("protect_pages") == "available":
            return True
    return False


def _table_label(table: PointerTableView) -> str:
    """Short pointer-table description for the dossier detail line."""

    if not table.resolved:
        return "unresolved"
    return "read-only" if table.sealed else ("writable" if table.writable else "unknown")
