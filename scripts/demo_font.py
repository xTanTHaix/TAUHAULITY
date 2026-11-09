"""A compact 5x7 bitmap font and text rasteriser for generated demo assets.

Ninety-five glyphs, five pixels wide and seven tall. The table is column major:
each glyph is five bytes, one per pixel column, and bit zero of a byte is the top
pixel of that column. The two trailing bytes of each tuple are padding, kept so
the table stays a uniform seven bytes per entry. Column major matches the classic
hand drawn 5x7 fonts this data comes from, and converting to row bitmaps here
means every renderer shares one correct interpretation instead of repeating a
transpose bug.

A font this small keeps the generator dependency free: the GIF encoder and the
rasteriser are plain Python, so regenerating a demo never downloads a font or an
image library.
"""

from __future__ import annotations

import functools
from typing import Final

GLYPH_WIDTH: Final[int] = 5
GLYPH_HEIGHT: Final[int] = 7
GLYPH_ADVANCE: Final[int] = 6

#: The demo renders at scale two so a 960 pixel wide window still looks crisp on
#: a retina display when the GIF is shown at README width.
DEFAULT_SCALE: Final[int] = 2
#: One empty pixel between glyph cells. Without it, adjacent letters of a twelve
#: pixel wide typeface blur together at GIF compression.
DEFAULT_TRACKING: Final[int] = 1
#: Empty pixel rows between text baselines.
DEFAULT_LINE_GAP: Final[int] = 2

#: One entry per printable ASCII character, from space (0x20) to tilde (0x7E).
FONT_5X7: Final[dict[str, tuple[int, ...]]] = {
    " ": (0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
    "!": (0x00, 0x00, 0x5F, 0x00, 0x00, 0x00, 0x00),
    '"': (0x00, 0x07, 0x00, 0x07, 0x00, 0x00, 0x00),
    "#": (0x14, 0x7F, 0x14, 0x7F, 0x14, 0x00, 0x00),
    "$": (0x24, 0x2A, 0x7F, 0x2A, 0x12, 0x00, 0x00),
    "%": (0x23, 0x13, 0x08, 0x64, 0x62, 0x00, 0x00),
    "&": (0x36, 0x49, 0x55, 0x22, 0x50, 0x00, 0x00),
    "'": (0x00, 0x05, 0x03, 0x00, 0x00, 0x00, 0x00),
    "(": (0x00, 0x1C, 0x22, 0x41, 0x00, 0x00, 0x00),
    ")": (0x00, 0x41, 0x22, 0x1C, 0x00, 0x00, 0x00),
    "*": (0x14, 0x08, 0x3E, 0x08, 0x14, 0x00, 0x00),
    "+": (0x08, 0x08, 0x3E, 0x08, 0x08, 0x00, 0x00),
    ",": (0x00, 0x50, 0x30, 0x00, 0x00, 0x00, 0x00),
    "-": (0x08, 0x08, 0x08, 0x08, 0x08, 0x00, 0x00),
    ".": (0x00, 0x60, 0x60, 0x00, 0x00, 0x00, 0x00),
    "/": (0x20, 0x10, 0x08, 0x04, 0x02, 0x00, 0x00),
    "0": (0x3E, 0x51, 0x49, 0x45, 0x3E, 0x00, 0x00),
    "1": (0x00, 0x42, 0x7F, 0x40, 0x00, 0x00, 0x00),
    "2": (0x42, 0x61, 0x51, 0x49, 0x46, 0x00, 0x00),
    "3": (0x21, 0x41, 0x45, 0x4B, 0x31, 0x00, 0x00),
    "4": (0x18, 0x14, 0x12, 0x7F, 0x10, 0x00, 0x00),
    "5": (0x27, 0x45, 0x45, 0x45, 0x39, 0x00, 0x00),
    "6": (0x3C, 0x4A, 0x49, 0x49, 0x30, 0x00, 0x00),
    "7": (0x01, 0x71, 0x09, 0x05, 0x03, 0x00, 0x00),
    "8": (0x36, 0x49, 0x49, 0x49, 0x36, 0x00, 0x00),
    "9": (0x06, 0x49, 0x49, 0x29, 0x1E, 0x00, 0x00),
    ":": (0x00, 0x36, 0x36, 0x00, 0x00, 0x00, 0x00),
    ";": (0x00, 0x56, 0x36, 0x00, 0x00, 0x00, 0x00),
    "<": (0x08, 0x14, 0x22, 0x41, 0x00, 0x00, 0x00),
    "=": (0x14, 0x14, 0x14, 0x14, 0x14, 0x00, 0x00),
    ">": (0x00, 0x41, 0x22, 0x14, 0x08, 0x00, 0x00),
    "?": (0x02, 0x01, 0x51, 0x09, 0x06, 0x00, 0x00),
    "@": (0x32, 0x49, 0x79, 0x41, 0x3E, 0x00, 0x00),
    "A": (0x7E, 0x11, 0x11, 0x11, 0x7E, 0x00, 0x00),
    "B": (0x7F, 0x49, 0x49, 0x49, 0x36, 0x00, 0x00),
    "C": (0x3E, 0x41, 0x41, 0x41, 0x22, 0x00, 0x00),
    "D": (0x7F, 0x41, 0x41, 0x22, 0x1C, 0x00, 0x00),
    "E": (0x7F, 0x49, 0x49, 0x49, 0x41, 0x00, 0x00),
    "F": (0x7F, 0x09, 0x09, 0x09, 0x01, 0x00, 0x00),
    "G": (0x3E, 0x41, 0x49, 0x49, 0x7A, 0x00, 0x00),
    "H": (0x7F, 0x08, 0x08, 0x08, 0x7F, 0x00, 0x00),
    "I": (0x00, 0x41, 0x7F, 0x41, 0x00, 0x00, 0x00),
    "J": (0x20, 0x40, 0x41, 0x3F, 0x01, 0x00, 0x00),
    "K": (0x7F, 0x08, 0x14, 0x22, 0x41, 0x00, 0x00),
    "L": (0x7F, 0x40, 0x40, 0x40, 0x40, 0x00, 0x00),
    "M": (0x7F, 0x02, 0x0C, 0x02, 0x7F, 0x00, 0x00),
    "N": (0x7F, 0x04, 0x08, 0x10, 0x7F, 0x00, 0x00),
    "O": (0x3E, 0x41, 0x41, 0x41, 0x3E, 0x00, 0x00),
    "P": (0x7F, 0x09, 0x09, 0x09, 0x06, 0x00, 0x00),
    "Q": (0x3E, 0x41, 0x51, 0x21, 0x5E, 0x00, 0x00),
    "R": (0x7F, 0x09, 0x19, 0x29, 0x46, 0x00, 0x00),
    "S": (0x46, 0x49, 0x49, 0x49, 0x31, 0x00, 0x00),
    "T": (0x01, 0x01, 0x7F, 0x01, 0x01, 0x00, 0x00),
    "U": (0x3F, 0x40, 0x40, 0x40, 0x3F, 0x00, 0x00),
    "V": (0x1F, 0x20, 0x40, 0x20, 0x1F, 0x00, 0x00),
    "W": (0x7F, 0x20, 0x18, 0x20, 0x7F, 0x00, 0x00),
    "X": (0x63, 0x14, 0x08, 0x14, 0x63, 0x00, 0x00),
    "Y": (0x03, 0x04, 0x78, 0x04, 0x03, 0x00, 0x00),
    "Z": (0x61, 0x51, 0x49, 0x45, 0x43, 0x00, 0x00),
    "[": (0x00, 0x7F, 0x41, 0x41, 0x00, 0x00, 0x00),
    "\\": (0x02, 0x04, 0x08, 0x10, 0x20, 0x00, 0x00),
    "]": (0x00, 0x41, 0x41, 0x7F, 0x00, 0x00, 0x00),
    "^": (0x04, 0x02, 0x01, 0x02, 0x04, 0x00, 0x00),
    "_": (0x40, 0x40, 0x40, 0x40, 0x40, 0x00, 0x00),
    "`": (0x00, 0x01, 0x02, 0x04, 0x00, 0x00, 0x00),
    "a": (0x20, 0x54, 0x54, 0x54, 0x78, 0x00, 0x00),
    "b": (0x7F, 0x48, 0x44, 0x44, 0x38, 0x00, 0x00),
    "c": (0x38, 0x44, 0x44, 0x44, 0x20, 0x00, 0x00),
    "d": (0x38, 0x44, 0x44, 0x48, 0x7F, 0x00, 0x00),
    "e": (0x38, 0x54, 0x54, 0x54, 0x18, 0x00, 0x00),
    "f": (0x08, 0x7E, 0x09, 0x01, 0x02, 0x00, 0x00),
    "g": (0x0C, 0x52, 0x52, 0x52, 0x3E, 0x00, 0x00),
    "h": (0x7F, 0x08, 0x04, 0x04, 0x78, 0x00, 0x00),
    "i": (0x00, 0x44, 0x7D, 0x40, 0x00, 0x00, 0x00),
    "j": (0x20, 0x40, 0x44, 0x3D, 0x00, 0x00, 0x00),
    "k": (0x7F, 0x10, 0x28, 0x44, 0x00, 0x00, 0x00),
    "l": (0x00, 0x41, 0x7F, 0x40, 0x00, 0x00, 0x00),
    "m": (0x7C, 0x04, 0x18, 0x04, 0x78, 0x00, 0x00),
    "n": (0x7C, 0x08, 0x04, 0x04, 0x78, 0x00, 0x00),
    "o": (0x38, 0x44, 0x44, 0x44, 0x38, 0x00, 0x00),
    "p": (0x7C, 0x14, 0x14, 0x14, 0x08, 0x00, 0x00),
    "q": (0x08, 0x14, 0x14, 0x18, 0x7C, 0x00, 0x00),
    "r": (0x7C, 0x08, 0x04, 0x04, 0x08, 0x00, 0x00),
    "s": (0x48, 0x54, 0x54, 0x54, 0x20, 0x00, 0x00),
    "t": (0x04, 0x3F, 0x44, 0x40, 0x20, 0x00, 0x00),
    "u": (0x3C, 0x40, 0x40, 0x20, 0x7C, 0x00, 0x00),
    "v": (0x1C, 0x20, 0x40, 0x20, 0x1C, 0x00, 0x00),
    "w": (0x3C, 0x40, 0x30, 0x40, 0x3C, 0x00, 0x00),
    "x": (0x44, 0x28, 0x10, 0x28, 0x44, 0x00, 0x00),
    "y": (0x0C, 0x50, 0x50, 0x50, 0x3C, 0x00, 0x00),
    "z": (0x44, 0x64, 0x54, 0x4C, 0x44, 0x00, 0x00),
    "{": (0x00, 0x08, 0x36, 0x41, 0x00, 0x00, 0x00),
    "|": (0x00, 0x00, 0x7F, 0x00, 0x00, 0x00, 0x00),
    "}": (0x00, 0x41, 0x36, 0x08, 0x00, 0x00, 0x00),
    "~": (0x08, 0x04, 0x08, 0x10, 0x08, 0x00, 0x00),
}

FALLBACK_GLYPH: Final[tuple[int, ...]] = (0x7F, 0x41, 0x41, 0x41, 0x7F, 0x00, 0x00)


@functools.lru_cache(maxsize=256)
def glyph(char: str) -> tuple[int, ...]:
    """Return the seven row bitmasks for one character.

    The stored table is column major, so each entry is transposed into seven row
    masks whose low five bits are the five pixel columns, most significant bit
    leftmost. This is the only place the transpose happens.

    Parameters:
        char: Any single character; unknown characters render as a filled box so
            a missing glyph is visible instead of silently blank.

    Returns:
        Seven row values, five bits each.
    """

    columns = FONT_5X7.get(char, FALLBACK_GLYPH)
    rows: list[int] = []
    for row_index in range(GLYPH_HEIGHT):
        bits = 0
        for column_index in range(GLYPH_WIDTH):
            if columns[column_index] & (1 << row_index):
                bits |= 1 << (GLYPH_WIDTH - 1 - column_index)
        rows.append(bits)
    return tuple(rows)


def advance(scale: int = 1, tracking: int = 0) -> int:
    """Return the horizontal step from one glyph cell to the next.

    Parameters:
        scale: Integer pixel multiplier.
        tracking: Extra empty pixels after each cell.

    Raises:
        ValueError: When scale is below one or tracking is negative.
    """

    if scale < 1:
        raise ValueError("scale must be at least one")
    if tracking < 0:
        raise ValueError("tracking must not be negative")
    return GLYPH_WIDTH * scale + tracking


def line_height(scale: int = DEFAULT_SCALE, gap: int = DEFAULT_LINE_GAP) -> int:
    """Return the distance between two consecutive text baselines.

    Raises:
        ValueError: When scale is below one or gap is negative.
    """

    if scale < 1:
        raise ValueError("scale must be at least one")
    if gap < 0:
        raise ValueError("gap must not be negative")
    return GLYPH_HEIGHT * scale + gap


def text_width(text: str, scale: int = 1, tracking: int = 0) -> int:
    """Return the pixel width of a string at a given scale and tracking.

    The final glyph carries its trailing tracking too, so the result can be used
    directly as the x coordinate of a caret that follows the text.

    Raises:
        ValueError: When scale is below one or tracking is negative.
        TypeError: When text is not a string.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    return len(text) * advance(scale, tracking)


class Canvas:
    """A monochrome bitmap with helper drawing operations.

    Attributes:
        width: Canvas width in pixels.
        height: Canvas height in pixels.
    """

    def __init__(self, width: int, height: int, background: int = 0) -> None:
        if width <= 0 or height <= 0:
            raise ValueError("canvas dimensions must be positive")
        self.width = int(width)
        self.height = int(height)
        self.pixels = bytearray([background]) * (self.width * self.height)

    def set(self, x: int, y: int, value: int = 1) -> None:
        """Set one pixel, ignoring coordinates outside the canvas."""

        if 0 <= x < self.width and 0 <= y < self.height:
            self.pixels[y * self.width + x] = value

    def fill_rect(self, x: int, y: int, width: int, height: int, value: int = 1) -> None:
        """Fill a rectangle, clipped to the canvas."""

        for row in range(y, y + height):
            if not 0 <= row < self.height:
                continue
            base = row * self.width
            for column in range(x, x + width):
                if 0 <= column < self.width:
                    self.pixels[base + column] = value

    def hline(self, x: int, y: int, width: int, value: int = 1) -> None:
        """Draw a horizontal line."""

        self.fill_rect(x, y, width, 1, value)

    def fill(self, value: int) -> None:
        """Replace every pixel with one palette index."""

        self.pixels = bytearray([value]) * (self.width * self.height)

    def fill_circle(self, centre_x: int, centre_y: int, radius: int, value: int = 1) -> None:
        """Draw a filled circle, clipped to the canvas.

        The title bar traffic lights are the only circles in the design, so an
        integer midpoint test is enough and avoids pulling in math or a
        rasteriser.

        Raises:
            ValueError: When radius is negative.
        """

        if radius < 0:
            raise ValueError("radius must not be negative")
        for offset_y in range(-radius, radius + 1):
            span = int((radius * radius - offset_y * offset_y) ** 0.5)
            self.fill_rect(
                centre_x - span,
                centre_y + offset_y,
                span * 2 + 1,
                1,
                value,
            )

    def draw_text(
        self,
        x: int,
        y: int,
        text: str,
        scale: int = 2,
        value: int = 1,
        tracking: int = 0,
    ) -> int:
        """Draw text with the 5x7 font and return the x position after it.

        Parameters:
            x: Left pixel of the first glyph.
            y: Top pixel of the first glyph.
            text: Characters to draw.
            scale: Integer pixel multiplier; 2 gives a 10x14 character cell.
            value: Pixel value to write.
            tracking: Empty pixels after each glyph cell.

        Raises:
            ValueError: When scale is below one or tracking is negative.
        """

        if scale < 1:
            raise ValueError("scale must be at least one")
        if tracking < 0:
            raise ValueError("tracking must not be negative")
        cursor = x
        step = advance(scale, tracking)
        for char in text:
            rows = glyph(char)
            for row_index, bits in enumerate(rows):
                for column in range(GLYPH_WIDTH):
                    if bits & (1 << (GLYPH_WIDTH - 1 - column)):
                        self.fill_rect(
                            cursor + column * scale,
                            y + row_index * scale,
                            scale,
                            scale,
                            value,
                        )
            cursor += step
        return cursor

    def draw_text_bold(
        self,
        x: int,
        y: int,
        text: str,
        scale: int = 2,
        value: int = 1,
        tracking: int = 0,
    ) -> int:
        """Draw text twice, the second pass one pixel to the right.

        The demo has a single typeface, so bold has to be synthesised. One pixel
        of horizontal offset thickens every stroke without changing the advance,
        which keeps a bold command aligned with the output below it.
        """

        cursor = self.draw_text(x, y, text, scale, value, tracking)
        self.draw_text(x + 1, y, text, scale, value, tracking)
        return cursor

    def ink_pixels(self, background: int = 0) -> int:
        """Return how many pixels differ from the background index."""

        return sum(1 for pixel in self.pixels if pixel != background)

    def ink_coverage(self, background: int = 0) -> float:
        """Return the fraction of non background pixels in the canvas."""

        return self.ink_pixels(background) / (self.width * self.height)
