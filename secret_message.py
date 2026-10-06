import urllib.request
from html.parser import HTMLParser


class _DocTableParser(HTMLParser):
    """Collects the text of every <td> cell in document order."""

    def __init__(self):
        super().__init__()
        self._in_cell = False
        self._buf = []
        self.cells = []

    def handle_starttag(self, tag, attrs):
        if tag == "td":
            self._in_cell = True
            self._buf = []

    def handle_endtag(self, tag):
        if tag == "td":
            self._in_cell = False
            self.cells.append("".join(self._buf).strip())

    def handle_data(self, data):
        if self._in_cell:
            self._buf.append(data)


def print_secret_message(url):
    """Fetch a published Google Doc of (char, x, y) triples and print the grid."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    html = urllib.request.urlopen(req).read().decode("utf-8")

    parser = _DocTableParser()
    parser.feed(html)
    cells = parser.cells

    # The table has three columns: x-coordinate, Character, y-coordinate.
    # The first three cells are the header row; skip them, then read triples.
    header = [c.lower() for c in cells[:3]]
    x_i, c_i, y_i = header.index("x-coordinate"), header.index("character"), header.index("y-coordinate")

    points = {}
    max_x = max_y = 0
    for i in range(3, len(cells) - 2, 3):
        triple = cells[i:i + 3]
        x = int(triple[x_i])
        y = int(triple[y_i])
        ch = triple[c_i]
        points[(x, y)] = ch
        max_x, max_y = max(max_x, x), max(max_y, y)

    # (0, 0) is the bottom-left corner: x increases rightward, y increases upward,
    # so print from the top row (max_y) down to row 0.
    for y in range(max_y, -1, -1):
        print("".join(points.get((x, y), " ") for x in range(max_x + 1)))


if __name__ == "__main__":
    import sys
    print_secret_message(sys.argv[1])
