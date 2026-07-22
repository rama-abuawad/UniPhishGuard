from html.parser import HTMLParser


class VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.suppressed_tags: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        attributes = {name.lower(): (value or "").lower() for name, value in attrs}
        style = attributes.get("style", "").replace(" ", "")
        hidden = "hidden" in attributes or attributes.get("aria-hidden") == "true" or any(
            marker in style for marker in ("display:none", "visibility:hidden", "opacity:0")
        )
        if tag.lower() in {"script", "style", "noscript", "template"} or hidden or self.suppressed_tags:
            self.suppressed_tags.append(tag.lower())

    def handle_endtag(self, tag: str):
        lowered = tag.lower()
        if lowered in self.suppressed_tags:
            index = len(self.suppressed_tags) - 1 - self.suppressed_tags[::-1].index(lowered)
            del self.suppressed_tags[index:]

    def handle_data(self, data: str):
        if not self.suppressed_tags:
            self.parts.append(data)


def visible_html_text(value: str) -> str:
    parser = VisibleTextParser()
    parser.feed(value or "")
    parser.close()
    return " ".join(" ".join(parser.parts).split())
