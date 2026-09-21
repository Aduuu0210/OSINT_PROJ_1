"""Investigative modules.

`web_dorks`, `news_search`, `maps_search` and `lens_search` are backed by SerpApi
vertical engines. `hibp_breach` is the exception: it queries Have I Been Pwned
directly and needs its own (paid) API key, so it is opt-in.
"""

from .web_dorks import WebDorksModule
from .lens_search import LensSearchModule
from .maps_search import MapsSearchModule
from .news_search import NewsSearchModule
from .hibp_breach import HibpBreachModule

__all__ = [
    "WebDorksModule",
    "LensSearchModule",
    "MapsSearchModule",
    "NewsSearchModule",
    "HibpBreachModule",
]
