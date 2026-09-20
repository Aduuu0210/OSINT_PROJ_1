"""Investigative modules backed exclusively by SerpApi vertical engines."""

from .web_dorks import WebDorksModule
from .lens_search import LensSearchModule
from .maps_search import MapsSearchModule
from .news_search import NewsSearchModule

__all__ = [
    "WebDorksModule",
    "LensSearchModule",
    "MapsSearchModule",
    "NewsSearchModule",
]
