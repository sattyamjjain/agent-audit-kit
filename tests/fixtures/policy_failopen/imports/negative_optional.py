"""An optional import that is no policy. This one must not fire."""

try:
    from yaml import CSafeLoader as Loader
except ImportError:
    Loader = None


def load(text, parser):
    if Loader is None:
        return parser(text)
    return Loader(text).get_data()
