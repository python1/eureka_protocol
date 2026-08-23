import importlib
import pkgutil

import eureka_protocol


def test_all_modules_import():
    failures = []
    for m in pkgutil.walk_packages(eureka_protocol.__path__,
                                   eureka_protocol.__name__ + "."):
        try:
            importlib.import_module(m.name)
        except Exception as e:
            failures.append(f"{m.name}: {type(e).__name__}: {e}")
    assert not failures, "\n".join(failures)
