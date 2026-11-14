"""The pseudonymisation pepper and date jitter, kept in OnkoDICOM's configuration.

They live in ``~/.OnkoDICOM/pseudonymisation.toml``, as ``pepper`` and ``epoch_jitter`` in a
``[pseudo]`` table. A site that pseudonymised data with pymedphys, or with OnkoDICOM before
this file existed, has them in ``~/.pymedphys/config.toml``. When OnkoDICOM's file lacks a
value and pymedphys's has it, the value is copied into OnkoDICOM's file, so the site keeps
producing the same pseudonyms; pymedphys's file is never changed. Only when neither has it
is a new value created.

Losing or replacing the pepper or jitter would silently change every pseudonym from then on,
so a configuration that exists but cannot be read stops pseudonymisation instead.
"""

import functools
import logging
import os
import pathlib
import secrets
import stat
import tempfile

import toml

logger = logging.getLogger(__name__)

ONKODICOM_CONFIG_DIR = ".OnkoDICOM"
ONKODICOM_CONFIG_FILENAME = "pseudonymisation.toml"
PYMEDPHYS_CONFIG_DIR = ".pymedphys"
PYMEDPHYS_CONFIG_FILENAME = "config.toml"


class PseudonymisationConfigError(OSError):
    """A configuration exists but cannot be read, so the pepper and jitter are unknown.

    Pseudonymisation stops rather than create a new pepper, which would silently change
    every pseudonym from then on.
    """


def onkodicom_config_path() -> pathlib.Path:
    """``~/.OnkoDICOM/pseudonymisation.toml``, in the directory OnkoDICOM keeps its configuration."""
    return pathlib.Path.home().joinpath(ONKODICOM_CONFIG_DIR, ONKODICOM_CONFIG_FILENAME)


def pymedphys_config_path() -> pathlib.Path:
    """``~/.pymedphys/config.toml``, where pymedphys kept the pepper and jitter."""
    return pathlib.Path.home().joinpath(PYMEDPHYS_CONFIG_DIR, PYMEDPHYS_CONFIG_FILENAME)


def _read_toml(path: pathlib.Path) -> dict:
    """Read one TOML file.

    Raises:
        PseudonymisationConfigError: if it cannot be read or is not valid TOML.
    """
    try:
        with open(path) as f:
            return toml.load(f)
    except (OSError, toml.TomlDecodeError) as error:
        raise PseudonymisationConfigError(
            f"Cannot read the pseudonymisation configuration {path}: {error}. "
            "Pseudonymisation stopped so that the pepper and jitter are not replaced."
        ) from error


def _exists(path: pathlib.Path) -> bool:
    """Whether ``path`` exists; a symlink whose target cannot be reached is an error, not absence.

    ``Path.exists()`` is false for such a link (a shared configuration on a share that is
    offline), and treating that as "no configuration" would create a new pepper.

    Raises:
        PseudonymisationConfigError: if ``path`` is a symlink whose target does not exist.
    """
    if path.exists():
        return True
    if path.is_symlink():
        raise PseudonymisationConfigError(
            f"The pseudonymisation configuration {path} is a link to {os.readlink(path)}, which cannot "
            "be reached. Pseudonymisation stopped so that the pepper and jitter are not replaced."
        )
    return False


def _read_onkodicom_config() -> dict:
    """OnkoDICOM's configuration, or an empty one if the file does not exist yet.

    Raises:
        PseudonymisationConfigError: if it exists but cannot be read, or is a broken link.
    """
    path = onkodicom_config_path()
    return _read_toml(path) if _exists(path) else {}


def _read_pymedphys_config() -> dict:
    """pymedphys's configuration, following its ``redirect`` entries; empty if there is none.

    Raises:
        PseudonymisationConfigError: if it, or a file it redirects to, cannot be read, or the
            redirects loop.
    """
    config_path = pymedphys_config_path()
    if not _exists(config_path):
        return {}
    read_already: set[pathlib.Path] = set()
    while True:
        resolved = config_path.resolve()
        if resolved in read_already:
            raise PseudonymisationConfigError(
                f"The pymedphys configuration redirects in a loop back to {config_path}. "
                "Pseudonymisation stopped so that the pepper and jitter are not replaced."
            )
        read_already.add(resolved)
        results = _read_toml(config_path)
        try:
            config_path = pathlib.Path(results["redirect"])
        except KeyError:
            return results


def _get_or_move_or_create(key: str, create, is_valid):
    """Return ``[pseudo] key``: from OnkoDICOM's configuration, else moved from pymedphys's, else new.

    A value moved or created is written to OnkoDICOM's configuration, keeping its other keys.

    Raises:
        PseudonymisationConfigError: if a configuration cannot be read, or holds a value for
            ``key`` that ``is_valid`` rejects.
    """
    onkodicom = _read_onkodicom_config()
    if key in onkodicom.get("pseudo", {}):
        return _checked(key, onkodicom["pseudo"][key], is_valid, onkodicom_config_path())
    pymedphys = _read_pymedphys_config().get("pseudo", {})
    if key in pymedphys:
        value = _checked(key, pymedphys[key], is_valid, pymedphys_config_path())
        logger.info("Pseudonymisation %s copied from the pymedphys configuration to %s", key, onkodicom_config_path())
    else:
        value = create()
        logger.info("Pseudonymisation %s created in %s", key, onkodicom_config_path())
    onkodicom.setdefault("pseudo", {})[key] = value
    path = onkodicom_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_atomically(path, onkodicom)
    return value


def _checked(key: str, value, is_valid, path: pathlib.Path):
    """Return ``value`` if ``is_valid(value)``.

    Raises:
        PseudonymisationConfigError: otherwise; the value is not quoted, since it may be the pepper.
    """
    if not is_valid(value):
        raise PseudonymisationConfigError(
            f"The pseudonymisation {key} in {path} is not valid (a {type(value).__name__}). "
            "Pseudonymisation stopped so that the pepper and jitter are not replaced."
        )
    return value


def _write_atomically(path: pathlib.Path, config: dict) -> None:
    """Replace ``path`` with ``config`` in one step, so a failure part-way leaves the old file whole.

    Rewriting in place could leave the file empty or partial (a crash, a full disk), and the
    next run would then create a new pepper, changing every pseudonym (#69). The directory
    is synced after the replace, so a power loss cannot undo it.

    The new file keeps the old one's permissions, except that it is never readable or
    writable by every user: it holds the pepper. A site may share it with a group through a
    link, so group permissions are kept. A first file is readable by its owner only.
    """
    # Through a symlink, the file to replace is its target: os.replace would replace the link
    # itself, and a configuration reached by a link would stop being written.
    path = path.resolve()
    mode = stat.S_IMODE(path.stat().st_mode) & ~0o007 if path.exists() else 0o600
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            toml.dump(config, f)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise
    _sync_directory(path.parent)


def _sync_directory(directory: pathlib.Path) -> None:
    """Make a replace in ``directory`` durable. POSIX only: Windows cannot open a directory to sync it."""
    if os.name != "posix":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@functools.lru_cache()
def get_pepper() -> bytes:
    """Return the pepper added to every hashed value.

    The pepper is not stored with the pseudonymised data, which makes a dictionary attack on
    the pseudonyms harder.

    Raises:
        PseudonymisationConfigError: if a configuration exists but cannot be read, or its
            pepper is not ASCII text.
    """
    return _get_or_move_or_create(
        "pepper", lambda: secrets.token_urlsafe(32), lambda v: isinstance(v, str) and v.isascii()
    ).encode("ASCII")


@functools.lru_cache()
def get_epoch_jitter() -> int:
    """Return the number of days (0 to 999) added to shifted dates.

    Raises:
        PseudonymisationConfigError: if a configuration exists but cannot be read, or its
            jitter is not a whole number. A new jitter is from 0 to 999, but pymedphys accepted
            any whole number, and a site may have set one.
    """
    return _get_or_move_or_create(
        "epoch_jitter",
        lambda: secrets.randbelow(1000),
        lambda v: isinstance(v, int) and not isinstance(v, bool),
    )


def clear_cache() -> None:
    """Forget the pepper and jitter read so far, so the next call reads the configuration again."""
    get_pepper.cache_clear()
    get_epoch_jitter.cache_clear()


__all__ = [
    "PseudonymisationConfigError",
    "clear_cache",
    "get_epoch_jitter",
    "get_pepper",
    "onkodicom_config_path",
    "pymedphys_config_path",
]
