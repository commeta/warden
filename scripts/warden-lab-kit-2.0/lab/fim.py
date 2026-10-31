"""FIM path coverage shared by the PHP sites and microservices.

Keep this list aligned with Warden 0.14.3's default ``fim.site.include`` and
add explicit upload-path patterns for script types that must never be present
in writable upload directories. Warden's ``files`` signature filter is a
separate basename-only filter (see ``templates/warden/lab-signatures.toml``).
"""


_WARDEN_DEFAULT_INCLUDE = (
    "**/*.php",
    "**/*.php[0-9]",
    "**/*.phtml",
    "**/*.pht",
    "**/*.phar",
    "**/*.inc",
    "**/*.module",
    "**/*.js",
    "**/*.mjs",
    "**/*.cjs",
    "**/*.jsx",
    "**/*.ts",
    "**/*.py",
    "**/*.pyc",
    "**/*.rb",
    "**/*.pl",
    "**/*.pm",
    "**/*.cgi",
    "**/*.sh",
    "**/*.jsp",
    "**/*.jspx",
    "**/*.asp",
    "**/*.aspx",
    "**/*.cfm",
    "**/*.html",
    "**/*.htm",
    "**/*.shtml",
    "**/*.svg",
    "**/.htaccess",
    "**/.user.ini",
    "**/php.ini",
    "**/web.config",
    "**/*.so",
    "**/*.wasm",
)

_UPLOAD_SCRIPT_PATTERNS = (
    "*.php",
    "*.php[0-9]",
    "*.phtml",
    "*.pht",
    "*.phar",
)


def fim_include_globs() -> list[str]:
    """Return an explicit include list, including direct and nested uploads."""
    upload_globs = [
        pattern
        for suffix in _UPLOAD_SCRIPT_PATTERNS
        for pattern in (f"uploads/{suffix}", f"uploads/**/{suffix}")
    ]
    return list(dict.fromkeys((*_WARDEN_DEFAULT_INCLUDE, *upload_globs)))
