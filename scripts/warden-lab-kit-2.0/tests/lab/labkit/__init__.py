"""Black-box helpers for the Warden Lab pytest suite.

The tests talk to the stand exactly as a client or an operator would: HTTP
from a chosen source address (``http.py``), the Warden control socket
(``warden.py``), a tailed event window (``journal.py``), and the selected WAF
log mode (``modsec.py``). Nothing reads Warden's internal state.
"""
