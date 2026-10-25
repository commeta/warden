<?php
header('Content-Type: text/html; charset=utf-8');
?><!doctype html><html lang="en"><head><meta charset="utf-8"><title>Warden isolated security lab</title></head><body>
<h1>Warden / ModSecurity test application</h1>
<p>Isolated disposable VM only. These routes intentionally demonstrate common web input flaws.</p>
<ul>
<li><a href="health.php">Health check</a></li>
<li><a href="xss.php?q=hello">Reflected XSS test route</a></li>
<li><a href="sqli.php?id=1">Read-only SQL injection test route</a></li>
<li><a href="traversal.php?file=hello.txt">Path traversal test route</a></li>
<li><a href="command-sim.php?cmd=whoami">Command-injection signal simulation (does not execute commands)</a></li>
</ul>
<p>WAF test expectation: benign request 200; common XSS/SQLi/LFI probes blocked with 403 and logged to ModSecurity audit log.</p>
</body></html>
