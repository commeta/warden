// Warden Lab microservice — ASP.NET Core minimal API (OPTIONAL).
// Needs the dotnet SDK, which is not in the base Ubuntu archive, so this
// service is only built when `dotnet` is explicitly enabled and present.
// It implements the read-only parts of the shared contract.
using System.Diagnostics;

var root = Environment.GetEnvironmentVariable("LAB_ROOT") ?? "/tmp";
var port = Environment.GetEnvironmentVariable("PORT") ?? "3108";

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Lab-Service"] = "dotnet";
    await next();
});

string Strip(HttpContext c) => c.Request.Path.Value ?? "/";

app.MapGet("/health", () => "ok");
app.MapGet("/echo", (string? q) => $"echo: {q}");                       // XSS target
app.MapGet("/sleep", (int ms) => { Thread.Sleep(Math.Min(ms, 10000)); return "slept"; });
app.MapGet("/alloc", (int mb) =>
{
    mb = Math.Clamp(mb, 1, 256);
    var buf = new byte[mb * 1024 * 1024];
    buf[0] = 1;
    return $"alloc {mb} ({buf[0]})";
});
app.MapGet("/spawn", () =>                                               // web_spawn target
{
    var p = Process.Start(new ProcessStartInfo("/usr/bin/id") { RedirectStandardOutput = true });
    p!.WaitForExit();
    return p.StandardOutput.ReadToEnd() + "spawned";
});

app.Run($"http://127.0.0.1:{port}");
