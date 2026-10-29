// Warden Lab microservice — Java (com.sun.net.httpserver from the JDK).
// No third-party dependencies; large JVM RSS is intentional (a memory target).
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class Server {
    static String root = env("LAB_ROOT", "/tmp");

    static String env(String k, String d) { String v = System.getenv(k); return v == null ? d : v; }

    static Map<String,String> query(String raw) {
        Map<String,String> m = new HashMap<>();
        if (raw == null) return m;
        for (String p : raw.split("&")) {
            int i = p.indexOf('=');
            try {
                if (i > 0) m.put(URLDecoder.decode(p.substring(0,i), "UTF-8"),
                                 URLDecoder.decode(p.substring(i+1), "UTF-8"));
            } catch (Exception e) {}
        }
        return m;
    }

    static void reply(HttpExchange x, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().set("X-Lab-Service", "java");
        x.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        x.sendResponseHeaders(code, b.length);
        try (OutputStream o = x.getResponseBody()) { o.write(b); }
    }

    static String run(String... cmd) {
        try {
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor();
            return out;
        } catch (Exception e) { return "error"; }
    }

    public static void main(String[] a) throws IOException {
        int port = Integer.parseInt(env("PORT", "3105"));
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        s.createContext("/", x -> {
            String path = x.getRequestURI().getPath().replaceFirst("^/svc/[^/]+", "");
            if (path.isEmpty()) path = "/";
            Map<String,String> q = query(x.getRequestURI().getRawQuery());
            try {
                switch (path) {
                    case "/health": reply(x, 200, "ok"); break;
                    case "/echo": reply(x, 200, "echo: " + q.getOrDefault("q","")); break;
                    case "/item": {
                        String id = q.getOrDefault("id","1");
                        String out = run("/usr/bin/sqlite3","-readonly", root+"/data/items.sqlite",
                            "SELECT id||'|'||name||'|'||note FROM items WHERE id = " + id);
                        reply(x, 200, out.isEmpty() ? "no result" : out); break;
                    }
                    case "/spawn": reply(x, 200, run("/usr/bin/id") + "spawned"); break;
                    case "/sleep": {
                        int ms = Math.min(Integer.parseInt(q.getOrDefault("ms","0")), 10000);
                        Thread.sleep(ms); reply(x, 200, "slept"); break;
                    }
                    case "/alloc": {
                        int mb = Math.max(1, Math.min(Integer.parseInt(q.getOrDefault("mb","1")), 256));
                        byte[] buf = new byte[mb*1024*1024]; buf[0]=1;
                        reply(x, 200, "alloc " + mb + " (" + buf[0] + ")"); break;
                    }
                    case "/upload": {
                        if (!x.getRequestMethod().equals("POST")) { reply(x,405,"POST"); break; }
                        Files.createDirectories(Paths.get(root, "uploads"));
                        String name = q.getOrDefault("name","upload.bin").replaceAll("[^A-Za-z0-9._-]","_");
                        byte[] body = x.getRequestBody().readNBytes(262144);
                        Files.write(Paths.get(root, "uploads", name), body);
                        reply(x, 200, "stored uploads/" + name); break;
                    }
                    default: reply(x, 404, "not found");
                }
            } catch (Exception e) { reply(x, 500, "error"); }
        });
        s.setExecutor(null);
        s.start();
        System.out.println("java lab svc on " + port);
    }
}
