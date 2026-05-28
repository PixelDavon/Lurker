import http.server
import socketserver
import os

# python ./mock_server/mock_server.py
# python lurker.py scan --url http://127.0.0.1:8000 --wordlist ./mock_server/wordlist.txt

PORT = 8000

# 100 valid paths
VALID_PATHS = [
    "admin", "config", "logs", "dashboard", "home", "index.html", "login", "logout",
    "register", "profile", "settings", "api", "users", "products", "orders", "cart",
    "checkout", "search", "faq", "about","contact", "support", "blog", "news",
    "docs", "help", "status", "download", "upload", "static", "assets", "images",
    "css", "js", "fonts", "media", "videos", "audio", "data", "backup", "db",
    "test", "debug", "info", "metrics", "health", "version", "robots.txt", "sitemap.xml",
    "security.txt","humans.txt", "ads.txt", "favicon.ico","apple-touch-icon.png",
    "manifest.json", "service-worker.js", "ws", "graphql", "rpc", "json", "xml",
    "csv", "pdf", "zip", "tar", "gz", "rar", "7z", "exe", "dmg", "app", "iso",
    "bin", "sh", "bat", "ps1", "py", "rb", "php", "java", "go", "c", "cpp",
    "cs", "swift", "kt", "dart", "rs", "lua", "pl", "sql","env", "yml", "toml",
    "ini", "cfg", "conf", "pem", "crt", "key", "cer", "p12", "pfx", "jks",
    "htpasswd", "htaccess", "web.config"
]
# Test new/regressions
VALID_PATHS2 = [
    "index.html", "login","logout","register", "profile", "settings", "api", "users",
    "products", "orders", "cart", "checkout", "search", "faq", "about", "contact",
    "support", "blog", "news", "docs", "help", "status", "download", "upload", "static",
    "assets", "images","css", "js", "fonts", "media", "videos", "audio", "data", "backup", "db",
    "test", "debug", "info", "metrics", "health", "version","robots.txt", "sitemap.xml",
    "security.txt", "humans.txt", "ads.txt", "favicon.ico", "apple-touch-icon.png",
    "manifest.json", "service-worker.js", "ws", "graphql", "rpc", "json", "xml",
    "csv", "pdf", "zip", "tar", "toml", "ini", "cfg", "conf", "pem", "crt", "key",
    "cer", "p12", "pfx", "jks", "htpasswd", "htaccess",
    "NEW1", "NEW2", "NEW3","NEW4","NEW5",
]
VALID_PATHS3=[
    "admin", "config", "logs", "dashboard", "home", "index.html", "login", "logout",
    "register", "profile", "settings", "api", "users", "products", "orders", "cart",
    "checkout", "search", "faq", "about","contact", "support", "blog", "news",
    "docs", "help", "status", "download", "upload", "static", "assets", "images",
    "css", "js", "fonts", "media"
]
VALID_PATHS4=[
    "admin", "config","logs", "dashboard", "home", "index.html", "login", "logout",
    "register", "profile", "settings", "api", "users","products", "orders", "cart",
    "checkout","search", "faq", "about","contact", "support", "blog", "news",
    "docs", "help", "status", "download", "upload", "static", "assets", "images",
    "NEW1", "NEW2", "NEW3","NEW4","NEW5" # new
]

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        path = self.path.strip("/")
        display_path = path or ""
        if not path or path in VALID_PATHS4: # feel free to switch to VALID_PATHS[1,2,3,4]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body><h1>This is /{display_path}</h1></body></html>".encode("utf-8"))
        else:
            self.send_error(404, "File Not Found: %s" % self.path)

def main():
    with socketserver.TCPServer(("", PORT), MyHttpRequestHandler) as httpd:
        print(f"Serving at port {PORT}")
        print(f"You can test with http://localhost:{PORT}/<path>")
        print(f"Valid paths include: /admin, /config, /logs, etc.")
        httpd.serve_forever()

if __name__ == "__main__":
    main()
