# TrustLens LK — Member 4 Demo Instructions
**Topic:** Safe Scanner and Security Controls (SSRF Containment)

During the final competition demonstration, you need to prove that our backend is resilient to Server-Side Request Forgery (SSRF) and cannot be tricked into scanning internal network resources.

## Demo Script

**1. Context Setup**
*   **Speaker (Member 4):** *"As a security tool, TrustLens must fetch URLs submitted by users. If a malicious user submits an internal network address instead of a public URL, it could lead to Server-Side Request Forgery, exposing our cloud metadata or internal databases. Here is how we prevent that."*

**2. The "Malicious" Submission**
*   Open the TrustLens web interface.
*   In the URL submission box, enter a known internal address:
    *   `http://169.254.169.254/latest/meta-data/` (Standard AWS/Cloud metadata IP)
    *   Alternatively: `http://localhost:5173` or `http://127.0.0.1`

**3. Execution & Explanation**
*   Click **"Scan URL"**.
*   **Speaker:** *"I am submitting an AWS cloud metadata IP. When the backend receives this, the Playwright scanner performs a DNS resolution and intercepts the actual IP address before making the connection."*

**4. The Result**
*   The UI should display a safe failure state (e.g., "Scan Failed" or "Scanner Error: net::ERR_BLOCKED_BY_CLIENT" or a 500 error related to blocklists).
*   **Speaker:** *"As you can see, the scanner immediately blocked the connection. Our DNS rebinding protection (`isPrivateIp` check) detected a private IP range and aborted the fetch at the network layer inside the sandboxed Chromium worker. The host remains secure."*

**5. Show the Logs (Optional but Recommended)**
*   Open the terminal running the `services/scanner` worker.
*   Point to the log line: `[Scanner] Blocked request to private IP 169.254.169.254 for 169.254.169.254`
*   **Speaker:** *"Here is the audit log proving the request was intercepted and denied before leaving the container."*
