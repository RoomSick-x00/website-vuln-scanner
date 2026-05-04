import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

from .base import BaseScanner, Finding

class XSSScanner(BaseScanner):
    name = "xss"
    display_name = "XSS (Cross-Site Scripting)"
    tier = "intrusive"

    PROBE = "xsstest<b>probe123</b>"
    PROBE_MARKER = "xsstest<b>probe123</b>"
    
    def scan(self, target: str, timeout: int = 10) -> list[Finding]:
        findings = []

        try:
            response = requests.get(
                target,
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)"},
                allow_redirects=True,
            )
        except requests.RequestException as e:
            return [self._finding(
                issue="XSS scan failed — could not reach target",
                evidence=str(e),
                severity="medium",
                remediation="Check that the target URL is reachable.",
                score_penalty=0,
            )]

        if self._requires_login(response):
            return [self._finding(
                issue="XSS scan skipped — page requires authentication",
                evidence="Login form detected or access denied",
                severity="info",
                remediation="XSS scanning of authenticated pages requires manual testing.",
                score_penalty=0,
            )]

        soup = BeautifulSoup(response.text, "html.parser")

        findings.extend(self._check_url_parameters(target, response, timeout))
        findings.extend(self._check_forms(target, soup, timeout))

        if not findings:
            findings.append(self._finding(
                issue="No XSS vulnerabilities detected",
                evidence="No reflected input found in URL parameters or forms",
                severity="info",
            ))

        return findings
    
    def _requires_login(self, response: requests.Response) -> bool:
        """
        Detect if the page is a login wall or access denied page.
        Checks both HTTP status codes and common login page indicators in HTML.
        """
        if response.status_code in (401, 403):
            return True

        # Check for common login page indicators in HTML
        login_indicators = [
            'type="password"',
            "type='password'",
            "login",
            "sign in",
            "signin",
        ]

        page_lower = response.text.lower()
        password_field = 'type="password"' in page_lower or "type='password'" in page_lower

        # Only flag as login page if there's actually a password field
        # Checking just for "login" text would cause too many false positives
        return password_field
    
    def _check_url_parameters(self, target: str, original_response: requests.Response, timeout: int) -> list[Finding]:
        """
        Probe each URL parameter with the XSS payload and check
        if it reflects unencoded in the response.
        """
        findings = []

        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return findings  # No URL parameters to test

        for param_name in params:
            # Build a copy of params with probe injected into this one
            probed_params = dict(params)
            probed_params[param_name] = [self.PROBE]

            # Rebuild the full URL with the probe
            new_query = urlencode(probed_params, doseq=True)
            probe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

            try:
                response = requests.get(
                    probe_url,
                    timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)"},
                    allow_redirects=True,
                )

                if self.PROBE_MARKER in response.text:
                    findings.append(self._finding(
                        issue="Reflected XSS vulnerability detected in URL parameter",
                        evidence=f"Parameter '{param_name}' reflects unencoded input. Probe URL: {probe_url}",
                        severity="high",
                        remediation=(
                            f"Sanitize the '{param_name}' parameter before rendering it in HTML. "
                            "Use output encoding — convert < to &lt; and > to &gt;. "
                            "In Python/Jinja2: use {{ value | e }}. In PHP: use htmlspecialchars()."
                        ),
                        score_penalty=35,
                    ))
                else:
                    findings.append(self._finding(
                        issue=f"URL parameter '{param_name}' does not reflect input",
                        evidence=f"Probe not found in response for parameter '{param_name}'",
                        severity="info",
                    ))

            except requests.RequestException:
                continue  # Skip this parameter if request fails, try the next one

        return findings
    
    def _check_forms(self, target: str, soup: BeautifulSoup, timeout: int) -> list[Finding]:
        """
        Find all forms on the page, inject the XSS probe into each
        text-like input field, submit the form, and check if the
        probe reflects unencoded in the response.
        """
        findings = []
        forms = soup.find_all("form")

        if not forms:
            return findings  # No forms on this page

        for form in forms:
            # ── Step A: Get form submission details ──────────────────────────
            action = form.get("action", "")
            method = form.get("method", "get").lower()

            # Resolve relative URLs — e.g. /submit → https://example.com/submit
            form_url = urljoin(target, action) if action else target

            # Step B: Build the base data dict from all inputs ─────────────
            # Fill every field with a safe default so the server doesn't
            # reject the request due to missing required fields
            data = {}
            inputs = form.find_all(["input", "textarea", "select"])

            for inp in inputs:
                inp_type = inp.get("type", "text").lower()
                inp_name = inp.get("name")

                if not inp_name:
                    continue  # Unnamed inputs are never submitted

                # Skip inputs that shouldn't be touched
                if inp_type in ("submit", "button", "image", "reset"):
                    continue

                if inp_type == "hidden":
                    # Keep hidden fields as-is — likely CSRF tokens
                    data[inp_name] = inp.get("value", "")
                elif inp_type == "checkbox":
                    data[inp_name] = "on"
                elif inp_type == "radio":
                    data[inp_name] = inp.get("value", "on")
                elif inp_type == "email":
                    data[inp_name] = "test@example.com"
                elif inp_type == "number":
                    data[inp_name] = "1"
                else:
                    # text, textarea, search, url, tel etc.
                    data[inp_name] = "test"

            # ── Step C: Probe each text-like field individually ───────────────
            for inp in inputs:
                inp_type = inp.get("type", "text").lower()
                inp_name = inp.get("name")

                if not inp_name:
                    continue

                # Only probe fields where a user can type free text
                if inp_type not in ("text", "search", "url", "tel", "textarea", ""):
                    continue

                # Inject probe into this field, keep others as safe defaults
                probed_data = dict(data)
                probed_data[inp_name] = self.PROBE

                try:
                    if method == "post":
                        response = requests.post(
                            form_url,
                            data=probed_data,
                            timeout=timeout,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)"},
                            allow_redirects=True,
                        )
                    else:
                        response = requests.get(
                            form_url,
                            params=probed_data,
                            timeout=timeout,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)"},
                            allow_redirects=True,
                        )

                    if self.PROBE_MARKER in response.text:
                        findings.append(self._finding(
                            issue="Reflected XSS vulnerability detected in form field",
                            evidence=(
                                f"Form field '{inp_name}' reflects unencoded input. "
                                f"Form action: {form_url} Method: {method.upper()}"
                            ),
                            severity="high",
                            remediation=(
                                f"Sanitize the '{inp_name}' field before rendering in HTML. "
                                "Use output encoding — convert < to &lt; and > to &gt;. "
                                "In Python/Jinja2: use {{ value | e }}. "
                                "In PHP: use htmlspecialchars(). "
                                "Consider adding a Content-Security-Policy header as a second layer of defence."
                            ),
                            score_penalty=40,
                        ))

                except requests.RequestException:
                    continue  # Skip this field, try the next one

        return findings