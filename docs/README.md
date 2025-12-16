# Documentation Site

This directory contains the documentation site for the AWS MFA Incident Response Simulator.

## Deployment

### GitHub Pages

To deploy this documentation site to GitHub Pages:

1. Ensure `docs/index.html` exists (it does)
2. Go to your repository Settings → Pages
3. Set source to "Deploy from a branch"
4. Select branch: `main` (or your default branch)
5. Select folder: `/docs`
6. Click Save

The site will be available at: `https://<username>.github.io/aws-mfa-incident-simulator/`

### Local Preview

To preview locally, simply open `docs/index.html` in a web browser, or use a local server:

```bash
# Python 3
python -m http.server 8000 --directory docs

# Node.js (http-server)
npx http-server docs -p 8000

# Then visit http://localhost:8000
```

## Content

The documentation page (`index.html`) is a standalone HTML file with embedded CSS. It highlights:

- Detection logic and signal patterns
- Incident response workflows
- Design philosophy (assisted remediation, blast radius control)
- What the system does and does not do
- Links to repository resources

This is a **documentation page**, not an interactive demo. It showcases operational thinking, detection patterns, and runbooks—not live execution.

