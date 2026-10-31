"""Run with: python -m kubeshield"""

import uvicorn

from kubeshield.main import create_app

if __name__ == "__main__":
    uvicorn.run(create_app(), host="0.0.0.0", port=8000, proxy_headers=False)  # noqa: S104
