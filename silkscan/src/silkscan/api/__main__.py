"""Run with: python -m silkscan.api --config configs/api.yaml."""
from __future__ import annotations

import argparse
import logging
import os


def main():
    parser = argparse.ArgumentParser(description="silkscan REST + SSE service")
    parser.add_argument("--config", default="configs/api.yaml")
    parser.add_argument("--host", help="override the configured host (e.g. 0.0.0.0 in a container)")
    parser.add_argument("--port", type=int, help="override the configured port")
    args = parser.parse_args()
    # Each process owns its model; avoid CPU oversubscription unless explicitly configured.
    for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
        os.environ.setdefault(name, "1")
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    # Disable library logs that can contain untrusted URLs, multipart data or parser text.
    for name in ("httpx", "httpcore", "python_multipart"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    import uvicorn
    from silkscan.api.app import create_app
    from silkscan.api.config import load_api_config

    config = load_api_config(args.config)
    if args.host is not None:
        config.host = args.host
    if args.port is not None:
        config.port = args.port
    uvicorn.run(create_app(config), host=config.host, port=config.port, workers=1,
                loop="asyncio", http="h11", access_log=False, proxy_headers=False)


if __name__ == "__main__":
    main()
