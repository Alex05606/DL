from __future__ import annotations

import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from phishguardz.api import app  # noqa: E402


def ensure_frontend_build() -> None:
    source_files = [
        path
        for path in (PROJECT_ROOT / "web").rglob("*")
        if path.is_file()
    ]
    source_files.extend(
        [PROJECT_ROOT / "package.json", PROJECT_ROOT / "package-lock.json", PROJECT_ROOT / "vite.config.js"]
    )
    output_dir = PROJECT_ROOT / "phishguardz" / "static"
    output_files = [path for path in output_dir.rglob("*") if path.is_file()]

    newest_source = max((path.stat().st_mtime for path in source_files), default=0)
    newest_output = max((path.stat().st_mtime for path in output_files), default=0)
    if output_dir.joinpath("index.html").is_file() and newest_output >= newest_source:
        return
    if output_dir.joinpath("index.html").is_file() and not (
        PROJECT_ROOT / "node_modules"
    ).is_dir():
        return

    print("Building the React frontend...")
    if not (PROJECT_ROOT / "node_modules").is_dir():
        raise RuntimeError(
            "Frontend dependencies are not installed. Run `npm ci` in the project folder, "
            "then run `python main.py` again."
        )
    import subprocess

    subprocess.run(["npm", "run", "build"], cwd=PROJECT_ROOT, check=True)


def port_is_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind((host, port))
        except OSError:
            return False
    return True


def select_port(host: str) -> int:
    configured_port = os.environ.get("PHISHGUARD_PORT")
    if configured_port:
        try:
            port = int(configured_port)
        except ValueError as exc:
            raise RuntimeError("PHISHGUARD_PORT must be a valid port number.") from exc
        if not 1 <= port <= 65535:
            raise RuntimeError("PHISHGUARD_PORT must be between 1 and 65535.")
        if not port_is_available(host, port):
            raise RuntimeError(f"Port {port} is already in use.")
        return port

    for port in range(8000, 8011):
        if port_is_available(host, port):
            return port
    raise RuntimeError("No available port found between 8000 and 8010.")


def main() -> None:
    model_path = Path(
        os.environ.get(
            "PHISHGUARD_MODEL",
            PROJECT_ROOT / "models" / "phishguardz.joblib",
        )
    )
    if not model_path.is_file():
        raise FileNotFoundError(
            f"Trained model not found: {model_path}. Train it first with "
            "`python -m phishguardz.fetch_data`, `python -m phishguardz.prepare_data`, "
            "then `python -m phishguardz.train`."
        )

    ensure_frontend_build()

    host = os.environ.get("PHISHGUARD_HOST", "127.0.0.1")
    port = select_port(host)
    url = f"http://{host}:{port}"
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=host,
            port=port,
            log_level="info",
        )
    )
    server_thread = threading.Thread(target=server.run, name="phishguard-server")
    server_thread.start()

    while server_thread.is_alive() and not server.started:
        time.sleep(0.1)
    if not server.started:
        server_thread.join()
        raise RuntimeError("PhishGuard-Z server failed to start; check the server log above.")

    print(f"PhishGuard-Z is ready at {url}")
    if os.environ.get("PHISHGUARD_NO_BROWSER") != "1":
        webbrowser.open(url, new=2)

    try:
        server_thread.join()
    except KeyboardInterrupt:
        print("\nStopping PhishGuard-Z...")
        server.should_exit = True
        server_thread.join()


if __name__ == "__main__":
    main()
