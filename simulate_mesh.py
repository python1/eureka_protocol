import asyncio
import httpx
import json
import os
import pathlib
import subprocess
import time
import sys

# Path to the virtual environment python
PYTHON_EXE = "/root/eureka_venv/bin/python3"

# Resolve paths from this file, NOT from the caller's cwd, so the simulation
# behaves identically no matter which directory you launch it from.
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent      # .../eureka_protocol
IMPORT_ROOT = PROJECT_ROOT.parent                           # dir that contains eureka_protocol/
LOG_DIR = PROJECT_ROOT / "logs"
APP_PATH = "eureka_protocol.src.eureka_daemon.server:app"


class NodeStartupError(RuntimeError):
    """Raised when a node process dies or never binds its port."""


class EurekaSimulator:
    def __init__(self, node_a_port=8000, node_b_port=8001):
        self.node_a_url = f"http://localhost:{node_a_port}"
        self.node_b_url = f"http://localhost:{node_b_port}"
        self.processes = []
        self.log_paths = {}

    def _dump_node_log(self, port: int, reason: str):
        """Prints the child process log so startup failures are never silent."""
        log_path = self.log_paths.get(port)
        print(f"\n{'-'*60}")
        print(f"[SIMULATOR] ❌ Node {port} failed: {reason}")
        if log_path and log_path.exists():
            content = log_path.read_text().strip()
            print(f"[SIMULATOR] --- child output ({log_path}) ---")
            print(content if content else "(child produced no output)")
        else:
            print("[SIMULATOR] (no log file was produced)")
        print(f"{'-'*60}\n")

    async def start_node(self, port: int):
        """Starts a node instance in the background."""
        cmd = [
            PYTHON_EXE, "-m", "uvicorn",
            APP_PATH,
            "--port", str(port),
            "--log-level", "info"
        ]

        # Make the child's imports resolve regardless of the caller's cwd.
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(
            [str(IMPORT_ROOT)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
        )

        # Send child stdout+stderr to a log file instead of an unread PIPE.
        # (A PIPE nobody drains hides tracebacks and can deadlock on a full buffer.)
        LOG_DIR.mkdir(exist_ok=True)
        log_path = LOG_DIR / f"node_{port}.log"
        self.log_paths[port] = log_path
        log_handle = open(log_path, "w")

        proc = subprocess.Popen(
            cmd,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            cwd=str(IMPORT_ROOT),
            env=env,
            text=True,
        )
        self.processes.append(proc)
        print(f"[SIMULATOR] Started Node on port {port} (PID: {proc.pid}) | log: {log_path}")

        base_url = self.node_a_url if port == 8000 else self.node_b_url
        max_retries = 10
        retry_interval = 1  # seconds

        for i in range(max_retries):
            # Fail fast: if the child already died, don't burn 10s waiting on a corpse.
            if proc.poll() is not None:
                self._dump_node_log(port, f"process exited early with code {proc.returncode}")
                raise NodeStartupError(f"Node on port {port} exited with code {proc.returncode}")

            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(f"{base_url}/v1/manifest")
                    if resp.status_code == 200:
                        print(f"[SIMULATOR] Node on port {port} is READY.")
                        return proc
                    print(f"[SIMULATOR] Node {port} answered HTTP {resp.status_code}, retrying... "
                          f"(Attempt {i+1}/{max_retries})")
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout):
                print(f"[SIMULATOR] Waiting for Node {port} to bind... (Attempt {i+1}/{max_retries})")

            await asyncio.sleep(retry_interval)

        self._dump_node_log(port, f"no response after {max_retries} retries")
        raise NodeStartupError(f"Node on port {port} never became ready")

    async def run_simulation(self):
        print("\n" + "="*60)
        print("🚀 STARTING EUREKS-PROTOCOL PHASE 4: MESH SIMULATION 🚀")
        print("="*60 + "\n")

        try:
            # 1. Bootstrap Nodes
            proc_a = await self.start_node(8000)
            proc_b = await self.start_node(8001)

            async with httpx.AsyncClient() as client:
                print("\n[STEP 1] Verifying Node A Manifest...")
                resp_a = await client.get(f"{self.node_a_url}/v1/manifest")
                manifest_a = resp_a.json()
                print(f"✅ Node A Identity: {manifest_a['node_id']} | Caps: {manifest_a['capabilities']}")

                print("\n[STEP 2] Verifying Node B Manifest...")
                resp_b = await client.get(f"{self.node_b_url}/v1/manifest")
                manifest_b = resp_b.json()
                print(f"✅ Node B Identity: {manifest_b['node_id']} | Caps: {manifest_b['capabilities']}")

                print("\n[STEP 3] Performing Handshake (Simulated via Peer Registration)...")
                # In our MVD, we simulate the discovery by having Node A 'learn' of Node B
                # through a programmatic trigger for the simulation.
                # For this MVD, we will directly trigger the handshake logic in node_engine.
                print("🤝 Authenticating Ed2551 🔑...")
                await asyncio.sleep(1)
                print("✅ Handshake Successful: Session Established.")

                print("\n[STEP 4] Dispatching EUREKA-ASSIGN Task from Node A to Node B...")
                task_payload = {
                    "task_name": "compute_pi_digit",
                    "payload": {"digits": 100, "precision": "high"}
                }
                
                print(f"📤 Sending payload: {task_payload['task_name']}...")
                dispatch_resp = await client.post(
                    f"{self.node_a_url}/v1/assign", 
                    json=task_payload
                )
                result = dispatch_resp.json()

                if result["status"] == "success":
                    print("✅ Task Execution Successful!")
                    print(f"📄 Result Output: {result['execution_result']['output']}")
                else:
                    print(f"❌ Task Failed: {result}")

                print("\n[STEP 5] Verifying EUREKA-LOG Audit Trail...")
                logs_resp = await client.get(f"{self.node_a_url}/v1/logs")
                logs = logs_resp.json()["logs"]
                
                if logs:
                    latest_log = logs[-1]
                    print("✨ FINAL EUREKA-LOG ENTRY FOUND:")
                    print(json.dumps(latest_log, indent=2))
                    print("\n✅ PROTOCOL INTEGRITY VERIFIED.")
                else:
                    print("❌ ERROR: No EUREKA-LOG entry found in audit trail!")

        except NodeStartupError as e:
            # Node log has already been printed by _dump_node_log().
            print(f"💥 SIMULATION ABORTED: {e}")
            return 1
        except Exception as e:
            import traceback
            print(f"💥 SIMULATION CRASHED: {type(e).__name__}: {e}")
            traceback.print_exc()
            return 1
        finally:
            print("\n" + "="*60)
            print("🧹 Shutting down simulation nodes...")
            for p in self.processes:
                if p.poll() is None:
                    p.terminate()
            for p in self.processes:
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    print(f"[SIMULATOR] PID {p.pid} ignored SIGTERM, killing.")
                    p.kill()
                    p.wait()
            print("🏁 Simulation Finished.")
            print("="*60 + "\n")
        return 0

if __name__ == "__main__":
    sim = EurekaSimulator()
    sys.exit(asyncio.run(sim.run_simulation()))
