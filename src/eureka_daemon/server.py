import asyncio
import uvicorn
import sys
from .api import app

async def main():
    # Get port from command line or default to 8000
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print(f"Starting Eureka Daemon API on port {port}...")
    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
