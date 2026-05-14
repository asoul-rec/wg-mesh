import asyncio
import logging
from . import mesh
import argparse

parser = argparse.ArgumentParser(description="P2P WG Mesh Controller")
parser.add_argument("--config", type=str, default="config.json", help="Path to config file")
parser.add_argument("--dry-run", action="store_true", help="Run without executing WG commands")
parser.add_argument('-v', '--verbose', action='count', default=0, help="increase logging verbosity")
parser.add_argument('--metrics', type=str, default='', metavar='ADDR:PORT',
                    help="Prometheus metrics endpoint (e.g. 127.0.0.1:9586); empty to disable")
args = parser.parse_args()

logging_level = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG}.get(args.verbose, logging.DEBUG)
logging.basicConfig(level=logging_level, format='%(asctime)s [%(levelname).1s] [%(name)s] %(message)s')

if __name__ == "__main__":
    metrics_addr, metrics_port = '', 0
    if args.metrics:
        try:
            _host, _port = args.metrics.rsplit(':', 1)
            metrics_addr, metrics_port = _host, int(_port)
        except ValueError:
            parser.error("--metrics must be in ADDR:PORT format, e.g. 127.0.0.1:9586")
    asyncio.run(mesh.MeshController(args.config, args.dry_run, metrics_addr=metrics_addr, metrics_port=metrics_port).run())
