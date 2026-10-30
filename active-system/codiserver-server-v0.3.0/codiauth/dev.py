"""Explicit loopback development launcher. Never bind to 0.0.0.0 or public ports."""
from wsgiref.simple_server import make_server, WSGIRequestHandler
from pathlib import Path
import argparse
from .service import Config,Service
class Quiet(WSGIRequestHandler):
    def log_message(self,*args):pass

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--web-root',type=Path,required=True,help='Path to the web ZIP public/ directory')
    p.add_argument('--state-dir',type=Path,default=Path('var'))
    p.add_argument('--port',type=int,default=8098)
    args=p.parse_args();origin=f'http://127.0.0.1:{args.port}'
    app=Service(Config(args.state_dir,args.web_root,origin=origin))
    with make_server('127.0.0.1',args.port,app,handler_class=Quiet) as server:
        print(f'LOCAL TEST AUTHORITY ONLY: {origin}/',flush=True)
        print('No public deployment, peer relay, or host-files endpoint is enabled.',flush=True)
        try:server.serve_forever()
        except KeyboardInterrupt:pass
if __name__=='__main__':main()
