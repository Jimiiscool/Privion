import argparse, os
import uvicorn
if __name__=='__main__':
    from .app import create_app
    parser=argparse.ArgumentParser()
    parser.add_argument('--host',default=os.getenv('AVON_HOST','127.0.0.1'))
    parser.add_argument('--port',type=int,default=int(os.getenv('AVON_PORT','8000')))
    args,_=parser.parse_known_args()
    uvicorn.run(create_app(),host=args.host,port=args.port,proxy_headers=False,access_log=False)
