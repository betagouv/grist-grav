from starlette.applications import Starlette

from starlette.responses import JSONResponse
from starlette.routing import Route


async def endpoint(request):
    print(f"got forwarded request for {request.path_params['path']}")
    return JSONResponse({})


app = Starlette(routes=[Route("/{path:path}", endpoint,methods=["POST"])])
