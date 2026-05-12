from starlette.applications import Starlette

from starlette.responses import JSONResponse
from starlette.routing import Route

iteration = 0


async def results(request):
    print(f"got result request for {request.path_params['path']}")
    global iteration
    iteration += 1
    if iteration % 2 == 1:
        # return waiting
        return JSONResponse({}, status_code=404)
    else:
        # return result
        return JSONResponse({"done": True, "is_malware": False})

async def submit(request):
    print(f"got submit request for {request.path_params['path']}")
    return JSONResponse({})

app = Starlette(
    routes=[
        Route(
            "/results/{path:path}",
            results,
            methods=["GET"],
        ),
        Route(
            "/submit/{path:path}",
submit,methods=["POST"]
        ),
    ]
)
