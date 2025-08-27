import logging

from starlette.responses import JSONResponse
from starlette.routing import Route

from .av_scanner.base import AVScanResult, BaseAVScanner
from .forwarder.base import BaseForwarder

logger = logging.getLogger(__name__)


async def endpoint_scan(request, av_scanner: BaseAVScanner, forwarder: BaseForwarder):
    if request.method == "POST":
        # awaiting body() before form() ensures we can still read the body later on
        # but maybe this has resource usage implications, we may need to manually save the body in a spooled temp file
        await request.body()
        async with request.form() as form:
            upload = form.get("upload")
            if upload is None:
                logger.info("failed to extract upload from request")
                return JSONResponse({"error": "failed upload"}, status_code=400)
            result = await av_scanner.process(upload.file)
            if result == AVScanResult.SAFE:
                logger.info("scanner determined that the file is safe, forwarding")
                return await forwarder.forward(request)
            elif result == AVScanResult.MALWARE:
                logger.info("scanner determined that the file is malware, blocking")
                return JSONResponse({"error": "malware file"}, status_code=400)
            else:
                logger.info("failed to complete AV test")
                return JSONResponse({"error": "failed AV test"}, status_code=502)
    else:
        return await forwarder.forward(request)


def configure_routes(
    av_scanner: BaseAVScanner,
    fw_doc_wk: BaseForwarder,
    fw_home_wk: BaseForwarder,
):
    async def scan_forward_doc_worker(request):
        return await endpoint_scan(request, av_scanner, fw_doc_wk)

    async def scan_forward_home_worker(request):
        return await endpoint_scan(request, av_scanner, fw_home_wk)

    doc_wk_methods = ["POST"]
    home_wk_methods = ["POST", "GET", "OPTIONS"]

    routes = [
        Route(
            "/dw/{dw}/v/{v}/o/{o}/uploads",
            scan_forward_doc_worker,
            methods=doc_wk_methods,
        ),
        Route(
            "/dw/{dw}/v/{v}/uploads",
            scan_forward_doc_worker,
            methods=doc_wk_methods,
        ),
        Route(
            "/o/{org}/api/docs/{docid}/attachments",
            scan_forward_home_worker,
            methods=home_wk_methods,
        ),
        Route(
            "/api/docs/{docid}/attachments",
            scan_forward_home_worker,
            methods=home_wk_methods,
        ),
        Route(
            "/o/{org}/api/s/{share}/attachments",
            scan_forward_home_worker,
            methods=home_wk_methods,
        ),
    ]

    return routes
