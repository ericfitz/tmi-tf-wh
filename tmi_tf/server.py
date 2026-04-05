"""FastAPI server with webhook, health, and status endpoints."""

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Request  # ty:ignore[unresolved-import]
from fastapi.responses import JSONResponse, Response  # ty:ignore[unresolved-import]

from tmi_tf.config import get_config
from tmi_tf.job import Job
from tmi_tf.providers import QueueProvider, get_queue_provider
from tmi_tf.webhook_handler import (
    extract_job_id,
    handle_challenge,
    parse_webhook_payload,
    validate_subscription_id,
    verify_hmac_signature,
)
from tmi_tf.worker import WorkerPool

logger = logging.getLogger(__name__)

# Module-level globals, set during lifespan
queue_client: Optional[QueueProvider] = None
worker_pool: Optional[WorkerPool] = None
_worker_task: Optional[asyncio.Task] = None  # type: ignore[type-arg]


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    """Startup: load vault secrets, init queue client, start worker pool.
    Shutdown: stop worker pool.
    """
    global queue_client, worker_pool, _worker_task

    # Configure structured JSON logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    config = get_config()

    # Load secrets via configured provider
    from tmi_tf.providers import VAULT_SECRET_MAP, get_secret_provider

    provider = get_secret_provider(config)
    provider.load_secrets(VAULT_SECRET_MAP)

    if config.secret_provider != "none":
        # Reset config singleton so it re-reads env vars with provider secrets
        import tmi_tf.config

        tmi_tf.config._config = None
        config = get_config()

    # Initialize queue client
    if config.queue_provider != "none":
        queue_client = get_queue_provider(config)
        logger.info("Queue provider initialized: %s", config.queue_provider)

    # Start worker pool
    if queue_client is not None:
        worker_pool = WorkerPool(queue_client, config)
        _worker_task = asyncio.create_task(worker_pool.start())
        logger.info("Worker pool started")

    yield

    # Shutdown
    if worker_pool is not None:
        await worker_pool.stop()
        logger.info("Worker pool stopped")
    if _worker_task is not None:
        _worker_task.cancel()
        try:
            await _worker_task
        except asyncio.CancelledError:
            pass


app = FastAPI(lifespan=lifespan)


@app.post("/webhook")
async def webhook(request: Request) -> Response:
    """Handle incoming webhook requests."""
    config = get_config()

    # Read raw body
    raw_body = await request.body()

    # Log headers and payload at INFO
    headers = dict(request.headers)
    logger.info("Webhook received: headers=%s payload_size=%d", headers, len(raw_body))

    # Validate subscription ID if configured
    subscription_id = request.headers.get("x-subscription-id")
    if not validate_subscription_id(subscription_id, config.webhook_subscription_id):
        logger.warning("Subscription ID mismatch: %s", subscription_id)
        return Response(
            status_code=401,
            content=json.dumps({"error": "Invalid subscription ID"}),
            media_type="application/json",
        )

    # Verify HMAC signature
    signature = request.headers.get("x-webhook-signature", "")
    if not config.webhook_secret or not verify_hmac_signature(
        raw_body, signature, config.webhook_secret
    ):
        logger.warning("HMAC signature verification failed")
        return Response(
            status_code=401,
            content=json.dumps({"error": "Invalid signature"}),
            media_type="application/json",
        )

    # Parse JSON
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON payload: %s", e)
        return Response(
            status_code=400,
            content=json.dumps({"error": "Invalid JSON"}),
            media_type="application/json",
        )

    # Handle challenge
    challenge_response = handle_challenge(payload)
    if challenge_response is not None:
        return JSONResponse(content=challenge_response)

    # Extract job ID
    invocation_id = request.headers.get("x-invocation-id")
    delivery_id = request.headers.get("x-delivery-id")
    try:
        job_id = extract_job_id(invocation_id, delivery_id)
    except ValueError:
        logger.warning("Missing job ID headers")
        return Response(
            status_code=403,
            content=json.dumps({"error": "Missing job ID headers"}),
            media_type="application/json",
        )

    # Parse payload
    try:
        parsed = parse_webhook_payload(payload)
    except ValueError as e:
        logger.error("Invalid webhook payload: %s", e)
        return Response(
            status_code=400,
            content=json.dumps({"error": str(e)}),
            media_type="application/json",
        )

    # Build job and enqueue
    job = Job(
        job_id=job_id,
        threat_model_id=parsed["threat_model_id"],
        event_type=parsed.get("event_type", "unknown"),
        enqueued_at=datetime.now(timezone.utc),
        repo_id=parsed.get("repo_id"),
        callback_url=parsed.get("callback_url"),
        invocation_id=parsed.get("invocation_id"),
    )

    if queue_client is not None:
        queue_client.publish(job.to_queue_message())
        logger.info("Job enqueued: job_id=%s", job_id)
    else:
        logger.warning(
            "No queue client configured; job not enqueued: job_id=%s", job_id
        )

    return JSONResponse(content={"status": "accepted", "job_id": job_id})


@app.get("/health")
async def health() -> JSONResponse:
    """Health check endpoint."""
    return JSONResponse(
        content={
            "status": "healthy",
            "queue_connected": queue_client is not None,
            "worker_pool_running": worker_pool is not None,
        }
    )


@app.get("/status")
async def status() -> JSONResponse:
    """Worker pool status endpoint."""
    if worker_pool is not None:
        pool_status = worker_pool.get_status()
    else:
        pool_status = {"active_jobs": {}, "active_count": 0, "max_concurrent": 0}
    return JSONResponse(content=pool_status)
