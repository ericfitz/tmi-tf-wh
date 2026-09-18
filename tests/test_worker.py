"""Tests for the async worker pool."""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import ANY, MagicMock, patch

from tmi_tf.analyzer import AnalysisResult, FanoutTarget
from tmi_tf.config import Config
from tmi_tf.invocation import InvocationState
from tmi_tf.job import Job
from tmi_tf.providers.memory import MemoryQueueProvider
from tmi_tf.tmi_client_wrapper import STATUS_NOTE_NAME
from tmi_tf.worker import WorkerPool, _is_message_expired


class TestMessageExpiry:
    def test_fresh_message_not_expired(self):
        enqueued = datetime.now(timezone.utc) - timedelta(hours=1)
        assert _is_message_expired(enqueued.isoformat(), max_age_hours=24) is False

    def test_old_message_expired(self):
        enqueued = datetime.now(timezone.utc) - timedelta(hours=25)
        assert _is_message_expired(enqueued.isoformat(), max_age_hours=24) is True

    def test_exactly_at_boundary(self):
        enqueued = datetime.now(timezone.utc) - timedelta(hours=24)
        assert _is_message_expired(enqueued.isoformat(), max_age_hours=24) is True


class TestWorkerPool:
    def test_init(self):
        pool = WorkerPool(
            queue_client=MagicMock(),
            config=MagicMock(
                max_concurrent_jobs=3, job_timeout=3600, max_message_age_hours=24
            ),
        )
        assert pool.max_concurrent == 3

    def test_get_status_empty(self):
        pool = WorkerPool(
            queue_client=MagicMock(),
            config=MagicMock(
                max_concurrent_jobs=3, job_timeout=3600, max_message_age_hours=24
            ),
        )
        status = pool.get_status()
        assert status["active_count"] == 0
        assert status["max_concurrent"] == 3

    def test_consume_uses_job_timeout_as_visibility(self):
        """Visibility must cover the whole job or SQS/OCI redeliver it mid-run."""
        import asyncio

        queue = MagicMock()
        queue.consume.return_value = []
        pool = WorkerPool(
            queue_client=queue,
            config=MagicMock(
                max_concurrent_jobs=3, job_timeout=1234, max_message_age_hours=24
            ),
        )
        asyncio.run(pool._poll_and_dispatch())
        queue.consume.assert_called_once_with(max_messages=3, visibility_timeout=1234)


def _pool():
    config = Config()
    config.webhook_secret = "s"
    queue = MemoryQueueProvider()
    return WorkerPool(queue, config), queue


def _job(**kw):
    defaults = {
        "job_id": "p1",
        "threat_model_id": "tm1",
        "event_type": "addon.invoked",
        "enqueued_at": datetime.now(timezone.utc),
        "callback_url": "https://cb",
    }
    defaults.update(kw)
    return Job(**defaults)


def _child(job_id, siblings, **kw):
    return _job(
        job_id=job_id,
        environment=job_id.split(":")[1],
        siblings=siblings,
        deadline=datetime.now(timezone.utc) + timedelta(hours=1),
        **kw,
    )


class TestFanout:
    def test_parent_enqueues_children_and_completes(self):
        pool, queue = _pool()
        queue.delete = MagicMock(wraps=queue.delete)
        targets = [
            FanoutTarget("r1", "u", "aws-public"),
            FanoutTarget("r1", "u", "gcp-public"),
        ]
        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.worker.resolve_fanout_targets", return_value=targets),
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
            patch("tmi_tf.worker.open_invocation") as open_inv,
            patch("tmi_tf.worker.mark_child") as mark,
        ):
            asyncio.run(
                pool._run_job(
                    _job(
                        scope="all",
                        invocation_id="inv1",
                        event_type="addon.invoked",
                        threat_model_id="tm1",
                    ),
                    receipt="rc",
                )
            )
        bodies = [m.body for m in queue.consume(max_messages=10)]
        assert sorted(b["environment"] for b in bodies) == ["aws-public", "gcp-public"]
        assert all(
            b["job_id"].startswith("p1:") and b["repo_id"] == "r1" for b in bodies
        )
        assert all(b["callback_url"] == "https://cb" for b in bodies)
        assert all(
            sorted(b["siblings"]) == ["p1:aws-public", "p1:gcp-public"] for b in bodies
        )
        assert all(b["deadline"] for b in bodies)
        assert all(b["invocation_id"] == "inv1" for b in bodies)
        assert all(b["event_type"] == "addon.invoked" for b in bodies)
        assert all(b["threat_model_id"] == "tm1" for b in bodies)
        cb_cls.return_value.send_status.assert_any_call(
            "in_progress", "enqueued 2 of 2 environment jobs"
        )
        queue.delete.assert_called_once_with("rc")
        open_inv.assert_called_once()
        args = open_inv.call_args.args
        assert args[1:3] == ("tm1", "p1")
        assert sorted(args[3]) == ["p1:aws-public", "p1:gcp-public"]
        mark.assert_not_called()

    def test_parent_publish_failure_continues_and_completes(self):
        pool, queue = _pool()
        targets = [
            FanoutTarget("r1", "u", "aws-public"),
            FanoutTarget("r1", "u", "gcp-public"),
        ]
        real_publish = queue.publish
        calls = {"n": 0}

        def flaky_publish(message):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("boom")
            return real_publish(message)

        queue.publish = MagicMock(side_effect=flaky_publish)
        tmi = MagicMock()
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=tmi),
            patch("tmi_tf.worker.resolve_fanout_targets", return_value=targets),
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
            patch("tmi_tf.worker.open_invocation") as open_inv,
            patch("tmi_tf.worker.mark_child") as mark,
        ):
            asyncio.run(pool._run_job(_job(scope="all"), receipt="rc"))
        bodies = [m.body for m in queue.consume(max_messages=10)]
        assert len(bodies) == 1
        assert bodies[0]["environment"] == "gcp-public"
        assert tmi.update_status_note.call_args.args[0] == "tm1"
        assert "aws-public" in tmi.update_status_note.call_args.args[1]
        cb_cls.return_value.send_status.assert_any_call(
            "in_progress", "enqueued 1 of 2 environment jobs"
        )
        open_inv.assert_called_once()
        mark.assert_any_call(ANY, "tm1", "p1:aws-public", "failed")

    def test_parent_with_no_targets_completes_without_enqueue(self):
        pool, queue = _pool()
        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.worker.resolve_fanout_targets", return_value=[]),
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
            patch("tmi_tf.worker.open_invocation") as open_inv,
            patch("tmi_tf.worker.mark_child"),
        ):
            asyncio.run(pool._run_job(_job(scope="zzz"), receipt="rc"))
        assert queue.consume(max_messages=10) == []
        cb_cls.return_value.send_status.assert_any_call(
            "completed", "no environments matched"
        )
        open_inv.assert_not_called()

    def test_child_runs_analysis_with_environment_and_note_name(self):
        pool, _ = _pool()
        tmi = MagicMock()
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=tmi),
            patch(
                "tmi_tf.worker.run_analysis", return_value=AnalysisResult(success=True)
            ) as ra,
            patch("tmi_tf.worker.AddonCallback"),
            patch(
                "tmi_tf.worker.mark_child",
                return_value=InvocationState("p1", True, None, {}),
            ),
        ):
            asyncio.run(
                pool._run_job(
                    _job(
                        job_id="p1:aws-public",
                        repo_id="r1",
                        environment="aws-public",
                        repo_name="o_r",
                    ),
                    receipt="rc",
                )
            )
        assert ra.call_args.kwargs["environment"] == "aws-public"
        assert ra.call_args.kwargs["repo_id"] == "r1"
        assert tmi.status_note_name == f"{STATUS_NOTE_NAME} - o_r - aws-public"

    def test_child_whole_repo_note_named_after_repo(self):
        pool, _ = _pool()
        tmi = MagicMock(status_note_name="Analysis Status")
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=tmi),
            patch(
                "tmi_tf.worker.run_analysis", return_value=AnalysisResult(success=True)
            ),
            patch("tmi_tf.worker.AddonCallback"),
            patch(
                "tmi_tf.worker.mark_child",
                return_value=InvocationState("p1", True, None, {}),
            ),
        ):
            asyncio.run(
                pool._run_job(_job(environment="", repo_name="o_r"), receipt="rc")
            )
        assert tmi.status_note_name == f"{STATUS_NOTE_NAME} - o_r"


class TestCompletion:
    def _run_child(self, pool, job, result_success=True, raise_exc=None):
        tmi = MagicMock()
        result = AnalysisResult(
            success=result_success, errors=["boom"] if not result_success else []
        )
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=tmi),
            patch(
                "tmi_tf.worker.run_analysis", return_value=result, side_effect=raise_exc
            ),
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
        ):
            asyncio.run(pool._run_job(job, receipt="rc"))
        return cb_cls.return_value

    def test_all_children_succeed_sends_completed_once(self):
        pool, _queue = _pool()
        sibs = ["p1:aws", "p1:gcp"]
        states = iter(
            [
                InvocationState("p1", True, None, {"p1:aws": "success"}),
                InvocationState(
                    "p1", True, None, {"p1:aws": "success", "p1:gcp": "success"}
                ),
            ]
        )
        with (
            patch(
                "tmi_tf.worker.mark_child", side_effect=lambda *a: next(states)
            ) as mark,
            patch("tmi_tf.worker.close_invocation") as close,
        ):
            cb1 = self._run_child(pool, _child("p1:aws", sibs))
            cb2 = self._run_child(pool, _child("p1:gcp", sibs))
        mark.assert_any_call(ANY, "tm1", "p1:aws", "success")
        mark.assert_any_call(ANY, "tm1", "p1:gcp", "success")
        close.assert_called_once_with(
            ANY, "tm1", "Invocation complete: 2 succeeded, 0 failed"
        )
        cb1.send_status.assert_not_called()  # first child: not complete yet
        cb2.send_status.assert_called_once_with("completed", "2 succeeded, 0 failed")

    def test_one_child_fails_sends_failed_with_environment(self):
        pool, _queue = _pool()
        sibs = ["p1:aws", "p1:gcp"]
        states = iter(
            [
                InvocationState("p1", True, None, {"p1:aws": "failed"}),
                InvocationState(
                    "p1", True, None, {"p1:aws": "failed", "p1:gcp": "success"}
                ),
            ]
        )
        with (
            patch("tmi_tf.worker.mark_child", side_effect=lambda *a: next(states)),
            patch("tmi_tf.worker.close_invocation") as close,
        ):
            self._run_child(pool, _child("p1:aws", sibs), result_success=False)
            cb = self._run_child(pool, _child("p1:gcp", sibs))
        close.assert_called_once_with(
            ANY, "tm1", "Invocation complete: 1 succeeded, 1 failed (p1:aws)"
        )
        cb.send_status.assert_called_once_with(
            "failed", "1 succeeded, 1 failed (p1:aws)"
        )

    def test_late_mark_after_close_sends_nothing(self):
        pool, _queue = _pool()
        sibs = ["p1:aws"]
        closed = InvocationState("p1", False, None, {"p1:aws": "success"})
        with (
            patch("tmi_tf.worker.mark_child", return_value=closed),
            patch("tmi_tf.worker.close_invocation") as close,
        ):
            cb = self._run_child(pool, _child("p1:aws", sibs))
        close.assert_not_called()
        cb.send_status.assert_not_called()

    def test_exception_marks_failed_and_keeps_message(self):
        pool, queue = _pool()
        queue.delete = MagicMock()
        state = InvocationState("p1", True, None, {"p1:aws": "failed"})
        with (
            patch("tmi_tf.worker.mark_child", return_value=state) as mark,
            patch("tmi_tf.worker.close_invocation"),
        ):
            self._run_child(
                pool,
                _child("p1:aws", ["p1:aws", "p1:gcp"]),
                raise_exc=RuntimeError("x"),
            )
        mark.assert_called_once_with(ANY, "tm1", "p1:aws", "failed")
        queue.delete.assert_not_called()

    def test_timeout_marks_failed(self):
        pool, queue = _pool()
        pool.config.job_timeout = 0.01  # type: ignore[assignment]
        job = _child("p1:aws", ["p1:aws"])

        async def slow(*a, **k):
            await asyncio.sleep(1)

        with (
            patch.object(pool, "_run_job", side_effect=slow),
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch(
                "tmi_tf.worker.mark_child",
                return_value=InvocationState("p1", True, None, {"p1:aws": "failed"}),
            ) as mark,
            patch("tmi_tf.worker.close_invocation") as close,
            patch("tmi_tf.worker.AddonCallback"),
        ):
            queue.publish(job.to_queue_message())
            msg = queue.consume(max_messages=1)[0]
            asyncio.run(pool._handle_message(msg))
        mark.assert_called_once_with(ANY, "tm1", "p1:aws", "failed")
        close.assert_called_once()


class TestWatchdog:
    def test_watchdog_marks_missing_children_failed_and_closes(self):
        pool, _ = _pool()
        state = InvocationState("p1", True, None, {"p1:aws": "success"})
        after = InvocationState(
            "p1", True, None, {"p1:aws": "success", "p1:gcp": "failed"}
        )
        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.worker.read_state", return_value=state),
            patch("tmi_tf.worker.mark_child", return_value=after) as mark,
            patch("tmi_tf.worker.close_invocation") as close,
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
        ):

            async def go():
                pool._arm_watchdog(
                    "tm1",
                    "p1",
                    ["p1:aws", "p1:gcp"],
                    datetime.now(timezone.utc) + timedelta(milliseconds=20),
                    "https://cb",
                )
                await asyncio.sleep(0.2)

            asyncio.run(go())
        mark.assert_called_once_with(ANY, "tm1", "p1:gcp", "failed")
        close.assert_called_once_with(
            ANY, "tm1", "Invocation timed out: 1 succeeded, 1 failed (p1:gcp)"
        )
        cb_cls.return_value.send_status.assert_called_once_with(
            "failed", "1 succeeded, 1 failed (p1:gcp)"
        )

    def test_watchdog_does_nothing_if_already_closed(self):
        pool, _ = _pool()
        closed = InvocationState("p1", False, None, {"p1:aws": "success"})
        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.worker.read_state", return_value=closed),
            patch("tmi_tf.worker.close_invocation") as close,
        ):

            async def go():
                pool._arm_watchdog(
                    "tm1", "p1", ["p1:aws"], datetime.now(timezone.utc), None
                )
                await asyncio.sleep(0.05)

            asyncio.run(go())
        close.assert_not_called()

    def test_child_dequeue_rearms_watchdog(self):
        pool, queue = _pool()
        job = _child("p1:aws", ["p1:aws"])
        with (
            patch.object(pool, "_run_job", return_value=None),
            patch.object(pool, "_arm_watchdog") as arm,
        ):
            queue.publish(job.to_queue_message())
            msg = queue.consume(max_messages=1)[0]
            asyncio.run(pool._handle_message(msg))
        arm.assert_called_once_with("tm1", "p1", ["p1:aws"], job.deadline, "https://cb")

    def test_parent_arms_watchdog(self):
        pool, _queue = _pool()
        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch(
                "tmi_tf.worker.resolve_fanout_targets",
                return_value=[FanoutTarget("r1", "u", "aws")],
            ),
            patch("tmi_tf.worker.open_invocation"),
            patch("tmi_tf.worker.AddonCallback"),
            patch.object(pool, "_arm_watchdog") as arm,
        ):
            asyncio.run(pool._run_job(_job(scope="all"), receipt="rc"))
        arm.assert_called_once()
        assert arm.call_args.args[:3] == ("tm1", "p1", ["p1:aws"])
