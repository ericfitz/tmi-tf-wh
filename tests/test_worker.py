"""Tests for the async worker pool."""

import asyncio
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import ANY, MagicMock, patch

from test_invocation import FakeTMI

from tmi_tf import invocation as inv
from tmi_tf.analyzer import AnalysisResult, FanoutTarget
from tmi_tf.config import Config
from tmi_tf.invocation import InvocationState
from tmi_tf.job import Job
from tmi_tf.llm_profiles import LLMProfile
from tmi_tf.providers.memory import MemoryQueueProvider
from tmi_tf.tmi_client_wrapper import STATUS_NOTE_NAME, AnalysisAborted
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
    config.llm_profiles = {
        "test": LLMProfile("test", "oci", "m", "oci"),
        "other": LLMProfile("other", "oci", "m2", "oci"),
    }
    config.llm_profile = "test"
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

    def test_parent_closes_invocation_when_all_enqueues_fail(self):
        pool, queue = _pool()
        targets = [
            FanoutTarget("r1", "u", "aws-public"),
            FanoutTarget("r1", "u", "gcp-public"),
        ]
        queue.publish = MagicMock(side_effect=RuntimeError("boom"))
        tmi = MagicMock()
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=tmi),
            patch("tmi_tf.worker.resolve_fanout_targets", return_value=targets),
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
            patch("tmi_tf.worker.open_invocation") as open_inv,
            patch("tmi_tf.worker.mark_child") as mark,
            patch("tmi_tf.worker.close_invocation") as close,
        ):
            asyncio.run(pool._run_job(_job(scope="all"), receipt="rc"))
        open_inv.assert_called_once()
        assert mark.call_count == 2
        close.assert_called_once_with(
            ANY,
            "tm1",
            "Invocation complete: 0 succeeded, 2 failed (p1:aws-public, p1:gcp-public)",
        )
        cb_cls.return_value.send_status.assert_any_call(
            "failed", "0 succeeded, 2 failed (p1:aws-public, p1:gcp-public)"
        )
        assert "tm1" not in pool._watchdogs

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
                InvocationState("p1", True, None, {"p1_aws": "success"}),
                InvocationState(
                    "p1", True, None, {"p1_aws": "success", "p1_gcp": "success"}
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
                InvocationState("p1", True, None, {"p1_aws": "failed"}),
                InvocationState(
                    "p1", True, None, {"p1_aws": "failed", "p1_gcp": "success"}
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
        closed = InvocationState("p1", False, None, {"p1_aws": "success"})
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
        state = InvocationState("p1", True, None, {"p1_aws": "failed"})
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

    def test_stale_child_mark_does_not_close_newer_invocation(self):
        """A retried child from a superseded invocation must not close (or
        send a callback for) whatever invocation happens to be open now."""
        pool, _queue = _pool()
        fake = FakeTMI()
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        inv.open_invocation(fake, "tm1", "p2", ["p2:aws"], future)

        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=fake),
            patch(
                "tmi_tf.worker.run_analysis",
                return_value=AnalysisResult(success=True),
            ),
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
        ):
            asyncio.run(pool._run_job(_child("p1:aws", ["p1:aws"]), receipt="rc"))
        assert fake.metadata["tf_open"] == "true"
        assert fake.metadata["tf_child_p1_aws"] == "success"
        cb_cls.return_value.send_status.assert_not_called()

        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=fake),
            patch(
                "tmi_tf.worker.run_analysis",
                return_value=AnalysisResult(success=True),
            ),
            patch("tmi_tf.worker.AddonCallback") as cb_cls2,
        ):
            asyncio.run(pool._run_job(_child("p2:aws", ["p2:aws"]), receipt="rc"))
        assert fake.metadata["tf_open"] == "false"
        cb_cls2.return_value.send_status.assert_called_once_with(
            "completed", "1 succeeded, 0 failed"
        )

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
                return_value=InvocationState("p1", True, None, {"p1_aws": "failed"}),
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
        state = InvocationState("p1", True, None, {"p1_aws": "success"})
        after = InvocationState(
            "p1", True, None, {"p1_aws": "success", "p1_gcp": "failed"}
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

    def test_watchdog_closes_and_calls_back_when_mark_fails(self):
        pool, _ = _pool()
        state = InvocationState("p1", True, None, {"p1_aws": "success"})
        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.worker.read_state", return_value=state),
            patch("tmi_tf.worker.mark_child", side_effect=Exception("(500)")),
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
        close.assert_called_once_with(
            ANY, "tm1", "Invocation timed out: 1 succeeded, 1 failed (p1:gcp)"
        )
        cb_cls.return_value.send_status.assert_called_once_with(
            "failed", "1 succeeded, 1 failed (p1:gcp)"
        )

    def test_watchdog_sends_completed_when_all_succeeded(self):
        """A close attempt that failed earlier (all children already succeeded,
        note still open) should report completed, not failed, on timeout."""
        pool, _ = _pool()
        state = InvocationState(
            "p1", True, None, {"p1_aws": "success", "p1_gcp": "success"}
        )
        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.worker.read_state", return_value=state),
            patch("tmi_tf.worker.mark_child") as mark,
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
        mark.assert_not_called()
        close.assert_called_once_with(
            ANY, "tm1", "Invocation timed out: 2 succeeded, 0 failed"
        )
        cb_cls.return_value.send_status.assert_called_once_with(
            "completed", "2 succeeded, 0 failed"
        )

    def test_watchdog_does_nothing_if_already_closed(self):
        pool, _ = _pool()
        closed = InvocationState("p1", False, None, {"p1_aws": "success"})
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


class TestAbort:
    def test_abort_running_child(self):
        pool, queue = _pool()
        queue.delete = MagicMock()
        started = threading.Event()
        tmi = MagicMock()

        def fake_run_analysis(**kw):
            started.set()
            kw["tmi_client"].cancel_event.wait(5)
            raise AnalysisAborted("x")

        state_after = InvocationState("p1", True, None, {"p1:aws": "aborted"})
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=tmi),
            patch("tmi_tf.worker.run_analysis", side_effect=fake_run_analysis),
            patch("tmi_tf.worker.mark_child", return_value=state_after) as mark,
            patch(
                "tmi_tf.worker.read_state",
                return_value=InvocationState("p1", True, None, {}),
            ),
            patch("tmi_tf.worker.close_invocation") as close,
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
        ):
            job = _child("p1:aws", ["p1:aws"])

            async def go():
                queue.publish(job.to_queue_message())
                msg = queue.consume(max_messages=1)[0]
                t = asyncio.create_task(pool._handle_message(msg))
                await asyncio.to_thread(started.wait, 5)
                n = await pool.abort("p1", "operator")
                await t
                return n, t

            n, _ = asyncio.run(go())
        assert n == 1
        assert tmi.cancel_event.is_set()
        queue.delete.assert_called_once()
        mark.assert_any_call(ANY, "tm1", "p1:aws", "aborted")
        close.assert_called_once_with(ANY, "tm1", "Aborted: operator")
        cb_cls.return_value.send_status.assert_called_with(
            "failed", "aborted: operator"
        )
        assert not job.temp_dir or not job.temp_dir.exists()

    def test_cancel_seen_in_tmi_aborts_whole_invocation(self):
        """The delivery poll raises AnalysisAborted without abort() having run:
        the worker must abort the invocation itself."""
        pool, queue = _pool()
        tmi = MagicMock()
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=tmi),
            patch("tmi_tf.worker.run_analysis", side_effect=AnalysisAborted("x")),
            patch.object(pool, "abort") as abort,
        ):
            job = _child("p1:aws", ["p1:aws", "p1:gcp"])
            queue.publish(job.to_queue_message())
            msg = queue.consume(max_messages=1)[0]
            asyncio.run(pool._handle_message(msg))
        assert tmi.delivery_id == "p1"
        abort.assert_called_once_with("p1", "cancelled in TMI")

    def test_abort_after_invocation_closed_sends_no_failed_callback(self):
        """Last child already closed the invocation (and sent "completed")
        when abort() lands: no second, contradictory "failed" callback."""
        pool, queue = _pool()
        queue.delete = MagicMock()
        started = threading.Event()

        def fake_run_analysis(**kw):
            started.set()
            kw["tmi_client"].cancel_event.wait(5)
            raise AnalysisAborted("x")

        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.worker.run_analysis", side_effect=fake_run_analysis),
            patch(
                "tmi_tf.worker.read_state",
                return_value=InvocationState("p1", False, None, {}),
            ),
            patch("tmi_tf.worker.close_invocation") as close,
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
        ):
            job = _child("p1:aws", ["p1:aws"])

            async def go():
                queue.publish(job.to_queue_message())
                msg = queue.consume(max_messages=1)[0]
                t = asyncio.create_task(pool._handle_message(msg))
                await asyncio.to_thread(started.wait, 5)
                await pool.abort("p1", "operator")
                await t

            asyncio.run(go())
        close.assert_not_called()
        cb_cls.return_value.send_status.assert_not_called()

    def test_queued_child_of_aborted_invocation_is_dropped(self):
        pool, queue = _pool()
        queue.delete = MagicMock(wraps=queue.delete)
        pool._cancelled.add("p1")
        state = InvocationState("p1", False, None, {"p1:aws": "aborted"})
        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.worker.run_analysis") as run,
            patch("tmi_tf.worker.mark_child", return_value=state) as mark,
            patch("tmi_tf.worker.close_invocation"),
        ):
            job = _child("p1:aws", ["p1:aws", "p1:gcp"])
            queue.publish(job.to_queue_message())
            msg = queue.consume(max_messages=1)[0]
            asyncio.run(pool._handle_message(msg))
        run.assert_not_called()
        queue.delete.assert_called_once_with(msg.receipt)
        mark.assert_called_once_with(ANY, "tm1", "p1:aws", "aborted")

    def test_abort_unknown_invocation_returns_zero(self):
        pool, _ = _pool()
        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ) as auth,
            patch(
                "tmi_tf.worker.read_state",
                return_value=InvocationState(None, False, None),
            ),
            patch("tmi_tf.worker.close_invocation") as close,
        ):
            assert asyncio.run(pool.abort("nope", "r")) == 0
        close.assert_not_called()
        auth.assert_not_called()

    def test_abort_closes_idle_invocation_with_no_running_job(self):
        """Parent already opened the invocation and enqueued children, but no
        child has been dequeued yet: abort() must still find the threat model
        id (from the in-memory record made when the parent opened it) and
        close the invocation. Then dequeuing the queued child must drop it
        without a second close."""
        pool, queue = _pool()
        targets = [FanoutTarget("r1", "u", "aws")]
        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.worker.resolve_fanout_targets", return_value=targets),
            patch("tmi_tf.worker.AddonCallback"),
            patch("tmi_tf.worker.open_invocation"),
        ):
            asyncio.run(pool._run_job(_job(scope="all"), receipt="rc"))
        assert pool._invocations["p1"] == ("tm1", "https://cb")

        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch(
                "tmi_tf.worker.read_state",
                return_value=InvocationState("p1", True, None, {}),
            ),
            patch("tmi_tf.worker.close_invocation") as close,
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
        ):
            n = asyncio.run(pool.abort("p1", "operator"))
        assert n == 0
        close.assert_called_once_with(ANY, "tm1", "Aborted: operator")
        cb_cls.return_value.send_status.assert_called_once_with(
            "failed", "aborted: operator"
        )

        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.worker.run_analysis") as run,
            patch(
                "tmi_tf.worker.mark_child",
                return_value=InvocationState("p1", False, None, {"p1:aws": "aborted"}),
            ) as mark,
            patch("tmi_tf.worker.close_invocation") as close2,
        ):
            msg = queue.consume(max_messages=1)[0]
            asyncio.run(pool._handle_message(msg))
        run.assert_not_called()
        mark.assert_called_once_with(ANY, "tm1", "p1:aws", "aborted")
        close2.assert_not_called()

    def test_dropped_if_cancelled_while_waiting_for_semaphore(self):
        """A job already past the first _cancelled check (queued before the
        abort) must be re-checked once it clears the semaphore, not just
        dropped from _active_jobs after running."""
        pool, queue = _pool()
        pool._semaphore = asyncio.Semaphore(1)

        async def go():
            await pool._semaphore.acquire()  # occupy the only slot
            job = _child("p1:aws", ["p1:aws"])
            queue.publish(job.to_queue_message())
            msg = queue.consume(max_messages=1)[0]
            t = asyncio.create_task(pool._handle_message(msg))
            await asyncio.sleep(0.05)  # let it block waiting for the semaphore
            pool._cancelled.add("p1")
            pool._semaphore.release()
            await t

        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.worker.run_analysis") as run,
            patch(
                "tmi_tf.worker.mark_child",
                return_value=InvocationState("p1", False, None, {"p1:aws": "aborted"}),
            ) as mark,
            patch("tmi_tf.worker.close_invocation"),
        ):
            asyncio.run(go())
        run.assert_not_called()
        mark.assert_called_once_with(ANY, "tm1", "p1:aws", "aborted")
        assert pool._active_jobs == {}
        # The invocation was already aborted before the job cleared the
        # semaphore, so it must never have recorded _invocations or armed a
        # watchdog for it.
        assert "p1" not in pool._invocations
        assert "tm1" not in pool._watchdogs

    def test_abort_running_parent_sends_failed_callback(self):
        """A parent still in resolve_fanout_targets (invocation not opened
        yet) must still get its "aborted" callback when cancelled, even
        though there is nothing to mark or close."""
        pool, queue = _pool()
        queue.delete = MagicMock()
        started = threading.Event()
        release = threading.Event()

        def blocking_resolve(*a, **kw):
            started.set()
            release.wait(5)
            return []

        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.worker.resolve_fanout_targets", side_effect=blocking_resolve),
            patch(
                "tmi_tf.worker.read_state",
                return_value=InvocationState(None, False, None),
            ),
            patch("tmi_tf.worker.close_invocation") as close,
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
        ):
            job = _job(scope="all")

            async def go():
                queue.publish(job.to_queue_message())
                msg = queue.consume(max_messages=1)[0]
                t = asyncio.create_task(pool._handle_message(msg))
                await asyncio.to_thread(started.wait, 5)
                n = await pool.abort("p1", "operator")
                release.set()
                await t
                return n

            n = asyncio.run(go())
        assert n == 1
        close.assert_not_called()
        queue.delete.assert_called_once()
        cb_cls.return_value.send_status.assert_called_with(
            "failed", "aborted: operator"
        )

    def test_abort_of_stale_invocation_leaves_current_watchdog_armed(self):
        """_watchdogs is keyed by threat_model_id; abort() of a superseded
        invocation id on that threat model must not cancel the watchdog for
        whatever invocation is actually open there."""
        pool, _ = _pool()

        async def go():
            pool._arm_watchdog(
                "tm1",
                "p2",
                ["p2:aws"],
                datetime.now(timezone.utc) + timedelta(hours=1),
                None,
            )
            wd = pool._watchdogs["tm1"]
            pool._invocations["p1"] = ("tm1", None)
            with (
                patch(
                    "tmi_tf.worker.TMIClient.create_authenticated",
                    return_value=MagicMock(),
                ),
                patch(
                    "tmi_tf.worker.read_state",
                    return_value=InvocationState("p2", True, None, {}),
                ),
                patch("tmi_tf.worker.close_invocation") as close,
            ):
                n = await pool.abort("p1", "stale")
            assert n == 0
            close.assert_not_called()
            assert not wd.cancelled()
            assert pool._watchdogs.get("tm1") is wd
            wd.cancel()  # cleanup so the loop doesn't complain on teardown

        asyncio.run(go())


class TestProfiles:
    def _run_parent(self, job):
        pool, queue = _pool()
        targets = [FanoutTarget("r1", "u", "aws-public")]
        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.worker.resolve_fanout_targets", return_value=targets) as rft,
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
            patch("tmi_tf.worker.open_invocation"),
            patch("tmi_tf.worker.mark_child"),
        ):
            asyncio.run(pool._run_job(job, receipt="rc"))
        return queue, rft, cb_cls.return_value

    def test_children_inherit_requested_profile(self):
        queue, _, _ = self._run_parent(_job(profile="other"))
        bodies = [m.body for m in queue.consume(max_messages=10)]
        assert [b["profile"] for b in bodies] == ["other"]

    def test_children_get_default_when_none_requested(self):
        queue, _, _ = self._run_parent(_job())
        assert queue.consume(max_messages=10)[0].body["profile"] == "test"

    def test_unknown_profile_fails_before_fanout(self):
        queue, rft, cb = self._run_parent(_job(profile="nope"))
        rft.assert_not_called()
        assert queue.consume(max_messages=10) == []
        cb.send_status.assert_any_call(
            "failed", 'unknown LLM profile "nope" (available: other, test)'
        )

    def test_missing_key_fails_before_fanout(self):
        pool, _ = _pool()
        pool.config.llm_profiles["keyed"] = LLMProfile(
            "keyed", "anthropic", "m", "api_key", "T_WORKER_ABSENT_KEY"
        )
        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.worker.resolve_fanout_targets") as rft,
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
        ):
            asyncio.run(pool._run_job(_job(profile="keyed"), receipt="rc"))
        rft.assert_not_called()
        cb_cls.return_value.send_status.assert_any_call(
            "failed",
            'LLM profile "keyed" needs T_WORKER_ABSENT_KEY, which is not set',
        )

    def test_child_passes_profile_to_run_analysis(self):
        pool, _ = _pool()
        with (
            patch(
                "tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()
            ),
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
                        environment="aws-public",
                        profile="other",
                    ),
                    receipt="rc",
                )
            )
        assert ra.call_args.kwargs["profile"].name == "other"
