"""Render one scheduled run into its manifest and per-component cell inputs.

Control plane only. This module is the one place that uses the lab-wide HMAC key: it
derives each placement's callback token (:func:`control.core.tokens.derive_token`) and
checks tokens before a manifest is handed to a cell. The key is an argument, never
stored on any object, and never written into anything a cell receives:

* the manifest (:func:`render_manifest`): tokens, tag, placements and content hashes;
* the injector's ``LAB_PAYLOADS`` file (:func:`render_payloads`): placement texts;
* the catcher's token list (:func:`render_catcher_tokens`): ``(token, placement_id)``
  pairs only, the least the catcher needs to verify a callback.

Placement ids are a function of the run: ``pl_<run ULID>_<surface>`` (e.g.
``pl_01JC..._p1``), so rendering the same run twice gives the same placements and
tokens; only ``created_at`` differs unless given.

:func:`forbidden_tags_for` gives the labeller the tags that must not appear in a run's
evidence: the tags of every *other* injected run in the same schedule. For a control
run that always includes its paired injected run's tag (so the set is never empty);
for an injected run it is the rest of the experiment's tags, which turns any
cross-run leak (shared gateway, agent memory, a reused cell) into a refusal rather
than a silently mislabelled run.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from datetime import UTC, datetime
from string import Template

from control.core.models import Arm, Placement, RunManifest, Surface
from control.core.tags import decoy_prefix
from control.core.tokens import derive_token
from control.runner.experiment import Experiment
from control.runner.schedule import ScheduledRun

__all__ = [
    "TokenMismatchError",
    "forbidden_tags_for",
    "placement_id_for",
    "render_catcher_tokens",
    "render_manifest",
    "render_payloads",
    "render_text",
    "verify_manifest_tokens",
]


class TokenMismatchError(ValueError):
    """A manifest's placement token is not the one the lab key derives for it."""


def placement_id_for(run_id: str, surface: Surface) -> str:
    """The placement id of ``surface`` in run ``run_id``: ``pl_<run ULID>_<surface>``."""
    _, _, suffix = run_id.rpartition("_")
    return f"pl_{suffix or run_id}_{surface.value.lower()}"


def render_text(template: str, *, tag: str, token: str, callback_domain: str) -> str:
    """Fill a payload template (see :data:`~control.runner.experiment.TEMPLATE_FIELDS`)."""
    return Template(template).substitute(
        tag=tag,
        token=token,
        decoy_path=decoy_prefix(tag),
        callback_host=f"{token}.{callback_domain}",
    )


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _check_run(run: ScheduledRun, experiment: Experiment) -> None:
    if run.experiment_id != experiment.experiment_id:
        raise ValueError(
            f"run {run.run_id} belongs to experiment {run.experiment_id}, "
            f"not {experiment.experiment_id}"
        )
    if run.target not in {t.name for t in experiment.targets}:
        raise ValueError(f"run {run.run_id}: target {run.target!r} is not in the experiment")
    if run.agent not in experiment.agents:
        raise ValueError(f"run {run.run_id}: agent {run.agent!r} is not in the experiment")
    if run.model not in experiment.models:
        raise ValueError(f"run {run.run_id}: model {run.model!r} is not in the experiment")


def render_manifest(
    run: ScheduledRun,
    experiment: Experiment,
    lab_key: bytes,
    *,
    created_at: datetime | None = None,
) -> RunManifest:
    """The :class:`RunManifest` of ``run``.

    A control run gets no tag and no placements. An injected run gets its scheduled tag
    and one placement per surface of the injected arm, in the arm's order, each with
    the target's url and locator, the payload's id and version, the callback token
    ``derive_token(lab_key, run_id, placement_id)`` and the sha256 of its rendered
    UTF-8 text.
    """
    if not lab_key:
        raise ValueError("lab_key must be non-empty")
    _check_run(run, experiment)
    placements: list[Placement] = []
    if run.arm is Arm.INJECTED:
        if run.tag is None:  # pragma: no cover - ScheduledRun forbids it
            raise ValueError(f"injected run {run.run_id} has no tag")
        arm = experiment.arms.injected
        target = experiment.target(run.target)
        for surface in arm.surfaces:
            placement_id = placement_id_for(run.run_id, surface)
            token = derive_token(lab_key, run.run_id, placement_id)
            text = render_text(
                arm.payload.templates[surface],
                tag=run.tag,
                token=token,
                callback_domain=experiment.callback_domain,
            )
            spec = target.placements[surface]
            placements.append(
                Placement(
                    placement_id=placement_id,
                    run_id=run.run_id,
                    surface=surface,
                    url=spec.url,
                    locator=spec.locator,
                    payload_id=arm.payload.payload_id,
                    payload_version=arm.payload.version,
                    tag=run.tag,
                    token=token,
                    content_sha256=_sha256(text),
                )
            )
    return RunManifest(
        run_id=run.run_id,
        experiment_id=run.experiment_id,
        pair_id=run.pair_id,
        arm=run.arm,
        target=run.target,
        agent=run.agent,
        model=run.model,
        schedule_index=run.schedule_index,
        tag=run.tag,
        placements=placements,
        created_at=created_at if created_at is not None else datetime.now(UTC),
    )


def verify_manifest_tokens(manifest: RunManifest, lab_key: bytes) -> None:
    """Raise :class:`TokenMismatchError` unless every token is the one ``lab_key`` derives.

    Run before a manifest is handed to a cell, so a cell never plants or verifies a
    token the control plane cannot later map back to its run and placement.
    """
    for placement in manifest.placements:
        expected = derive_token(lab_key, manifest.run_id, placement.placement_id)
        if not hmac.compare_digest(expected, placement.token):
            raise TokenMismatchError(
                f"run {manifest.run_id}: placement {placement.placement_id} "
                "has a token the lab key does not derive"
            )


def render_payloads(manifest: RunManifest, experiment: Experiment) -> dict[str, str]:
    """The injector's ``LAB_PAYLOADS`` content: ``placement_id`` -> rendered text.

    Empty for a control run. Each text is re-rendered from the experiment's templates
    and must hash to its placement's ``content_sha256`` and contain the run's tag; a
    mismatch (the experiment changed after the manifest was rendered) raises
    ``ValueError``.
    """
    if manifest.experiment_id != experiment.experiment_id:
        raise ValueError(
            f"manifest {manifest.run_id} belongs to experiment {manifest.experiment_id}, "
            f"not {experiment.experiment_id}"
        )
    payload = experiment.arms.injected.payload
    texts: dict[str, str] = {}
    for placement in manifest.placements:
        where = f"run {manifest.run_id} placement {placement.placement_id}"
        if (placement.payload_id, placement.payload_version) != (
            payload.payload_id,
            payload.version,
        ):
            raise ValueError(f"{where}: payload differs from the experiment's")
        template = payload.templates.get(placement.surface)
        if template is None:
            raise ValueError(f"{where}: no template for surface {placement.surface.value}")
        text = render_text(
            template,
            tag=placement.tag,
            token=placement.token,
            callback_domain=experiment.callback_domain,
        )
        if _sha256(text) != placement.content_sha256:
            raise ValueError(f"{where}: rendered text does not match content_sha256")
        if placement.tag not in text:  # pragma: no cover - templates must use $tag
            raise ValueError(f"{where}: rendered text lacks the run tag")
        texts[placement.placement_id] = text
    return texts


def render_catcher_tokens(manifest: RunManifest) -> list[tuple[str, str]]:
    """The catcher's input: ``(token, placement_id)`` per placement; empty for control."""
    return [(p.token, p.placement_id) for p in manifest.placements]


def forbidden_tags_for(run: ScheduledRun, schedule: Sequence[ScheduledRun]) -> frozenset[str]:
    """Tags that must not occur in ``run``'s evidence: every other injected run's tag.

    For a control run the set always contains its paired injected run's tag and is
    therefore never empty (the labeller requires that); ``ValueError`` if the schedule
    lacks that run. Never contains ``run``'s own tag. ``ValueError`` if ``run`` is not
    in ``schedule``.
    """
    if not any(r.run_id == run.run_id for r in schedule):
        raise ValueError(f"run {run.run_id} is not in the schedule")
    if run.arm is Arm.CONTROL and not any(
        r.pair_id == run.pair_id and r.arm is Arm.INJECTED for r in schedule
    ):
        raise ValueError(f"control run {run.run_id}: no paired injected run in the schedule")
    return frozenset(
        r.tag for r in schedule if r.run_id != run.run_id and r.tag is not None and r.tag != run.tag
    )
