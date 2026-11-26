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
evidence: the tags of every *other* tagged (neutral or instruction) run in the same
schedule, every attempt included (a retry has a new run id and tag, so its evidence is
told apart). For a control run that always includes both tags of its own block, the
neutral's and the instruction's, so the only tag-free run of a block is checked for
both; for a neutral run it always includes its block's instruction tag (and so the
instruction's decoy path, ``/x-<tag>``). For every run it covers the rest of the
experiment's tags, which turns any cross-run leak (shared gateway, agent memory, a
reused cell) into a refusal rather than a silently mislabelled run.

:func:`forbidden_tokens_for` adds the callback tokens of the block's instruction run
(every attempt) for its control and neutral runs: the callback host is part of the
instruction's own fingerprint, and a neutral text never names one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from string import Template

from cell.injector.placement import BODY_SURFACES
from control.core.models import Arm, Placement, RunManifest, Surface
from control.core.tags import decoy_prefix
from control.core.tokens import derive_token
from control.runner.experiment import Experiment
from control.runner.schedule import ScheduledRun

__all__ = [
    "TokenMismatchError",
    "forbidden_tags_for",
    "forbidden_tokens_for",
    "placement_id_for",
    "render_catcher_file",
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

    A control run gets no tag and no placements. A neutral or instruction run gets its
    scheduled tag and one placement per planted surface, in the instruction arm's order,
    each with the target's url and locator, its own arm's payload id and version, the
    callback token ``derive_token(lab_key, run_id, placement_id)`` and the sha256 of its
    rendered UTF-8 text. Both tagged arms plant the same surfaces at the same places:
    only the text differs.
    """
    if not lab_key:
        raise ValueError("lab_key must be non-empty")
    _check_run(run, experiment)
    placements: list[Placement] = []
    if run.arm.tagged:
        if run.tag is None:  # pragma: no cover - ScheduledRun forbids it
            raise ValueError(f"{run.arm.value} run {run.run_id} has no tag")
        payload = experiment.arms.payload(run.arm)
        target = experiment.target(run.target)
        for surface in experiment.arms.surfaces:
            placement_id = placement_id_for(run.run_id, surface)
            token = derive_token(lab_key, run.run_id, placement_id)
            text = render_text(
                payload.templates[surface],
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
                    payload_id=payload.payload_id,
                    payload_version=payload.version,
                    tag=run.tag,
                    token=token,
                    content_sha256=_sha256(text),
                    offset_fraction=spec.offset_fraction if surface in BODY_SURFACES else None,
                )
            )
    return RunManifest(
        run_id=run.run_id,
        experiment_id=run.experiment_id,
        block_id=run.block_id,
        arm=run.arm,
        target=run.target,
        agent=run.agent,
        model=run.model,
        schedule_index=run.schedule_index,
        attempt=run.attempt,
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

    Empty for a control run. Each text is re-rendered from the templates of the
    manifest's own arm and must hash to its placement's ``content_sha256`` and contain
    the run's tag; a mismatch (the experiment changed after the manifest was rendered,
    or a placement names the other arm's payload) raises ``ValueError``.
    """
    if manifest.experiment_id != experiment.experiment_id:
        raise ValueError(
            f"manifest {manifest.run_id} belongs to experiment {manifest.experiment_id}, "
            f"not {experiment.experiment_id}"
        )
    if not manifest.arm.tagged:
        return {}
    payload = experiment.arms.payload(manifest.arm)
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


def render_catcher_file(manifest: RunManifest, experiment: Experiment) -> bytes:
    """The catcher's ``LAB_TOKENS`` file: run id, callback domain and token pairs only.

    The experiment's ``callback_domain`` is passed along so the catcher records the zone
    the payloads name; it answers every name, so DNS callbacks always resolve to it.
    """
    if manifest.experiment_id != experiment.experiment_id:
        raise ValueError(
            f"manifest {manifest.run_id} belongs to experiment {manifest.experiment_id}, "
            f"not {experiment.experiment_id}"
        )
    doc = {
        "run_id": manifest.run_id,
        "callback_domain": experiment.callback_domain,
        "tokens": [
            {"token": token, "placement_id": placement_id}
            for token, placement_id in render_catcher_tokens(manifest)
        ],
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def _require_block_partners(
    run: ScheduledRun, schedule: Sequence[ScheduledRun], arms: Sequence[Arm]
) -> None:
    """``ValueError`` unless ``schedule`` holds ``run`` and, in its block, a run of each of
    ``arms``."""
    if not any(r.run_id == run.run_id for r in schedule):
        raise ValueError(f"run {run.run_id} is not in the schedule")
    for arm in arms:
        if not any(r.block_id == run.block_id and r.arm is arm for r in schedule):
            raise ValueError(
                f"{run.arm.value} run {run.run_id}: no {arm.value} run of its block in the schedule"
            )


#: For each arm, the arms of the same block whose evidence must never show in it.
_GUARDED_BY: dict[Arm, tuple[Arm, ...]] = {
    Arm.CONTROL: (Arm.NEUTRAL, Arm.INSTRUCTION),
    Arm.NEUTRAL: (Arm.INSTRUCTION,),
    Arm.INSTRUCTION: (),
}


def forbidden_tags_for(run: ScheduledRun, schedule: Sequence[ScheduledRun]) -> frozenset[str]:
    """Tags that must not occur in ``run``'s evidence: every other tagged run's tag.

    ``schedule`` is every attempt of every run (see
    :func:`~control.runner.schedule.retry`), so the set covers the tags of the other
    attempts too, including earlier attempts of ``run`` itself. For a control run it
    always contains its block's neutral and instruction tags, and for a neutral run its
    block's instruction tag, so neither set is ever empty (the labeller requires that);
    ``ValueError`` if the schedule lacks those runs. Never contains ``run``'s own tag.
    ``ValueError`` if ``run`` is not in ``schedule``.
    """
    _require_block_partners(run, schedule, _GUARDED_BY[run.arm])
    return frozenset(
        r.tag for r in schedule if r.run_id != run.run_id and r.tag is not None and r.tag != run.tag
    )


def forbidden_tokens_for(
    run: ScheduledRun,
    schedule: Sequence[ScheduledRun],
    experiment: Experiment,
    lab_key: bytes,
) -> frozenset[str]:
    """Callback tokens that must not occur in ``run``'s evidence.

    For a control or neutral run: the token of every planted surface of every attempt of
    its block's instruction run, as the lab key derives them (the instruction's own
    callback host). Empty for an instruction run. ``ValueError`` as for
    :func:`forbidden_tags_for`.
    """
    if not lab_key:
        raise ValueError("lab_key must be non-empty")
    _require_block_partners(run, schedule, _GUARDED_BY[run.arm])
    if run.arm is Arm.INSTRUCTION:
        return frozenset()
    return frozenset(
        derive_token(lab_key, r.run_id, placement_id_for(r.run_id, surface))
        for r in schedule
        if r.block_id == run.block_id and r.arm is Arm.INSTRUCTION
        for surface in experiment.arms.surfaces
    )
