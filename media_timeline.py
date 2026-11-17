"""Structured timeline & audio peak summary for ArtCraft SoundCraft and FilmCraft plugins."""

from __future__ import annotations

import math
from pathlib import Path
import re
import struct
from typing import Any
import wave

from files_tools import PathPolicy

FILMCRAFT_TICKS_PER_SECOND = 254_016_000_000
_FLOAT_WRAPPER_RE = re.compile(r"Float\(([-+]?\d*\.?\d+(?:[eE][-+]?\d+)?)\)")


def _round_sec(value: float) -> float:
    return round(float(value), 3)


def _parse_effect_float(val: Any) -> float | None:
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        m = _FLOAT_WRAPPER_RE.search(val)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                return None
    return None


def _wav_peak_summary(wav_path: Path, buckets: int = 16) -> dict[str, Any] | None:
    """Compute lightweight peak/RMS dBFS and coarse envelope buckets from a PCM WAV file."""
    try:
        with wave.open(str(wav_path), "rb") as wf:
            sampwidth = wf.getsampwidth()
            nchannels = wf.getnchannels()
            nframes = wf.getnframes()
            framerate = wf.getframerate()
            if sampwidth not in (1, 2, 3, 4) or nchannels <= 0 or nframes <= 0 or framerate <= 0:
                return None

            max_possible = float((1 << (8 * sampwidth - 1)) - 1) if sampwidth > 1 else 128.0
            frames_per_bucket = max(1, nframes // buckets)
            bucket_peaks: list[float] = []
            overall_peak = 0.0
            sum_sq = 0.0
            total_samples = 0

            step_frames = max(1, nframes // 200_000)

            for _ in range(buckets):
                raw = wf.readframes(frames_per_bucket)
                if not raw:
                    break
                frame_size = sampwidth * nchannels
                count_frames = len(raw) // frame_size
                b_peak = 0.0
                for f_idx in range(0, count_frames, step_frames):
                    offset = f_idx * frame_size
                    for ch in range(nchannels):
                        s_off = offset + ch * sampwidth
                        sample_bytes = raw[s_off : s_off + sampwidth]
                        if sampwidth == 1:
                            val = abs(sample_bytes[0] - 128)
                        elif sampwidth == 2:
                            val = abs(struct.unpack("<h", sample_bytes)[0])
                        elif sampwidth == 3:
                            b0, b1, b2 = sample_bytes
                            signed = (b2 << 16) | (b1 << 8) | b0
                            if signed & 0x800000:
                                signed -= 0x1000000
                            val = abs(signed)
                        else:
                            val = abs(struct.unpack("<i", sample_bytes)[0])
                        norm = min(1.0, val / max_possible)
                        if norm > b_peak:
                            b_peak = norm
                        if norm > overall_peak:
                            overall_peak = norm
                        sum_sq += norm * norm
                        total_samples += 1
                bucket_peaks.append(round(b_peak, 3))

            peak_db = round(20.0 * math.log10(overall_peak), 2) if overall_peak > 1e-6 else -96.0
            rms = math.sqrt(sum_sq / total_samples) if total_samples > 0 else 0.0
            rms_db = round(20.0 * math.log10(rms), 2) if rms > 1e-6 else -96.0
            return {
                "waveform_source": "wav_pcm_analysis",
                "sample_rate": framerate,
                "channels": nchannels,
                "duration_seconds": _round_sec(nframes / framerate),
                "peak_dbfs": peak_db,
                "rms_dbfs": rms_db,
                "envelope_16": bucket_peaks,
            }
    except Exception:
        return None


def summarize_soundcraft_session(session: dict[str, Any], policy: PathPolicy | None = None) -> dict[str, Any]:
    """Build a clean, seconds-based timeline & dB summary for a SoundCraft session."""
    sr = int(session.get("sample_rate") or 48000)
    if sr <= 0:
        sr = 48000
    length_samples = int(session.get("length_samples") or 0)

    sources_by_id: dict[Any, dict[str, Any]] = {}
    session_dir = Path(session["path"]).parent if session.get("path") else None

    for src in session.get("sources") or []:
        sid = src.get("id")
        frames = int(src.get("frames") or 0)
        src_info: dict[str, Any] = {
            "id": sid,
            "name": src.get("name"),
            "path": src.get("path"),
            "channels": src.get("channels"),
            "duration_seconds": _round_sec(frames / sr),
            "loaded": bool(src.get("loaded", True)),
        }
        if policy is not None and src.get("path"):
            raw_p = Path(str(src["path"]))
            candidate = raw_p if raw_p.is_absolute() else (session_dir / raw_p if session_dir else None)
            if candidate is not None:
                try:
                    resolved = policy.resolve_read_path(str(candidate))
                    if resolved.exists() and resolved.suffix.lower() == ".wav":
                        wav_stats = _wav_peak_summary(resolved)
                        if wav_stats:
                            src_info["waveform_summary"] = wav_stats
                except PermissionError:
                    pass
        sources_by_id[sid] = src_info

    markers = [
        {
            "number": m.get("number"),
            "name": m.get("name"),
            "kind": m.get("kind"),
            "time_seconds": _round_sec(int(m.get("start") or 0) / sr),
        }
        for m in (session.get("markers") or [])
    ]

    tracks_out = []
    for tr in session.get("tracks") or []:
        track_vol_db = float(tr.get("volume_db") or 0.0)
        clips_out = []
        for cl in tr.get("clips") or []:
            start_s = int(cl.get("start") or 0)
            end_s = int(cl.get("end") or 0)
            dur_s = int(cl.get("length") or max(0, end_s - start_s))
            clip_gain_db = float(cl.get("gain_db") or 0.0)
            src_meta = sources_by_id.get(cl.get("source"))
            clip_entry: dict[str, Any] = {
                "id": cl.get("id"),
                "name": cl.get("name"),
                "start_seconds": _round_sec(start_s / sr),
                "end_seconds": _round_sec(end_s / sr),
                "duration_seconds": _round_sec(dur_s / sr),
                "gain_db": round(clip_gain_db, 2),
                "effective_gain_db": round(track_vol_db + clip_gain_db, 2),
                "fade_in_seconds": _round_sec(int(cl.get("fade_in") or 0) / sr),
                "fade_out_seconds": _round_sec(int(cl.get("fade_out") or 0) / sr),
                "muted": bool(cl.get("muted", False)),
            }
            if src_meta and "waveform_summary" in src_meta:
                clip_entry["waveform_summary"] = src_meta["waveform_summary"]
            else:
                clip_entry["waveform_source"] = "gain_metadata_only"
            clips_out.append(clip_entry)

        inserts = [
            f"{ins.get('plugin')}{'(bypassed)' if ins.get('bypass') else ''}"
            for ins in (tr.get("inserts") or [])
        ]
        tracks_out.append({
            "id": tr.get("id"),
            "name": tr.get("name"),
            "kind": tr.get("kind"),
            "format": tr.get("format"),
            "volume_db": round(track_vol_db, 2),
            "mute": bool(tr.get("mute", False)),
            "solo": bool(tr.get("solo", False)),
            "pan": tr.get("pan"),
            "inserts": inserts,
            "clips": clips_out,
        })

    return {
        "app": "SoundCraft",
        "session_name": session.get("name"),
        "path": session.get("path"),
        "sample_rate": sr,
        "bit_depth": session.get("bit_depth"),
        "duration_seconds": _round_sec(length_samples / sr),
        "tempo": session.get("tempo"),
        "meter": session.get("meter"),
        "busses": [b.get("name") for b in (session.get("busses") or [])],
        "markers": markers,
        "tracks": tracks_out,
    }


def _extract_filmcraft_volume_db(effects: list[dict[str, Any]] | None) -> float | None:
    for eff in effects or []:
        if eff.get("effect") == "volume" and eff.get("enabled", True):
            level = (eff.get("params") or {}).get("level")
            if isinstance(level, dict):
                return _parse_effect_float(level.get("value"))
    return None


def _summarize_filmcraft_tracks(tracks: list[dict[str, Any]] | None, kind: str) -> list[dict[str, Any]]:
    out = []
    for tr in tracks or []:
        clips_out = []
        for item in tr.get("items") or []:
            start_ticks = int(item.get("start") or 0)
            end_ticks = int(item.get("end") or 0)
            dur_ticks = int(item.get("duration") or max(0, end_ticks - start_ticks))
            effects_list = item.get("effects") or []
            effect_names = [e.get("effect") for e in effects_list if e.get("enabled", True)]
            vol_effect_db = _extract_filmcraft_volume_db(effects_list)
            gain_db = item.get("gainDb")
            combined_db = None
            if gain_db is not None or vol_effect_db is not None:
                combined_db = round(float(gain_db or 0.0) + float(vol_effect_db or 0.0), 2)

            clip_data: dict[str, Any] = {
                "item_id": item.get("item"),
                "name": item.get("name"),
                "start_seconds": _round_sec(start_ticks / FILMCRAFT_TICKS_PER_SECOND),
                "end_seconds": _round_sec(end_ticks / FILMCRAFT_TICKS_PER_SECOND),
                "duration_seconds": _round_sec(dur_ticks / FILMCRAFT_TICKS_PER_SECOND),
                "start_frame": item.get("startFrame"),
                "end_frame": item.get("endFrame"),
                "speed": item.get("speed", 1.0),
                "enabled": bool(item.get("enabled", True)),
                "effects": effect_names,
            }
            if kind == "audio" or combined_db is not None:
                clip_data["gain_db"] = gain_db
                clip_data["volume_effect_db"] = vol_effect_db
                clip_data["effective_volume_db"] = combined_db
            clips_out.append(clip_data)

        transitions_out = []
        for t in tr.get("transitions") or []:
            if isinstance(t, dict):
                t_start = int(t.get("start") or 0)
                t_end = int(t.get("end") or 0)
                t_dur = int(t.get("duration") or max(0, t_end - t_start))
                transitions_out.append({
                    "name": t.get("name") or t.get("transition") or t.get("type") or "transition",
                    "start_seconds": _round_sec(t_start / FILMCRAFT_TICKS_PER_SECOND),
                    "end_seconds": _round_sec(t_end / FILMCRAFT_TICKS_PER_SECOND),
                    "duration_seconds": _round_sec(t_dur / FILMCRAFT_TICKS_PER_SECOND),
                })

        out.append({
            "id": tr.get("id"),
            "name": tr.get("name"),
            "kind": kind,
            "enabled": bool(tr.get("enabled", True)),
            "muted": bool(tr.get("muted", False)),
            "solo": bool(tr.get("solo", False)),
            "locked": bool(tr.get("locked", False)),
            "transitions": transitions_out,
            "clips": clips_out,
        })
    return out


def summarize_filmcraft_sequence(seq: dict[str, Any], project: dict[str, Any] | None = None) -> dict[str, Any]:
    """Convert FilmCraft ticks-based sequence JSON into exact seconds, dB levels, and transitions."""
    dur_ticks = int(seq.get("duration") or 0)
    playhead_ticks = int(seq.get("playhead") or 0)

    markers = [
        {
            "name": m.get("name"),
            "kind": m.get("kind"),
            "color": m.get("color"),
            "comment": m.get("comment"),
            "time_seconds": _round_sec(int(m.get("start") or 0) / FILMCRAFT_TICKS_PER_SECOND),
            "duration_seconds": _round_sec(int(m.get("duration") or 0) / FILMCRAFT_TICKS_PER_SECOND),
        }
        for m in (seq.get("markers") or [])
    ]

    summary: dict[str, Any] = {
        "app": "FilmCraft",
        "sequence_name": seq.get("name"),
        "duration_seconds": _round_sec(dur_ticks / FILMCRAFT_TICKS_PER_SECOND),
        "duration_frames": seq.get("durationFrames"),
        "playhead_seconds": _round_sec(playhead_ticks / FILMCRAFT_TICKS_PER_SECOND),
        "settings": seq.get("settings"),
        "markers": markers,
        "video_tracks": _summarize_filmcraft_tracks(seq.get("video"), "video"),
        "audio_tracks": _summarize_filmcraft_tracks(seq.get("audio"), "audio"),
    }
    if project is not None:
        summary["project"] = project
    return summary
