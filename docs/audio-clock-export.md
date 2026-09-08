# Capture Clock Compatibility

The Device Session v2 reader supports the explicit optional
`openaria.audio-clock.v1` extension without changing the frozen schema bytes.
Both card ingestion and derived-media admission validate sample-clock anchors,
host-clock mapping, queue/error counters and clock residuals. PCM segment times
remain sample-relative; `audio.sync` remains session-relative.

Derived-media recipe 2 reads the verified frame index and measures video cadence
from its first/last monotonic timestamps. Frame identities, count, ordering and
internal residuals are checked before encoding. An internal residual over half a
frame requires variable-rate rendering and rejects automatic export. Output
frame rate and PTS use the measured cadence, with at most 0.5 ns rounding per
video frame. Independent clock arithmetic rounds to nanoseconds when the exact
common denominator exceeds the bounded timeline representation.

With valid audio-clock evidence, PCM sample positions use the measured rate
(rounded to 0.001 Hz) and `atempo` corrects drift before session offset placement.
The rounding error is at most 0.1125 ms over 30 minutes at the minimum supported
8 kHz rate. The new recipe is recorded in the derived receipt. Older recipe-1
receipts retain their original validation rules and are not silently relabeled.
Recipe-2 receipts retain the measured video tick, source input hashes and verified
output digest after temporary sources are cleaned up.

A timeline PASS verifies the derived output against the declared input clocks;
it does not prove ADC calibration or external multi-camera synchronization.
Historical audio without capture evidence has no continuity proof. Legacy audio
whose thread duration contradicts its PCM sample duration still fails the strict
desktop export timeline check; the SDK offers a start-offset-only export that
retains those original WAV files. Existing old desktop canonical exports whose
raw sources were removed require a fresh download to regenerate their cadence.
