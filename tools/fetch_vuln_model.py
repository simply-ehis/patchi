#!/usr/bin/env python
"""Fetch / build / verify the GNN vulnerability classifier (E-3 Slice 3.2).

One-time setup for the GNNBugDetector model asset:

  1. Build the GIN+GAT network and export it to ONNX
     (~/.patchi/models/gnn_vuln/gnn_vuln_classifier.onnx)
  2. Write a SHA256 checksum sidecar (.sha256) — verified on every load

IMPORTANT — weight honesty:
  The exported model carries RANDOM weights. It is written WITHOUT a
  `.trained` marker, so the detector will refuse to emit findings from it.
  To activate: train the network on BigVul/PrimeVul (or your own corpus),
  save the state_dict, re-export, then `touch` the .trained sidecar.

  A future revision of this script may download a trained checkpoint from a
  hosted URL; when that happens the URL + expected hash are pinned here.

Usage:
  python tools/fetch_vuln_model.py            # build + checksum
  python tools/fetch_vuln_model.py --verify   # verify existing model only
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from patchi.core.agents.gnn_models import (  # noqa: E402
    MODEL_DIR,
    MODEL_NAME,
    export_onnx,
    verify_checksum,
    write_checksum,
)

TRAINED_MARKER = "gnn_vuln_classifier.trained"


def build() -> int:
    try:

        from patchi.core.agents.gnn_models import GINGATNet
    except RuntimeError as e:
        print(f"ERROR: {e}")
        return 1

    net = GINGATNet()
    net.eval()
    model_path = MODEL_DIR / MODEL_NAME
    export_onnx(net, model_path)
    write_checksum(model_path)

    ok, msg = verify_checksum(model_path)
    print(f"model:      {model_path}")
    print(f"checksum:   {msg}")

    marker = MODEL_DIR / TRAINED_MARKER
    if not marker.exists():
        print()
        print("NOTICE: exported weights are UNTRAINED (random init).")
        print(f"The detector will SKIP until {marker} exists.")
        print("Train the network, re-export, then create the marker to activate.")

    # Smoke-test the ONNX session loads.
    try:
        from patchi.core.agents.gnn_models import GNNVulnerabilityClassifier

        clf = GNNVulnerabilityClassifier()
        if clf.available:
            print("session:    loaded OK (trusted=%s)" % clf.trusted)
        else:
            print(f"session:    NOT trusted -> {clf.skip_reason()}")
            return 1 if "integrity" in clf.skip_reason() else 0
    except Exception as e:  # noqa: BLE001
        print(f"session load failed: {e}")
        return 1
    return 0


def verify() -> int:
    model_path = MODEL_DIR / MODEL_NAME
    if not model_path.is_file():
        print(f"model not found: {model_path}")
        return 1
    ok, msg = verify_checksum(model_path)
    print(("OK  " if ok else "FAIL") + f"  {msg}")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verify", action="store_true", help="only verify checksum")
    args = ap.parse_args()
    return verify() if args.verify else build()


if __name__ == "__main__":
    sys.exit(main())
