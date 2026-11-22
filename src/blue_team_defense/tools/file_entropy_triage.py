"""File entropy triage tool for detecting packed, compressed, or encrypted payloads."""

import argparse
import collections
import math
import os
import sys
from typing import Any, Dict, List, Optional


def calculate_shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    counts = collections.Counter(data)

    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)


def execute_file_entropy_triage(
    file_path: str,
    chunk_size: int = 2048,
    threshold: float = 7.2,
) -> Dict[str, Any]:
    """Analyze file entropy in sequential chunks to detect packing or encryption."""
    if not os.path.isfile(file_path):
        return {
            "status": "error",
            "message": f"Target file not found: {file_path}",
        }

    file_size = os.path.getsize(file_path)
    chunk_entropies: List[Dict[str, Any]] = []
    total_data = bytearray()

    with open(file_path, "rb") as f:
        offset = 0
        while chunk := f.read(chunk_size):
            ent = calculate_shannon_entropy(chunk)
            chunk_entropies.append({
                "offset": offset,
                "length": len(chunk),
                "entropy": ent,
                "exceeds_threshold": ent >= threshold,
            })
            total_data.extend(chunk)
            offset += len(chunk)

    overall_entropy = calculate_shannon_entropy(bytes(total_data))
    high_entropy_chunks = sum(1 for c in chunk_entropies if c["exceeds_threshold"])
    high_entropy_ratio = round(high_entropy_chunks / len(chunk_entropies), 2) if chunk_entropies else 0.0

    # Classification
    if overall_entropy >= 7.5:
        classification = "ENCRYPTED_OR_PACKED"
    elif overall_entropy >= 6.8:
        classification = "COMPRESSED_OR_HIGH_ENTROPY"
    elif overall_entropy >= 4.5:
        classification = "NATIVE_CODE_OR_DATA"
    else:
        classification = "PLAIN_TEXT_OR_SPARSE"

    return {
        "status": "success",
        "file_path": os.path.abspath(file_path),
        "file_size_bytes": file_size,
        "overall_entropy": overall_entropy,
        "classification": classification,
        "entropy_threshold": threshold,
        "total_chunks": len(chunk_entropies),
        "high_entropy_chunks_count": high_entropy_chunks,
        "high_entropy_ratio": high_entropy_ratio,
        "chunk_samples": chunk_entropies[:10],
    }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for file entropy triage."""
    parser = argparse.ArgumentParser(
        description="File entropy triage tool for detecting packed, compressed, or encrypted payloads."
    )
    parser.add_argument("--file", "-f", required=True, help="Path to target file for entropy analysis")
    parser.add_argument("--chunk-size", "-c", type=int, default=2048, help="Byte chunk size for block analysis (default: 2048)")
    parser.add_argument("--threshold", "-t", type=float, default=7.2, help="Entropy threshold (default: 7.2 bits)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for file entropy triage."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_file_entropy_triage(
            file_path=args.file,
            chunk_size=args.chunk_size,
            threshold=args.threshold,
        )
        if result.get("status") == "error":
            sys.stderr.write(f"Error: {result.get('message')}\n")
            return 1

        print(f"File: {result['file_path']} ({result['file_size_bytes']} bytes)")
        print(f"Overall Entropy: {result['overall_entropy']}/8.0 bits")
        print(f"Classification: {result['classification']}")
        print(f"High Entropy Chunks: {result['high_entropy_chunks_count']}/{result['total_chunks']} ({result['high_entropy_ratio'] * 100}%)")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Entropy triage error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
