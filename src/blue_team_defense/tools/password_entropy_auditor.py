"""Password entropy auditor, dictionary attack resilience tester, and secure generator."""

import argparse
import collections
import math
import secrets
import string
import sys
from typing import Any, Dict, List, Optional

COMMON_PASSWORD_DICTIONARY = {
    "password", "123456", "12345678", "qwerty", "admin", "welcome",
    "login", "password123", "letmein", "football", "iloveyou", "master",
    "monkey", "dragon", "starwars", "pass1234", "administrator",
}


def calculate_password_bits_entropy(pwd: str) -> float:
    """Calculate password entropy in bits based on pool size and length."""
    if not pwd:
        return 0.0

    has_lower = any(c.islower() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_special = any(c in string.punctuation for c in pwd)

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_special:
        pool_size += len(string.punctuation)

    if pool_size == 0:
        pool_size = 1

    entropy_bits = len(pwd) * math.log2(pool_size)
    return round(entropy_bits, 2)


def generate_secure_password(length: int = 16) -> str:
    """Generate cryptographically secure high-entropy random password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^&*()-_=+" for c in pwd)):
            return pwd


def execute_password_entropy_auditor(
    password: Optional[str] = None,
    generate_length: int = 0,
    dictionary_check: bool = True,
) -> Dict[str, Any]:
    """Audit password security strength, compute bit entropy, and detect dictionary terms."""
    generated = None
    if generate_length > 0:
        generated = generate_secure_password(generate_length)
        eval_pwd = generated
    elif password:
        eval_pwd = password
    else:
        eval_pwd = "P@ssw0rdSecure2026!"

    entropy_bits = calculate_password_bits_entropy(eval_pwd)

    in_dictionary = False
    if dictionary_check:
        clean_lower = eval_pwd.lower()
        in_dictionary = any(dict_word in clean_lower for dict_word in COMMON_PASSWORD_DICTIONARY)

    if in_dictionary:
        rating = "VERY_WEAK (Common dictionary phrase matched)"
    elif entropy_bits < 40:
        rating = "WEAK"
    elif entropy_bits < 60:
        rating = "MODERATE"
    elif entropy_bits < 80:
        rating = "STRONG"
    else:
        rating = "VERY_STRONG"

    return {
        "status": "success",
        "length": len(eval_pwd),
        "entropy_bits": entropy_bits,
        "rating": rating,
        "dictionary_flag": in_dictionary,
        "generated_password": generated,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for password auditor."""
    parser = argparse.ArgumentParser(
        description="Password entropy auditor, dictionary tester, and secure generator."
    )
    parser.add_argument("--password", "-p", help="Password string to analyze")
    parser.add_argument("--generate", "-g", type=int, default=0, help="Generate a random password with specified character length")
    parser.add_argument(
        "--no-dict-check",
        dest="dictionary_check",
        action="store_false",
        help="Skip dictionary attack pattern matching",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for password auditor."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_password_entropy_auditor(
            password=args.password,
            generate_length=args.generate,
            dictionary_check=args.dictionary_check,
        )
        if result["generated_password"]:
            print(f"Generated Password: {result['generated_password']}")
        print(f"Password Length: {result['length']} characters")
        print(f"Entropy: {result['entropy_bits']} bits | Security Rating: {result['rating']}")
        if result["dictionary_flag"]:
            print("  [WARNING] Contains common dictionary patterns")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Password auditor error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
