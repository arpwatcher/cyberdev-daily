"""Entry point for password and certificate checks."""

import argparse
import getpass
import sys

from secplus import passwords, tls


def cmd_check_password(args):
    password = args.password or getpass.getpass("password: ")
    result = passwords.score_password(password)
    print(f"entropy: {result['entropy_bits']} bits")
    print(f"strength: {result['strength']}")
    if result["reason"]:
        print(f"note: {result['reason']}")


def cmd_identify_hash(args):
    print(passwords.identify_hash(args.value))


def cmd_check_cert(args):
    cert = tls.load_certificate(args.cert)
    result = tls.audit_certificate(cert)
    info = result["info"]
    print(f"subject: {info['subject']}")
    print(f"issuer:  {info['issuer']}")
    print(f"key: {info['key_type']} {info['key_size']} bits")
    print(f"signature: {info['signature_algorithm']}")
    print(f"valid: {info['not_valid_before']} to {info['not_valid_after']}")

    if result["findings"]:
        print("\nfindings:")
        for f in result["findings"]:
            print(f"  - {f}")
    else:
        print("\nno issues found")


def build_parser():
    parser = argparse.ArgumentParser(prog="secplus", description="security+ study toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    pw_parser = sub.add_parser("check-password", help="score password strength")
    pw_parser.add_argument("--password", help="omit to be prompted without echo")
    pw_parser.set_defaults(func=cmd_check_password)

    hash_parser = sub.add_parser("identify-hash", help="guess a hash format from its shape")
    hash_parser.add_argument("value")
    hash_parser.set_defaults(func=cmd_identify_hash)

    cert_parser = sub.add_parser("check-cert", help="audit a pem certificate")
    cert_parser.add_argument("cert")
    cert_parser.set_defaults(func=cmd_check_cert)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
