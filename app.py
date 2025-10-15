import argparse
import sys
try:
    import pkg_resources
    VERSION = pkg_resources.get_distribution("Python Password Entropy").version
except:
    VERSION = "0.1.0-src" 

from core.generator import generate_secure_password, generate_url_safe_token, generate_hex_key
from audit.entropy_check import assess_strength
from core.passphrase import generate_mnemonic_passphrase
from audit.breach_check import check_breach_k_anonymity

def run_cli():
    """Sets up the command-line interface for Python Password Entropy."""
    parser = argparse.ArgumentParser(
        description="Python Password Entropy: SOTA Secure Credential Generator and Auditor.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '-v', '--version', 
        action='version', 
        version=f'%(prog)s {VERSION}',
        help="Show the current version."
    )
    
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

    p_parser = subparsers.add_parser('password', help='Generate a secure, high-entropy password.')
    p_parser.add_argument('-l', '--length', type=int, default=16, help='Total length (default: 16).')
    p_parser.add_argument('-u', '--upper', type=int, default=1, help='Min uppercase (default: 1).')
    p_parser.add_argument('-L', '--lower', type=int, default=1, help='Min lowercase (default: 1).')
    p_parser.add_argument('-d', '--digit', type=int, default=1, help='Min digit (default: 1).')
    p_parser.add_argument('-s', '--symbol', type=int, default=1, help='Min symbol (default: 1).')

    pp_parser = subparsers.add_parser('passphrase', help='Generate a secure, memorable mnemonic passphrase (Diceware style).')
    pp_parser.add_argument('-w', '--words', type=int,default=6, help='The number of words in the passphrase (default: 6 for SOTA).')
    pp_parser.add_argument('-S', '--separator', type=str, default='-', help='The separator to use between words (default: "-").')

    subparsers.add_parser('token', help='Generate a URL-safe, base64-encoded token.').add_argument(
        '-b', '--bytes', type=int, default=32, help='Bytes for entropy source (default: 32).'
    )
    subparsers.add_parser('key', help='Generate a secure cryptographic key (hex-encoded).').add_argument(
        '-b', '--bytes', type=int, default=32, help='Bytes for entropy source (default: 32 for AES-256).'
    )

    a_parser = subparsers.add_parser('audit', help='Assess the cryptographic strength (Entropy and Breach Status) of a given secret.')
    a_parser.add_argument('secret', type=str, help='The secret string (password or passphrase) to be audited.')
    a_parser.add_argument('-p', '--passphrase',action='store_true',help='Treat the secret as a passphrase (uses wordlist entropy calculation).')
    a_parser.add_argument('-B', '--breach',action='store_true',help='Check if the secret has been found in known data breaches (K-Anonymity check).')
    

    args = parser.parse_args()
    
    try:
        if args.command == 'password':
            policy = {"lower": args.lower, "upper": args.upper, "digit": args.digit, "symbol": args.symbol}
            password = generate_secure_password(args.length, policy)
            print(password)
        elif args.command == 'passphrase': 
            passphrase = generate_mnemonic_passphrase(args.words, args.separator)
            print(passphrase)
            
        elif args.command == 'token':
            token = generate_url_safe_token(args.bytes)
            print(token)
            
        elif args.command == 'key':
            key = generate_hex_key(args.bytes)
            print(key)

        elif args.command == 'audit':
            secret = args.secret
            assessment = assess_strength(secret, is_passphrase=args.passphrase)
            print("\n--- Python Password Entropy Security Audit ---")
            print(f"Secret: {secret}")
            print(f"Length/Words: {assessment['length_metric']}")
            entropy_label = "Wordlist Est." if args.passphrase else "Char Set Est."
            print(f"Entropy ({entropy_label}): {assessment['entropy_per_char']}") 
            print(f"Total Entropy Bits: {assessment['total_entropy_bits']}")
            print(f"** Strength Rating: {assessment['rating']} **")

            if args.breach:
                is_breached, count = check_breach_k_anonymity(secret)
                
                print("\n--- Breach Check (K-Anonymity) ---")
                if is_breached:
                    print(f"STATUS: CRITICAL! Found in {count:,} known breaches.")
                    print("ACTION: Change this password immediately. DO NOT USE.")
                else:
                    print("STATUS: SAFE. Not found in simulated breach lists.")
                
            print("-" * 35 + "\n") 


    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    run_cli()

        