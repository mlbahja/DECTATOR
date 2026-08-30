import argparse

from modules.utils import validate_image
from modules.metadata import extract_metadata
from modules.output import save_output
from modules.steganography import (
    extract_lsb_bits,
    bits_to_bytes,
    bytes_to_text,
    detect_pgp_key,
)


def parse_arguments():
    """
    Parse command-line arguments.
    """

    parser = argparse.ArgumentParser(
        prog="image-inspector",
        description="Analyze image metadata and detect hidden information."
    )

    parser.add_argument(
        "-m",
        "--metadata",
        action="store_true",
        help="Extract image metadata."
    )

    parser.add_argument(
        "-s",
        "--steganography",
        action="store_true",
        help="Detect hidden data using steganography."
    )

    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Save the output to a file."
    )

    parser.add_argument(
        "image",
        help="Path to the image file."
    )

    args = parser.parse_args()

    # At least one analysis mode must be selected
    if not args.metadata and not args.steganography:
        parser.error("At least one analysis option (-m or -s) is required.")

    return args


def main():
    args = parse_arguments()

    try:
        # Validate image before processing
        validate_image(args.image)

        # ==========================
        # Metadata Extraction
        # ==========================
        if args.metadata:

            metadata = extract_metadata(args.image)

            if metadata:
                print("===== METADATA =====")

                for key, value in metadata.items():
                    print(f"{key}: {value}")

                if args.output:
                    save_output(metadata, args.output)

            else:
                message = "No metadata found."
                print(message)

                if args.output:
                    save_output(message, args.output)

        # ==========================
        # Steganography Detection
        # ==========================
        if args.steganography:

            bits = extract_lsb_bits(args.image)
            bytes_data = bits_to_bytes(bits)
            text = bytes_to_text(bytes_data)

            pgp_key = detect_pgp_key(text)

            if pgp_key:
                print("\n===== HIDDEN PGP KEY FOUND =====")
                print(pgp_key)

                if args.output:
                    save_output(
                        pgp_key,
                        args.output,
                        append=args.metadata
                    )

            else:
                message = "No hidden PGP key found."
                print(message)

                if args.output:
                    save_output(
                        message,
                        args.output,
                        append=args.metadata
                    )

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()