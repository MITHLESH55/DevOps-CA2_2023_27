import logging
import sys

LOG_FILE = "transfer.log"


def get_logger(name="SecureTransfer"):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)-8s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger


def log_encryption(logger, metadata):
    logger.info("=" * 60)
    logger.info("ENCRYPTION OPERATION COMPLETE")
    logger.info("-" * 60)
    logger.info(f"  Input file      : {metadata.get('input_file', 'N/A')}")
    logger.info(f"  Output file     : {metadata.get('output_file', 'N/A')}")
    logger.info(f"  Plaintext size  : {metadata.get('plaintext_size', 0)} bytes")
    logger.info(f"  Bundle size     : {metadata.get('bundle_size', 0)} bytes")
    logger.info(f"  Plaintext SHA256: {metadata.get('plaintext_sha256', 'N/A')}")
    logger.info(f"  Bundle SHA256   : {metadata.get('bundle_sha256', 'N/A')}")
    logger.info("=" * 60)


def log_decryption(logger, metadata):
    logger.info("=" * 60)
    logger.info("DECRYPTION OPERATION COMPLETE")
    logger.info("-" * 60)
    logger.info(f"  Input file      : {metadata.get('input_file', 'N/A')}")
    logger.info(f"  Output file     : {metadata.get('output_file', 'N/A')}")
    logger.info(f"  Plaintext size  : {metadata.get('plaintext_size', 0)} bytes")
    logger.info(f"  Plaintext SHA256: {metadata.get('plaintext_sha256', 'N/A')}")
    logger.info(f"  Integrity       : {'VERIFIED' if metadata.get('verified') else 'FAILED'}")
    logger.info("=" * 60)


def log_transfer_start(logger, host, port, filename):
    logger.info(f"TRANSFER START: {filename} -> {host}:{port}")


def log_transfer_complete(logger, filename, elapsed_ms):
    logger.info(f"TRANSFER COMPLETE: {filename} in {elapsed_ms:.1f} ms")
