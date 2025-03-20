import json
import logging
import os
import sys
import traceback
import zipfile

from my_proof.proof import Proof
from my_proof.config import settings

logging.basicConfig(level=logging.INFO, format="%(message)s")


def run() -> None:
    """Generate proofs for all input files."""
    # logging.info(f"Using config: {settings.model_dump_json(indent=2)}")

    input_files_exist = os.path.isdir(settings.INPUT_DIR) and bool(
        os.listdir(settings.INPUT_DIR)
    )

    if not input_files_exist:
        raise FileNotFoundError(f"No input files found in {settings.INPUT_DIR}")

    logging.info(f"Input directory before extraction: {os.listdir(settings.INPUT_DIR)}")
    extract_input()
    logging.info(f"Input directory after extraction: {os.listdir(settings.INPUT_DIR)}")

    proof = Proof()
    proof_response = proof.generate()

    output_path = os.path.join(settings.OUTPUT_DIR, "results.json")
    with open(output_path, "w") as f:
        json.dump(proof_response.model_dump(), f, indent=2)
    logging.info(f"Proof generation complete: {proof_response}")


def extract_input() -> None:
    """If the input directory contains any zip files, extract them"""
    for input_filename in os.listdir(settings.INPUT_DIR):
        input_file = os.path.join(settings.INPUT_DIR, input_filename)

        if zipfile.is_zipfile(input_file):
            logging.info(f"Extracting zip file: {input_file}")
            with zipfile.ZipFile(input_file, "r") as zip_ref:
                file_list = zip_ref.namelist()
                logging.info(f"Zip contains files: {file_list}")
                zip_ref.extractall(settings.INPUT_DIR)
                logging.info(f"Extracted {len(file_list)} files from {input_filename}")


if __name__ == "__main__":
    try:
        run()
    except Exception as e:
        logging.error(f"Error during proof generation: {e}")
        traceback.print_exc()
        sys.exit(1)
