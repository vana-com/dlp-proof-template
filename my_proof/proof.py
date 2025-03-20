import hashlib
import json
import logging
import os

from my_proof.models.proof_response import ProofResponse
from my_proof.utils.blockchain import BlockchainClient
from my_proof.utils.google import get_google_user
from my_proof.utils.schema import validate_schema
from my_proof.config import settings


class Proof:
    def __init__(self):
        self.proof_response = ProofResponse(dlp_id=settings.DLP_ID)
        try:
            self.blockchain_client = BlockchainClient()
            self.blockchain_available = True
        except Exception as e:
            logging.warning(f"Blockchain client initialization failed: {str(e)}")
            self.blockchain_available = False

    def generate(self) -> ProofResponse:
        """Generate proofs for all input files."""
        logging.info("Starting proof generation")
        errors = []

        # Fetch Google user info if token is provided
        google_user = None
        storage_user_hash = None
        if settings.GOOGLE_TOKEN:
            google_user = get_google_user()
            if google_user:
                storage_user_hash = hashlib.sha256(google_user.id.encode()).hexdigest()
                if not google_user.verified_email:
                    errors.append("UNVERIFIED_STORAGE_EMAIL")
            else:
                errors.append("UNVERIFIED_STORAGE_USER")
        else:
            logging.info("GOOGLE_TOKEN not set, skipping user verification")

        # Get existing file count from blockchain if available
        if self.blockchain_available and settings.OWNER_ADDRESS:
            existing_file_count = self.blockchain_client.get_contributor_file_count()
            if existing_file_count > 0:
                errors.append(f"DUPLICATE_CONTRIBUTION")
        else:
            logging.info("Skipping blockchain validation")

        # Log the files we'll be processing
        input_files = os.listdir(settings.INPUT_DIR)
        logging.info(
            f"Found {len(input_files)} files in input directory: {input_files}"
        )
        processed_count = 0

        # Iterate through files and calculate data validity
        for input_filename in input_files:
            logging.info(f"Checking file: {input_filename}")
            input_file = os.path.join(settings.INPUT_DIR, input_filename)

            # Skip directories
            if os.path.isdir(input_file):
                logging.info(f"Skipping directory: {input_filename}")
                continue

            file_extension = os.path.splitext(input_file)[1].lower()
            if file_extension == ".json":
                processed_count += 1
                logging.info(f"Processing JSON file: {input_filename}")
                with open(input_file, "r") as f:
                    json_content = f.read()
                    logging.info(f"Validating file: {json_content[:50]}...")
                    input_data = json.loads(json_content)
                    schema_type, schema_matches = validate_schema(input_data)
                    logging.info(
                        f"Schema validation result: type={schema_type}, valid={schema_matches}"
                    )
                    if not schema_matches:
                        errors.append(f"INVALID_SCHEMA")
                        break

                    # Verify the input data matches the Google profile
                    if google_user:
                        profile_matches = self._verify_profile_match(
                            google_user, input_data
                        )
                        if not profile_matches:
                            errors.append("PROFILE_MISMATCH")
                            logging.error(
                                f"Input profile data does not match Google profile"
                            )

                    # Calculate proof-of-contribution scores
                    self.proof_response.ownership = (
                        1.0 if settings.OWNER_ADDRESS else 0.0
                    )
                    self.proof_response.quality = 1.0 if schema_matches else 0.0
                    self.proof_response.authenticity = (
                        1.0 if google_user and schema_matches else 0.0
                    )
                    self.proof_response.uniqueness = 1.0

                    # Calculate overall score
                    self.proof_response.score = (
                        self.proof_response.quality * 0.4
                        + self.proof_response.authenticity * 0.3
                        + self.proof_response.uniqueness * 0.2
                        + self.proof_response.ownership * 0.1
                    )

                    # Additional (public) properties to include in the proof about the data
                    self.proof_response.attributes = {
                        "schema_type": schema_type,
                        "user_email": input_data.get("email"),
                        "user_id": input_data.get("userId"),
                        "profile_name": input_data.get("profile", {}).get("name"),
                        "verified_with_oauth": google_user is not None,
                    }

                    # Additional metadata about the proof, written onchain
                    self.proof_response.metadata = {
                        "schema_type": schema_type,
                    }

                    self.proof_response.valid = len(errors) == 0
            else:
                logging.info(
                    f"Skipping non-JSON file: {input_filename} (extension: {file_extension})"
                )

        logging.info(
            f"Processed {processed_count} JSON files out of {len(input_files)} total files"
        )

        # Only include errors if there are any
        if len(errors) > 0:
            logging.warning(f"Errors found during proof generation: {errors}")
            self.proof_response.attributes["errors"] = errors

        return self.proof_response

    def _verify_profile_match(self, google_user, input_data):
        """
        Verify that the input data matches the Google profile.

        Args:
            google_user: The GoogleUserInfo object from the OAuth API
            input_data: The input data from the JSON file

        Returns:
            bool: True if the data matches, False otherwise
        """
        # Check userId matches Google user ID
        if input_data.get("userId") != google_user.id:
            logging.error(
                f"User ID mismatch: {input_data.get('userId')} != {google_user.id}"
            )
            return False

        # Check email matches Google email
        if input_data.get("email") != google_user.email:
            logging.error(
                f"Email mismatch: {input_data.get('email')} != {google_user.email}"
            )
            return False

        # Check profile name matches Google name if available
        profile_name = input_data.get("profile", {}).get("name")
        if profile_name and profile_name != google_user.name:
            logging.error(f"Name mismatch: {profile_name} != {google_user.name}")
            return False

        logging.info("Google profile verification successful")
        return True
