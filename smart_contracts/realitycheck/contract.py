from algopy import (
    ARC4Contract,
    GlobalState,
    Txn,
    arc4,
    log,
    op,
    subroutine,
)


class RealityCheckContract(ARC4Contract):
    """
    RealityCheck: Verifiable Credentials for YouTube Content Creators

    This contract stores credential hashes and revocation status for 
    verifiable credentials issued to YouTube content creators.
    """

    def __init__(self) -> None:
        # Store the issuer's address (your address)
        self.issuer = GlobalState(Txn.sender)

        # Track total credentials issued
        self.total_credentials = GlobalState(arc4.UInt64(0))

    @arc4.abimethod
    def issue_credential(
        self,
        credential_hash: arc4.StaticArray[arc4.Byte, arc4.Literal[32]],
        creator_address: arc4.Address,
        video_url_hash: arc4.StaticArray[arc4.Byte, arc4.Literal[32]]
    ) -> arc4.String:
        """
        Issue a new verifiable credential

        Args:
            credential_hash: SHA-256 hash of the full VC JSON
            creator_address: Algorand address of the content creator
            video_url_hash: SHA-256 hash of the video URL

        Returns:
            Success message with credential ID
        """
        # Only the issuer can issue credentials
        assert Txn.sender == self.issuer, "Only issuer can issue credentials"

        # Generate credential ID (using total count + 1)
        credential_id = self.total_credentials.value + 1

        # Store credential data in box storage
        # Box name format: "cred_{credential_id}"
        box_name = op.concat(b"cred_", op.itob(credential_id))

        # Create credential data structure
        # Format: credential_hash(32) + creator_address(32) + video_url_hash(32) + timestamp(8) + revoked_flag(1)
        credential_data = op.concat(
            credential_hash.bytes,
            creator_address.bytes,
            video_url_hash.bytes,
            op.itob(op.Global.latest_timestamp),
            b"\x00"  # Not revoked initially
        )

        # Store in box
        op.Box.put(box_name, credential_data)

        # Update total count
        self.total_credentials.value = credential_id

        # Log the issuance event
        log(
            op.concat(
                b"CREDENTIAL_ISSUED:",
                op.itob(credential_id),
                b":",
                credential_hash.bytes
            )
        )

        return arc4.String(f"Credential issued with ID: {credential_id}")

    @arc4.abimethod
    def revoke_credential(self, credential_id: arc4.UInt64) -> arc4.String:
        """
        Revoke an existing credential

        Args:
            credential_id: ID of the credential to revoke

        Returns:
            Success message
        """
        # Only the issuer can revoke credentials
        assert Txn.sender == self.issuer, "Only issuer can revoke credentials"

        # Check if credential exists
        box_name = op.concat(b"cred_", op.itob(credential_id.native))
        box_exists, box_data = op.Box.get(box_name)
        assert box_exists, "Credential does not exist"

        # Check if already revoked
        revoked_flag = op.extract_uint64(box_data, 104)  # Byte 104 is the revocation flag
        assert revoked_flag == 0, "Credential already revoked"

        # Update revocation flag
        new_data = op.concat(
            op.extract(box_data, 0, 104),  # First 104 bytes (all data except revocation flag)
            b"\x01"  # Set revoked flag to 1
        )

        # Update box
        op.Box.put(box_name, new_data)

        # Log the revocation event
        log(
            op.concat(
                b"CREDENTIAL_REVOKED:",
                op.itob(credential_id.native)
            )
        )

        return arc4.String(f"Credential {credential_id.native} revoked successfully")

    @arc4.abimethod(readonly=True)
    def verify_credential(
        self,
        credential_id: arc4.UInt64
    ) -> arc4.Tuple[
        arc4.Bool,  # exists
        arc4.Bool,  # is_revoked
        arc4.StaticArray[arc4.Byte, arc4.Literal[32]],  # credential_hash
        arc4.Address,  # creator_address
        arc4.StaticArray[arc4.Byte, arc4.Literal[32]],  # video_url_hash
        arc4.UInt64  # timestamp
    ]:
        """
        Verify a credential's existence and status

        Args:
            credential_id: ID of the credential to verify

        Returns:
            Tuple containing verification data
        """
        box_name = op.concat(b"cred_", op.itob(credential_id.native))
        box_exists, box_data = op.Box.get(box_name)

        if not box_exists:
            # Return empty data if credential doesn't exist
            empty_hash = arc4.StaticArray[arc4.Byte, arc4.Literal[32]].from_bytes(b"\x00" * 32)
            empty_address = arc4.Address.from_bytes(b"\x00" * 32)
            return arc4.Tuple((
                arc4.Bool(False),  # doesn't exist
                arc4.Bool(False),  # not revoked (meaningless if doesn't exist)
                empty_hash,
                empty_address,
                empty_hash,
                arc4.UInt64(0)
            ))

        # Extract data from box
        credential_hash = arc4.StaticArray[arc4.Byte, arc4.Literal[32]].from_bytes(
            op.extract(box_data, 0, 32)
        )
        creator_address = arc4.Address.from_bytes(op.extract(box_data, 32, 32))
        video_url_hash = arc4.StaticArray[arc4.Byte, arc4.Literal[32]].from_bytes(
            op.extract(box_data, 64, 32)
        )
        timestamp = arc4.UInt64(op.extract_uint64(box_data, 96))
        is_revoked = arc4.Bool(op.extract_uint64(box_data, 104) == 1)

        return arc4.Tuple((
            arc4.Bool(True),  # exists
            is_revoked,
            credential_hash,
            creator_address,
            video_url_hash,
            timestamp
        ))

    @arc4.abimethod(readonly=True)
    def verify_by_hash(
        self,
        credential_hash: arc4.StaticArray[arc4.Byte, arc4.Literal[32]]
    ) -> arc4.Tuple[arc4.Bool, arc4.UInt64]:
        """
        Find credential by its hash and return if it exists and is not revoked

        Args:
            credential_hash: Hash to search for

        Returns:
            Tuple of (is_valid, credential_id)
        """
        total = self.total_credentials.value

        # Search through all credentials
        for i in range(1, total + 1):
            box_name = op.concat(b"cred_", op.itob(i))
            box_exists, box_data = op.Box.get(box_name)

            if box_exists:
                stored_hash = op.extract(box_data, 0, 32)
                if stored_hash == credential_hash.bytes:
                    # Found matching hash, check if revoked
                    is_revoked = op.extract_uint64(box_data, 104) == 1
                    return arc4.Tuple((arc4.Bool(not is_revoked), arc4.UInt64(i)))

        # Not found
        return arc4.Tuple((arc4.Bool(False), arc4.UInt64(0)))

    @arc4.abimethod(readonly=True)
    def get_issuer(self) -> arc4.Address:
        """Get the issuer's address"""
        return arc4.Address(self.issuer.value)

    @arc4.abimethod(readonly=True)
    def get_total_credentials(self) -> arc4.UInt64:
        """Get total number of credentials issued"""
        return self.total_credentials.value
