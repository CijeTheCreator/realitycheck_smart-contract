import pytest
import hashlib
from algopy_testing import AlgopyTestContext, algopy_testing_context
from algopy import arc4

from smart_contracts.realitycheck.contract import RealityCheckContract


class TestRealityCheckContract:
    """Test suite for RealityCheck smart contract"""

    @pytest.fixture(scope="function")
    def context(self) -> AlgopyTestContext:
        """Create a fresh test context for each test"""
        return algopy_testing_context()

    @pytest.fixture
    def contract(self, context: AlgopyTestContext) -> RealityCheckContract:
        """Deploy a fresh contract for each test"""
        with context.txn.create_application(
            sender=context.default_sender,
            on_completion=context.txn.OnCompletion.NoOp,
        ):
            contract = RealityCheckContract()
        return contract

    def create_test_hash(self, data: str) -> arc4.StaticArray[arc4.Byte, arc4.Literal[32]]:
        """Helper to create SHA-256 hash for testing"""
        hash_bytes = hashlib.sha256(data.encode()).digest()
        return arc4.StaticArray[arc4.Byte, arc4.Literal[32]].from_bytes(hash_bytes)

    def test_contract_initialization(self, context: AlgopyTestContext, contract: RealityCheckContract):
        """Test that contract initializes correctly"""
        # Check issuer is set to deployer
        assert contract.get_issuer().bytes == context.default_sender.bytes

        # Check initial credential count is 0
        assert contract.get_total_credentials().native == 0

    def test_issue_credential_success(self, context: AlgopyTestContext, contract: RealityCheckContract):
        """Test successful credential issuance"""
        # Prepare test data
        cred_hash = self.create_test_hash("test_credential_json")
        creator_address = arc4.Address(context.default_sender)
        video_hash = self.create_test_hash("https://youtube.com/watch?v=test123")

        # Issue credential
        with context.txn.create_application_call(sender=context.default_sender):
            result = contract.issue_credential(cred_hash, creator_address, video_hash)

        # Check result
        assert "Credential issued with ID: 1" in result.native

        # Check total count increased
        assert contract.get_total_credentials().native == 1

    def test_issue_credential_unauthorized(self, context: AlgopyTestContext, contract: RealityCheckContract):
        """Test that only issuer can issue credentials"""
        # Create different sender
        unauthorized_sender = context.any_account()

        # Prepare test data
        cred_hash = self.create_test_hash("test_credential_json")
        creator_address = arc4.Address(context.default_sender)
        video_hash = self.create_test_hash("https://youtube.com/watch?v=test123")

        # Try to issue credential from unauthorized account
        with context.txn.create_application_call(sender=unauthorized_sender):
            with pytest.raises(Exception, match="Only issuer can issue credentials"):
                contract.issue_credential(cred_hash, creator_address, video_hash)

    def test_multiple_credential_issuance(self, context: AlgopyTestContext, contract: RealityCheckContract):
        """Test issuing multiple credentials"""
        # Issue first credential
        cred_hash1 = self.create_test_hash("credential_1")
        creator_address1 = arc4.Address(context.default_sender)
        video_hash1 = self.create_test_hash("https://youtube.com/watch?v=video1")

        with context.txn.create_application_call(sender=context.default_sender):
            result1 = contract.issue_credential(cred_hash1, creator_address1, video_hash1)

        # Issue second credential
        cred_hash2 = self.create_test_hash("credential_2")
        creator_address2 = arc4.Address(context.any_account())
        video_hash2 = self.create_test_hash("https://youtube.com/watch?v=video2")

        with context.txn.create_application_call(sender=context.default_sender):
            result2 = contract.issue_credential(cred_hash2, creator_address2, video_hash2)

        # Check results
        assert "Credential issued with ID: 1" in result1.native
        assert "Credential issued with ID: 2" in result2.native
        assert contract.get_total_credentials().native == 2

    def test_verify_credential_exists(self, context: AlgopyTestContext, contract: RealityCheckContract):
        """Test verifying an existing credential"""
        # Issue a credential first
        cred_hash = self.create_test_hash("test_credential")
        creator_address = arc4.Address(context.default_sender)
        video_hash = self.create_test_hash("https://youtube.com/watch?v=test")

        with context.txn.create_application_call(sender=context.default_sender):
            contract.issue_credential(cred_hash, creator_address, video_hash)

        # Verify the credential
        verification_result = contract.verify_credential(arc4.UInt64(1))

        # Unpack the tuple
        exists, is_revoked, returned_hash, returned_creator, returned_video, timestamp = verification_result.native

        # Check verification results
        assert exists == True
        assert is_revoked == False
        assert returned_hash == cred_hash.bytes
        assert returned_creator == creator_address.bytes
        assert returned_video == video_hash.bytes
        assert timestamp > 0

    def test_verify_credential_not_exists(self, context: AlgopyTestContext, contract: RealityCheckContract):
        """Test verifying a non-existent credential"""
        # Verify non-existent credential
        verification_result = contract.verify_credential(arc4.UInt64(999))

        # Unpack the tuple
        exists, is_revoked, returned_hash, returned_creator, returned_video, timestamp = verification_result.native

        # Check verification results
        assert exists == False
        assert is_revoked == False  # Meaningless when doesn't exist
        assert timestamp == 0

    def test_revoke_credential_success(self, context: AlgopyTestContext, contract: RealityCheckContract):
        """Test successful credential revocation"""
        # Issue a credential first
        cred_hash = self.create_test_hash("test_credential")
        creator_address = arc4.Address(context.default_sender)
        video_hash = self.create_test_hash("https://youtube.com/watch?v=test")

        with context.txn.create_application_call(sender=context.default_sender):
            contract.issue_credential(cred_hash, creator_address, video_hash)

        # Revoke the credential
        with context.txn.create_application_call(sender=context.default_sender):
            result = contract.revoke_credential(arc4.UInt64(1))

        # Check result
        assert "Credential 1 revoked successfully" in result.native

        # Verify credential is now revoked
        verification_result = contract.verify_credential(arc4.UInt64(1))
        exists, is_revoked, _, _, _, _ = verification_result.native

        assert exists == True
        assert is_revoked == True

    def test_revoke_credential_unauthorized(self, context: AlgopyTestContext, contract: RealityCheckContract):
        """Test that only issuer can revoke credentials"""
        # Issue a credential first
        cred_hash = self.create_test_hash("test_credential")
        creator_address = arc4.Address(context.default_sender)
        video_hash = self.create_test_hash("https://youtube.com/watch?v=test")

        with context.txn.create_application_call(sender=context.default_sender):
            contract.issue_credential(cred_hash, creator_address, video_hash)

        # Try to revoke from unauthorized account
        unauthorized_sender = context.any_account()

        with context.txn.create_application_call(sender=unauthorized_sender):
            with pytest.raises(Exception, match="Only issuer can revoke credentials"):
                contract.revoke_credential(arc4.UInt64(1))

    def test_revoke_nonexistent_credential(self, context: AlgopyTestContext, contract: RealityCheckContract):
        """Test revoking a non-existent credential"""
        with context.txn.create_application_call(sender=context.default_sender):
            with pytest.raises(Exception, match="Credential does not exist"):
                contract.revoke_credential(arc4.UInt64(999))

    def test_revoke_already_revoked_credential(self, context: AlgopyTestContext, contract: RealityCheckContract):
        """Test revoking an already revoked credential"""
        # Issue and revoke a credential
        cred_hash = self.create_test_hash("test_credential")
        creator_address = arc4.Address(context.default_sender)
        video_hash = self.create_test_hash("https://youtube.com/watch?v=test")

        with context.txn.create_application_call(sender=context.default_sender):
            contract.issue_credential(cred_hash, creator_address, video_hash)

        with context.txn.create_application_call(sender=context.default_sender):
            contract.revoke_credential(arc4.UInt64(1))

        # Try to revoke again
        with context.txn.create_application_call(sender=context.default_sender):
            with pytest.raises(Exception, match="Credential already revoked"):
                contract.revoke_credential(arc4.UInt64(1))

    def test_verify_by_hash_valid(self, context: AlgopyTestContext, contract: RealityCheckContract):
        """Test verifying credential by hash - valid case"""
        # Issue a credential
        cred_hash = self.create_test_hash("unique_credential")
        creator_address = arc4.Address(context.default_sender)
        video_hash = self.create_test_hash("https://youtube.com/watch?v=unique")

        with context.txn.create_application_call(sender=context.default_sender):
            contract.issue_credential(cred_hash, creator_address, video_hash)

        # Verify by hash
        result = contract.verify_by_hash(cred_hash)
        is_valid, credential_id = result.native

        assert is_valid == True
        assert credential_id == 1

    def test_verify_by_hash_invalid(self, context: AlgopyTestContext, contract: RealityCheckContract):
        """Test verifying credential by hash - invalid case"""
        # Try to verify non-existent hash
        fake_hash = self.create_test_hash("non_existent_credential")

        result = contract.verify_by_hash(fake_hash)
        is_valid, credential_id = result.native

        assert is_valid == False
        assert credential_id == 0

    def test_verify_by_hash_revoked(self, context: AlgopyTestContext, contract: RealityCheckContract):
        """Test verifying revoked credential by hash"""
        # Issue and revoke a credential
        cred_hash = self.create_test_hash("revoked_credential")
        creator_address = arc4.Address(context.default_sender)
        video_hash = self.create_test_hash("https://youtube.com/watch?v=revoked")

        with context.txn.create_application_call(sender=context.default_sender):
            contract.issue_credential(cred_hash, creator_address, video_hash)

        with context.txn.create_application_call(sender=context.default_sender):
            contract.revoke_credential(arc4.UInt64(1))

        # Verify by hash (should be invalid since revoked)
        result = contract.verify_by_hash(cred_hash)
        is_valid, credential_id = result.native

        assert is_valid == False
        assert credential_id == 1  # ID is returned but validity is False

    def test_full_workflow(self, context: AlgopyTestContext, contract: RealityCheckContract):
        """Test complete workflow: issue, verify, revoke, verify again"""
        # 1. Issue credential
        cred_hash = self.create_test_hash("workflow_test_credential")
        creator_address = arc4.Address(context.default_sender)
        video_hash = self.create_test_hash("https://youtube.com/watch?v=workflow")

        with context.txn.create_application_call(sender=context.default_sender):
            issue_result = contract.issue_credential(cred_hash, creator_address, video_hash)

        assert "Credential issued with ID: 1" in issue_result.native

        # 2. Verify credential exists and is valid
        verification1 = contract.verify_credential(arc4.UInt64(1))
        exists1, is_revoked1, _, _, _, _ = verification1.native

        assert exists1 == True
        assert is_revoked1 == False

        # 3. Verify by hash
        hash_verify1 = contract.verify_by_hash(cred_hash)
        is_valid1, cred_id1 = hash_verify1.native

        assert is_valid1 == True
        assert cred_id1 == 1

        # 4. Revoke credential
        with context.txn.create_application_call(sender=context.default_sender):
            revoke_result = contract.revoke_credential(arc4.UInt64(1))

        assert "Credential 1 revoked successfully" in revoke_result.native

        # 5. Verify credential is now revoked
        verification2 = contract.verify_credential(arc4.UInt64(1))
        exists2, is_revoked2, _, _, _, _ = verification2.native

        assert exists2 == True
        assert is_revoked2 == True

        # 6. Verify by hash should now be invalid
        hash_verify2 = contract.verify_by_hash(cred_hash)
        is_valid2, cred_id2 = hash_verify2.native

        assert is_valid2 == False
        assert cred_id2 == 1
