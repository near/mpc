# TODO(#1690): tests in this module are almost the same as the shared_cluster_tests. Eventually they should be unified
import pytest

# V2Secp256k1 has been removed from the DTO SignatureScheme enum.
# These tests need to be re-enabled once the DamgardEtAl protocol is surfaced via the KeyConfig DTO.
pytestmark = pytest.mark.skip(
    reason="V2Secp256k1 removed from DTO; re-enable when DamgardEtAl protocol is surfaced via KeyConfig DTO"
)
