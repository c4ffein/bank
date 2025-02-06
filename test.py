from unittest import TestCase
from unittest import main as unittest_main

class PinnedSSLTest(TestCase):
    pass
    # TODO : UT to ensure the checks are called for any python version
    # TODO : UT to ensure those works if we create 2 contexts with 2 different certificatesa
    # TODO : UT to ensure check is called if already opened socket gets wrapped
    # TODO : UT to ensure check is called if connecting on new socket
    # TODO : Ensure called with correct params, so that regular verif, and so getpeercert is enough


class BankTest(TestCase):
    def test_bad(self):
        raise("TODO")


if __name__ == "__main__":
    unittest_main()
