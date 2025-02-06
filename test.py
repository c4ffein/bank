from unittest import TestCase
from unittest import main as unittest_main


class PinnedSSLTest(TestCase):
    def test_the_checks_are_called_for_any_python_version(self):
        raise Exception("TODO")

    def test_those_works_if_we_create_2_contexts_with_2_different_certificates(self):
        raise Exception("TODO")

    def test_check_is_called_if_already_opened_socket_gets_wrapped(self):
        raise Exception("TODO")

    def test_check_is_called_if_connecting_on_new_socket(self):
        raise Exception("TODO")

    def test_called_with_correct_params_so_that_regular_verif_and_so_getpeercert_is_enough(self):
        raise Exception("TODO")


class BankTest(TestCase):
    def test_bad(self):
        raise Exception("TODO")


if __name__ == "__main__":
    unittest_main()
