from unittest import TestCase, mock
from unittest import main as unittest_main
from unittest.mock import patch

from bank import make_pinned_ssl_context

class PinnedSSLTest(TestCase):
    @patch("ssl.SSLSocket.getpeercert")
    def test_those_works_if_we_create_2_contexts_with_2_different_certificates(self, mocked_getpeercert):
        context_a = make_pinned_ssl_context("d711a9468e2c4ee6ab4ea244afff8e24b8e8fdd2bdcfc98ce6e5bb9d43e17844")
        context_b = make_pinned_ssl_context("960284fdd51e3651b8ae998cfc82ed2104ee306d3f8ca2f066c4a7b76a47430f")
        mocked_getpeercert.return_value = b"checksum_a"
        context_a.sslsocket_class.check_pinned_cert(context_a.sslsocket_class)
        mocked_getpeercert.return_value = b"checksum_b"
        with self.assertRaises(Exception) as e:
            context_a.sslsocket_class.check_pinned_cert(context_a.sslsocket_class)
        self.assertEqual(e.exception.args, ("Incorrect certificate checksum",))
        mocked_getpeercert.return_value = b"checksum_b"
        context_b.sslsocket_class.check_pinned_cert(context_b.sslsocket_class)
        mocked_getpeercert.return_value = b"checksum_a"
        with self.assertRaises(Exception) as e:
            context_b.sslsocket_class.check_pinned_cert(context_b.sslsocket_class)
        self.assertEqual(e.exception.args, ("Incorrect certificate checksum",))

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
