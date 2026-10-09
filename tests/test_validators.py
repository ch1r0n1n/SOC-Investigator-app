import pytest
from ronin.validators import classify_ioc


def test_ipv4():
    assert classify_ioc("8.8.8.8") == ("ipv4", "8.8.8.8")


def test_url_before_domain():
    assert classify_ioc("https://example.com/a")[0] == "url"


def test_domain():
    assert classify_ioc("Example.COM") == ("domain", "example.com")


def test_sha256():
    value = "a" * 64
    assert classify_ioc(value) == ("sha256", value)


def test_invalid_numeric_ip_is_not_domain():
    with pytest.raises(ValueError):
        classify_ioc("999.999.999.999")
