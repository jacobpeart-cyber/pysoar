from src.core.config import Settings


def test_debug_accepts_release_environment_value():
    settings = Settings(debug="release")

    assert settings.debug is False


def test_debug_accepts_environment_names():
    assert Settings(debug="production").debug is False
    assert Settings(debug="development").debug is True
