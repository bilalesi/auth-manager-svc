"""Guard context managers for common validation patterns."""

from contextlib import contextmanager
from typing import Callable, Iterator, Type, TypeVar

from sqlalchemy.exc import NoResultFound

from app.core.exceptions import AuthManagerError

T = TypeVar("T")


@contextmanager
def raise_if_not_found_guard(
    exc: Exception,
) -> Iterator[None]:
    """Guard that raises error when database query returns no results.

    Args:
        error_message: Error message to raise
        error_code: Error code for the exception

    Yields:
        None

    Raises:
        Exception: If NoResultFound is raised

    """
    try:
        yield
    except NoResultFound as err:
        raise exc from err


@contextmanager
def invariant_guard(
    value: T,
    condition: Callable[[T], bool],
    exc: Exception,
) -> Iterator[T]:
    """
    Universal invariant guard with automatic type narrowing.

    Ensures `condition(value)` is False. If True, raises `exc`.
    Yields `value` with narrowed type if condition enables type inference.

    Args:
        value: Any object to guard
        condition: Callable that returns True if invariant is VIOLATED
        exc: Exception to raise on violation

    Yields:
        The original `value`, but type-narrowed in the `with` block

    Example:
        with invariant_guard(entry, lambda e: e.token is None, ValidationError(...)) as e:
            reveal_type(e.token)  # str, not Optional[str]
    """
    if condition(value):
        raise exc
    yield value


@contextmanager
def auth_error_guard(
    exc: Type[AuthManagerError] | None,
    error_message: str,
) -> Iterator[None]:
    """
    Wrap a block and re-raise any exception as the specified exception type.

    Args:
        exc: Exception class to raise (or None for generic AuthManagerError)

    Yields:
        None

    Raises:
        Exception
    """
    try:
        yield
    except AuthManagerError as ex:
        if exc:
            raise exc(error_message)
        raise AuthManagerError(
            message=ex.message or error_message,
            code=ex.code,
            details=ex.details,
        ) from ex
