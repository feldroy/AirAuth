"""Tests for permission management functions."""

from unittest.mock import AsyncMock, patch

from airauth.models import _GLOBAL, User, UserPermission
from airauth.permissions import assign_perm, get_objects_for_user, get_users_with_perm, remove_perm


def _make_user(id=1):
    return User(id=id, username="alice", email="a@b.com", password_hash="h")


async def test_assign_perm_creates_new():
    user = _make_user()
    fake_perm = UserPermission(id=1, user_id=1, permission="admin")
    with (
        patch.object(UserPermission, "get", new_callable=AsyncMock, return_value=None),
        patch.object(UserPermission, "create", new_callable=AsyncMock, return_value=fake_perm) as mock_create,
    ):
        result = await assign_perm("admin", user)
        assert result is fake_perm
        mock_create.assert_called_once_with(user_id=1, permission="admin", object_type=_GLOBAL, object_id=_GLOBAL)


async def test_assign_perm_idempotent():
    user = _make_user()
    existing = UserPermission(id=1, user_id=1, permission="admin")
    with (
        patch.object(UserPermission, "get", new_callable=AsyncMock, return_value=existing),
        patch.object(UserPermission, "create", new_callable=AsyncMock) as mock_create,
    ):
        result = await assign_perm("admin", user)
        assert result is existing
        mock_create.assert_not_called()


async def test_remove_perm():
    user = _make_user()
    with patch.object(UserPermission, "bulk_delete", new_callable=AsyncMock) as mock_delete:
        await remove_perm("admin", user)
        mock_delete.assert_called_once_with(user_id=1, permission="admin", object_type=_GLOBAL, object_id=_GLOBAL)


async def test_get_users_with_perm():
    perm1 = UserPermission(id=1, user_id=1, permission="admin")
    perm2 = UserPermission(id=2, user_id=2, permission="admin")
    users = [_make_user(1), _make_user(2)]
    with (
        patch.object(UserPermission, "filter", new_callable=AsyncMock, return_value=[perm1, perm2]),
        patch.object(User, "filter", new_callable=AsyncMock, return_value=users) as mock_user_filter,
    ):
        result = await get_users_with_perm("admin")
        assert result == users
        mock_user_filter.assert_called_once_with(id__in=[1, 2])


async def test_get_users_with_perm_empty():
    with patch.object(UserPermission, "filter", new_callable=AsyncMock, return_value=[]):
        result = await get_users_with_perm("admin")
        assert result == []


async def test_get_objects_for_user():
    user = _make_user()
    perm1 = UserPermission(id=1, user_id=1, permission="edit", object_type="app_post", object_id="10")
    perm2 = UserPermission(id=2, user_id=1, permission="edit", object_type="app_post", object_id="20")

    mock_model = AsyncMock()
    mock_model._table_name.return_value = "app_post"
    mock_model.filter = AsyncMock(return_value=["post10", "post20"])

    with patch.object(UserPermission, "filter", new_callable=AsyncMock, return_value=[perm1, perm2]):
        result = await get_objects_for_user(user, "edit", mock_model)
        assert result == ["post10", "post20"]
        mock_model.filter.assert_called_once_with(id__in=[10, 20])


async def test_get_objects_for_user_empty():
    user = _make_user()
    mock_model = AsyncMock()
    mock_model._table_name.return_value = "app_post"

    with patch.object(UserPermission, "filter", new_callable=AsyncMock, return_value=[]):
        result = await get_objects_for_user(user, "edit", mock_model)
        assert result == []
