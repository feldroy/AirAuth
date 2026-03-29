"""Object-level permission management.

Four functions, same shape as django-guardian: assign, remove, query by perm, query by user.
"""

from .models import _GLOBAL, User, UserPermission


def _obj_filters(obj):
    if obj is not None:
        return {
            "object_type": obj.__class__._table_name(),
            "object_id": str(obj.id),
        }
    return {"object_type": _GLOBAL, "object_id": _GLOBAL}


async def assign_perm(perm: str, user: User, obj=None) -> UserPermission:
    """Grant a permission to a user, optionally on a specific object.

    Idempotent: if the permission already exists, returns it.
    """
    filters = {"user_id": user.id, "permission": perm, **_obj_filters(obj)}
    existing = await UserPermission.get(**filters)
    if existing:
        return existing
    return await UserPermission.create(**filters)


async def remove_perm(perm: str, user: User, obj=None) -> None:
    """Revoke a permission from a user."""
    await UserPermission.bulk_delete(
        user_id=user.id,
        permission=perm,
        **_obj_filters(obj),
    )


async def get_users_with_perm(perm: str, obj=None) -> list[User]:
    """Get all users who have a permission, optionally on a specific object."""
    perms = await UserPermission.filter(
        permission=perm,
        **_obj_filters(obj),
    )
    user_ids = [p.user_id for p in perms]
    if not user_ids:
        return []
    return await User.filter(id__in=user_ids)


async def get_objects_for_user(user: User, perm: str, model_class) -> list:
    """Get all objects of a model that a user has a permission on."""
    table_name = model_class._table_name()
    perms = await UserPermission.filter(
        user_id=user.id,
        permission=perm,
        object_type=table_name,
    )
    obj_ids = [int(p.object_id) for p in perms]
    if not obj_ids:
        return []
    return await model_class.filter(id__in=obj_ids)
