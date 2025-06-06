# coding=utf-8
# *** WARNING: this file was generated by pulumi-language-python. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import builtins
import copy
import warnings
import sys
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
if sys.version_info >= (3, 11):
    from typing import NotRequired, TypedDict, TypeAlias
else:
    from typing_extensions import NotRequired, TypedDict, TypeAlias
from .. import _utilities

__all__ = [
    'FileStorageLustreFileSystemMaintenanceWindowArgs',
    'FileStorageLustreFileSystemMaintenanceWindowArgsDict',
    'FileStorageLustreFileSystemRootSquashConfigurationArgs',
    'FileStorageLustreFileSystemRootSquashConfigurationArgsDict',
    'GetFileStorageLustreFileSystemsFilterArgs',
    'GetFileStorageLustreFileSystemsFilterArgsDict',
]

MYPY = False

if not MYPY:
    class FileStorageLustreFileSystemMaintenanceWindowArgsDict(TypedDict):
        day_of_week: NotRequired[pulumi.Input[builtins.str]]
        """
        Day of the week when the maintainence window starts.
        """
        time_start: NotRequired[pulumi.Input[builtins.str]]
        """
        The time to start the maintenance window. The format is 'HH:MM', 'HH:MM' represents the time in UTC.   Example: `22:00`
        """
elif False:
    FileStorageLustreFileSystemMaintenanceWindowArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class FileStorageLustreFileSystemMaintenanceWindowArgs:
    def __init__(__self__, *,
                 day_of_week: Optional[pulumi.Input[builtins.str]] = None,
                 time_start: Optional[pulumi.Input[builtins.str]] = None):
        """
        :param pulumi.Input[builtins.str] day_of_week: Day of the week when the maintainence window starts.
        :param pulumi.Input[builtins.str] time_start: The time to start the maintenance window. The format is 'HH:MM', 'HH:MM' represents the time in UTC.   Example: `22:00`
        """
        if day_of_week is not None:
            pulumi.set(__self__, "day_of_week", day_of_week)
        if time_start is not None:
            pulumi.set(__self__, "time_start", time_start)

    @property
    @pulumi.getter(name="dayOfWeek")
    def day_of_week(self) -> Optional[pulumi.Input[builtins.str]]:
        """
        Day of the week when the maintainence window starts.
        """
        return pulumi.get(self, "day_of_week")

    @day_of_week.setter
    def day_of_week(self, value: Optional[pulumi.Input[builtins.str]]):
        pulumi.set(self, "day_of_week", value)

    @property
    @pulumi.getter(name="timeStart")
    def time_start(self) -> Optional[pulumi.Input[builtins.str]]:
        """
        The time to start the maintenance window. The format is 'HH:MM', 'HH:MM' represents the time in UTC.   Example: `22:00`
        """
        return pulumi.get(self, "time_start")

    @time_start.setter
    def time_start(self, value: Optional[pulumi.Input[builtins.str]]):
        pulumi.set(self, "time_start", value)


if not MYPY:
    class FileStorageLustreFileSystemRootSquashConfigurationArgsDict(TypedDict):
        client_exceptions: NotRequired[pulumi.Input[Sequence[pulumi.Input[builtins.str]]]]
        """
        (Updatable) A list of NIDs allowed with this lustre file system not to be squashed. A maximum of 10 is allowed.
        """
        identity_squash: NotRequired[pulumi.Input[builtins.str]]
        """
        (Updatable) Used when clients accessing the Lustre file system have their UID and GID remapped to `squashUid` and `squashGid`. If `ROOT`, only the root user and group (UID/GID 0) are remapped; if `NONE`, no remapping is done. If unspecified, defaults to `NONE`.
        """
        squash_gid: NotRequired[pulumi.Input[builtins.str]]
        """
        (Updatable) The GID value to remap to when squashing a client GID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
        """
        squash_uid: NotRequired[pulumi.Input[builtins.str]]
        """
        (Updatable) The UID value to remap to when squashing a client UID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
        """
elif False:
    FileStorageLustreFileSystemRootSquashConfigurationArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class FileStorageLustreFileSystemRootSquashConfigurationArgs:
    def __init__(__self__, *,
                 client_exceptions: Optional[pulumi.Input[Sequence[pulumi.Input[builtins.str]]]] = None,
                 identity_squash: Optional[pulumi.Input[builtins.str]] = None,
                 squash_gid: Optional[pulumi.Input[builtins.str]] = None,
                 squash_uid: Optional[pulumi.Input[builtins.str]] = None):
        """
        :param pulumi.Input[Sequence[pulumi.Input[builtins.str]]] client_exceptions: (Updatable) A list of NIDs allowed with this lustre file system not to be squashed. A maximum of 10 is allowed.
        :param pulumi.Input[builtins.str] identity_squash: (Updatable) Used when clients accessing the Lustre file system have their UID and GID remapped to `squashUid` and `squashGid`. If `ROOT`, only the root user and group (UID/GID 0) are remapped; if `NONE`, no remapping is done. If unspecified, defaults to `NONE`.
        :param pulumi.Input[builtins.str] squash_gid: (Updatable) The GID value to remap to when squashing a client GID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
        :param pulumi.Input[builtins.str] squash_uid: (Updatable) The UID value to remap to when squashing a client UID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
        """
        if client_exceptions is not None:
            pulumi.set(__self__, "client_exceptions", client_exceptions)
        if identity_squash is not None:
            pulumi.set(__self__, "identity_squash", identity_squash)
        if squash_gid is not None:
            pulumi.set(__self__, "squash_gid", squash_gid)
        if squash_uid is not None:
            pulumi.set(__self__, "squash_uid", squash_uid)

    @property
    @pulumi.getter(name="clientExceptions")
    def client_exceptions(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[builtins.str]]]]:
        """
        (Updatable) A list of NIDs allowed with this lustre file system not to be squashed. A maximum of 10 is allowed.
        """
        return pulumi.get(self, "client_exceptions")

    @client_exceptions.setter
    def client_exceptions(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[builtins.str]]]]):
        pulumi.set(self, "client_exceptions", value)

    @property
    @pulumi.getter(name="identitySquash")
    def identity_squash(self) -> Optional[pulumi.Input[builtins.str]]:
        """
        (Updatable) Used when clients accessing the Lustre file system have their UID and GID remapped to `squashUid` and `squashGid`. If `ROOT`, only the root user and group (UID/GID 0) are remapped; if `NONE`, no remapping is done. If unspecified, defaults to `NONE`.
        """
        return pulumi.get(self, "identity_squash")

    @identity_squash.setter
    def identity_squash(self, value: Optional[pulumi.Input[builtins.str]]):
        pulumi.set(self, "identity_squash", value)

    @property
    @pulumi.getter(name="squashGid")
    def squash_gid(self) -> Optional[pulumi.Input[builtins.str]]:
        """
        (Updatable) The GID value to remap to when squashing a client GID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
        """
        return pulumi.get(self, "squash_gid")

    @squash_gid.setter
    def squash_gid(self, value: Optional[pulumi.Input[builtins.str]]):
        pulumi.set(self, "squash_gid", value)

    @property
    @pulumi.getter(name="squashUid")
    def squash_uid(self) -> Optional[pulumi.Input[builtins.str]]:
        """
        (Updatable) The UID value to remap to when squashing a client UID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
        """
        return pulumi.get(self, "squash_uid")

    @squash_uid.setter
    def squash_uid(self, value: Optional[pulumi.Input[builtins.str]]):
        pulumi.set(self, "squash_uid", value)


if not MYPY:
    class GetFileStorageLustreFileSystemsFilterArgsDict(TypedDict):
        name: builtins.str
        values: Sequence[builtins.str]
        regex: NotRequired[builtins.bool]
elif False:
    GetFileStorageLustreFileSystemsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetFileStorageLustreFileSystemsFilterArgs:
    def __init__(__self__, *,
                 name: builtins.str,
                 values: Sequence[builtins.str],
                 regex: Optional[builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: builtins.str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[builtins.str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[builtins.bool]):
        pulumi.set(self, "regex", value)


