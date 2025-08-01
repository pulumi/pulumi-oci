# coding=utf-8
# *** WARNING: this file was generated by pulumi-language-python. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import builtins as _builtins
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
    'OpaInstanceAttachmentArgs',
    'OpaInstanceAttachmentArgsDict',
    'GetOpaInstancesFilterArgs',
    'GetOpaInstancesFilterArgsDict',
]

MYPY = False

if not MYPY:
    class OpaInstanceAttachmentArgsDict(TypedDict):
        is_implicit: NotRequired[pulumi.Input[_builtins.bool]]
        """
        * If role == `PARENT`, the attached instance was created by this service instance
        * If role == `CHILD`, this instance was created from attached instance on behalf of a user
        """
        target_id: NotRequired[pulumi.Input[_builtins.str]]
        """
        The OCID of the target instance (which could be any other Oracle Cloud Infrastructure PaaS/SaaS resource), to which this instance is attached.
        """
        target_instance_url: NotRequired[pulumi.Input[_builtins.str]]
        """
        The dataplane instance URL of the attached instance
        """
        target_role: NotRequired[pulumi.Input[_builtins.str]]
        """
        The role of the target attachment. 
        * `PARENT` - The target instance is the parent of this attachment.
        * `CHILD` - The target instance is the child of this attachment.
        """
        target_service_type: NotRequired[pulumi.Input[_builtins.str]]
        """
        The type of the target instance, such as "FUSION".
        """
elif False:
    OpaInstanceAttachmentArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class OpaInstanceAttachmentArgs:
    def __init__(__self__, *,
                 is_implicit: Optional[pulumi.Input[_builtins.bool]] = None,
                 target_id: Optional[pulumi.Input[_builtins.str]] = None,
                 target_instance_url: Optional[pulumi.Input[_builtins.str]] = None,
                 target_role: Optional[pulumi.Input[_builtins.str]] = None,
                 target_service_type: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input[_builtins.bool] is_implicit: * If role == `PARENT`, the attached instance was created by this service instance
               * If role == `CHILD`, this instance was created from attached instance on behalf of a user
        :param pulumi.Input[_builtins.str] target_id: The OCID of the target instance (which could be any other Oracle Cloud Infrastructure PaaS/SaaS resource), to which this instance is attached.
        :param pulumi.Input[_builtins.str] target_instance_url: The dataplane instance URL of the attached instance
        :param pulumi.Input[_builtins.str] target_role: The role of the target attachment. 
               * `PARENT` - The target instance is the parent of this attachment.
               * `CHILD` - The target instance is the child of this attachment.
        :param pulumi.Input[_builtins.str] target_service_type: The type of the target instance, such as "FUSION".
        """
        if is_implicit is not None:
            pulumi.set(__self__, "is_implicit", is_implicit)
        if target_id is not None:
            pulumi.set(__self__, "target_id", target_id)
        if target_instance_url is not None:
            pulumi.set(__self__, "target_instance_url", target_instance_url)
        if target_role is not None:
            pulumi.set(__self__, "target_role", target_role)
        if target_service_type is not None:
            pulumi.set(__self__, "target_service_type", target_service_type)

    @_builtins.property
    @pulumi.getter(name="isImplicit")
    def is_implicit(self) -> Optional[pulumi.Input[_builtins.bool]]:
        """
        * If role == `PARENT`, the attached instance was created by this service instance
        * If role == `CHILD`, this instance was created from attached instance on behalf of a user
        """
        return pulumi.get(self, "is_implicit")

    @is_implicit.setter
    def is_implicit(self, value: Optional[pulumi.Input[_builtins.bool]]):
        pulumi.set(self, "is_implicit", value)

    @_builtins.property
    @pulumi.getter(name="targetId")
    def target_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The OCID of the target instance (which could be any other Oracle Cloud Infrastructure PaaS/SaaS resource), to which this instance is attached.
        """
        return pulumi.get(self, "target_id")

    @target_id.setter
    def target_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "target_id", value)

    @_builtins.property
    @pulumi.getter(name="targetInstanceUrl")
    def target_instance_url(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The dataplane instance URL of the attached instance
        """
        return pulumi.get(self, "target_instance_url")

    @target_instance_url.setter
    def target_instance_url(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "target_instance_url", value)

    @_builtins.property
    @pulumi.getter(name="targetRole")
    def target_role(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The role of the target attachment. 
        * `PARENT` - The target instance is the parent of this attachment.
        * `CHILD` - The target instance is the child of this attachment.
        """
        return pulumi.get(self, "target_role")

    @target_role.setter
    def target_role(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "target_role", value)

    @_builtins.property
    @pulumi.getter(name="targetServiceType")
    def target_service_type(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The type of the target instance, such as "FUSION".
        """
        return pulumi.get(self, "target_service_type")

    @target_service_type.setter
    def target_service_type(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "target_service_type", value)


if not MYPY:
    class GetOpaInstancesFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetOpaInstancesFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetOpaInstancesFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


