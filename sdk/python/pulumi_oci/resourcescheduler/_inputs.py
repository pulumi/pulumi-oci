# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

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
    'ScheduleResourceArgs',
    'ScheduleResourceArgsDict',
    'ScheduleResourceFilterArgs',
    'ScheduleResourceFilterArgsDict',
    'ScheduleResourceFilterValueArgs',
    'ScheduleResourceFilterValueArgsDict',
    'GetSchedulesFilterArgs',
    'GetSchedulesFilterArgsDict',
]

MYPY = False

if not MYPY:
    class ScheduleResourceArgsDict(TypedDict):
        id: pulumi.Input[str]
        """
        (Updatable) This is the resource OCID.
        """
        metadata: NotRequired[pulumi.Input[Mapping[str, pulumi.Input[str]]]]
        """
        (Updatable) This is additional information that helps to identity the resource for the schedule.

        { "id": "<OCID_of_bucket>" "metadata": { "namespaceName": "sampleNamespace", "bucketName": "sampleBucket" } }
        """
elif False:
    ScheduleResourceArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class ScheduleResourceArgs:
    def __init__(__self__, *,
                 id: pulumi.Input[str],
                 metadata: Optional[pulumi.Input[Mapping[str, pulumi.Input[str]]]] = None):
        """
        :param pulumi.Input[str] id: (Updatable) This is the resource OCID.
        :param pulumi.Input[Mapping[str, pulumi.Input[str]]] metadata: (Updatable) This is additional information that helps to identity the resource for the schedule.
               
               { "id": "<OCID_of_bucket>" "metadata": { "namespaceName": "sampleNamespace", "bucketName": "sampleBucket" } }
        """
        pulumi.set(__self__, "id", id)
        if metadata is not None:
            pulumi.set(__self__, "metadata", metadata)

    @property
    @pulumi.getter
    def id(self) -> pulumi.Input[str]:
        """
        (Updatable) This is the resource OCID.
        """
        return pulumi.get(self, "id")

    @id.setter
    def id(self, value: pulumi.Input[str]):
        pulumi.set(self, "id", value)

    @property
    @pulumi.getter
    def metadata(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[str]]]]:
        """
        (Updatable) This is additional information that helps to identity the resource for the schedule.

        { "id": "<OCID_of_bucket>" "metadata": { "namespaceName": "sampleNamespace", "bucketName": "sampleBucket" } }
        """
        return pulumi.get(self, "metadata")

    @metadata.setter
    def metadata(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[str]]]]):
        pulumi.set(self, "metadata", value)


if not MYPY:
    class ScheduleResourceFilterArgsDict(TypedDict):
        attribute: pulumi.Input[str]
        """
        (Updatable) This is the resource attribute on which the threshold is defined.
        """
        condition: NotRequired[pulumi.Input[str]]
        """
        (Updatable) This is the condition for the filter in comparison to its creation time.
        """
        should_include_child_compartments: NotRequired[pulumi.Input[bool]]
        """
        (Updatable) This sets whether to include child compartments.
        """
        values: NotRequired[pulumi.Input[Sequence[pulumi.Input['ScheduleResourceFilterValueArgsDict']]]]
        """
        (Updatable) This is a collection of resource lifecycle state values.
        """
elif False:
    ScheduleResourceFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class ScheduleResourceFilterArgs:
    def __init__(__self__, *,
                 attribute: pulumi.Input[str],
                 condition: Optional[pulumi.Input[str]] = None,
                 should_include_child_compartments: Optional[pulumi.Input[bool]] = None,
                 values: Optional[pulumi.Input[Sequence[pulumi.Input['ScheduleResourceFilterValueArgs']]]] = None):
        """
        :param pulumi.Input[str] attribute: (Updatable) This is the resource attribute on which the threshold is defined.
        :param pulumi.Input[str] condition: (Updatable) This is the condition for the filter in comparison to its creation time.
        :param pulumi.Input[bool] should_include_child_compartments: (Updatable) This sets whether to include child compartments.
        :param pulumi.Input[Sequence[pulumi.Input['ScheduleResourceFilterValueArgs']]] values: (Updatable) This is a collection of resource lifecycle state values.
        """
        pulumi.set(__self__, "attribute", attribute)
        if condition is not None:
            pulumi.set(__self__, "condition", condition)
        if should_include_child_compartments is not None:
            pulumi.set(__self__, "should_include_child_compartments", should_include_child_compartments)
        if values is not None:
            pulumi.set(__self__, "values", values)

    @property
    @pulumi.getter
    def attribute(self) -> pulumi.Input[str]:
        """
        (Updatable) This is the resource attribute on which the threshold is defined.
        """
        return pulumi.get(self, "attribute")

    @attribute.setter
    def attribute(self, value: pulumi.Input[str]):
        pulumi.set(self, "attribute", value)

    @property
    @pulumi.getter
    def condition(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) This is the condition for the filter in comparison to its creation time.
        """
        return pulumi.get(self, "condition")

    @condition.setter
    def condition(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "condition", value)

    @property
    @pulumi.getter(name="shouldIncludeChildCompartments")
    def should_include_child_compartments(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) This sets whether to include child compartments.
        """
        return pulumi.get(self, "should_include_child_compartments")

    @should_include_child_compartments.setter
    def should_include_child_compartments(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "should_include_child_compartments", value)

    @property
    @pulumi.getter
    def values(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ScheduleResourceFilterValueArgs']]]]:
        """
        (Updatable) This is a collection of resource lifecycle state values.
        """
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ScheduleResourceFilterValueArgs']]]]):
        pulumi.set(self, "values", value)


if not MYPY:
    class ScheduleResourceFilterValueArgsDict(TypedDict):
        namespace: NotRequired[pulumi.Input[str]]
        """
        (Updatable) This is the namespace of the defined tag.
        """
        tag_key: NotRequired[pulumi.Input[str]]
        """
        (Updatable) This is the key of the defined tag.
        """
        value: NotRequired[pulumi.Input[str]]
        """
        (Updatable) This is the value of the defined tag.
        """
elif False:
    ScheduleResourceFilterValueArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class ScheduleResourceFilterValueArgs:
    def __init__(__self__, *,
                 namespace: Optional[pulumi.Input[str]] = None,
                 tag_key: Optional[pulumi.Input[str]] = None,
                 value: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] namespace: (Updatable) This is the namespace of the defined tag.
        :param pulumi.Input[str] tag_key: (Updatable) This is the key of the defined tag.
        :param pulumi.Input[str] value: (Updatable) This is the value of the defined tag.
        """
        if namespace is not None:
            pulumi.set(__self__, "namespace", namespace)
        if tag_key is not None:
            pulumi.set(__self__, "tag_key", tag_key)
        if value is not None:
            pulumi.set(__self__, "value", value)

    @property
    @pulumi.getter
    def namespace(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) This is the namespace of the defined tag.
        """
        return pulumi.get(self, "namespace")

    @namespace.setter
    def namespace(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "namespace", value)

    @property
    @pulumi.getter(name="tagKey")
    def tag_key(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) This is the key of the defined tag.
        """
        return pulumi.get(self, "tag_key")

    @tag_key.setter
    def tag_key(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "tag_key", value)

    @property
    @pulumi.getter
    def value(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) This is the value of the defined tag.
        """
        return pulumi.get(self, "value")

    @value.setter
    def value(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "value", value)


if not MYPY:
    class GetSchedulesFilterArgsDict(TypedDict):
        name: str
        values: Sequence[str]
        regex: NotRequired[bool]
elif False:
    GetSchedulesFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetSchedulesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


