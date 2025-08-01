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
from . import outputs

__all__ = [
    'GetLogResult',
    'AwaitableGetLogResult',
    'get_log',
    'get_log_output',
]

@pulumi.output_type
class GetLogResult:
    """
    A collection of values returned by getLog.
    """
    def __init__(__self__, compartment_id=None, configurations=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, is_enabled=None, log_group_id=None, log_id=None, log_type=None, retention_duration=None, state=None, tenancy_id=None, time_created=None, time_last_modified=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if configurations and not isinstance(configurations, list):
            raise TypeError("Expected argument 'configurations' to be a list")
        pulumi.set(__self__, "configurations", configurations)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_enabled and not isinstance(is_enabled, bool):
            raise TypeError("Expected argument 'is_enabled' to be a bool")
        pulumi.set(__self__, "is_enabled", is_enabled)
        if log_group_id and not isinstance(log_group_id, str):
            raise TypeError("Expected argument 'log_group_id' to be a str")
        pulumi.set(__self__, "log_group_id", log_group_id)
        if log_id and not isinstance(log_id, str):
            raise TypeError("Expected argument 'log_id' to be a str")
        pulumi.set(__self__, "log_id", log_id)
        if log_type and not isinstance(log_type, str):
            raise TypeError("Expected argument 'log_type' to be a str")
        pulumi.set(__self__, "log_type", log_type)
        if retention_duration and not isinstance(retention_duration, int):
            raise TypeError("Expected argument 'retention_duration' to be a int")
        pulumi.set(__self__, "retention_duration", retention_duration)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if tenancy_id and not isinstance(tenancy_id, str):
            raise TypeError("Expected argument 'tenancy_id' to be a str")
        pulumi.set(__self__, "tenancy_id", tenancy_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_last_modified and not isinstance(time_last_modified, str):
            raise TypeError("Expected argument 'time_last_modified' to be a str")
        pulumi.set(__self__, "time_last_modified", time_last_modified)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment that the resource belongs to.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def configurations(self) -> Sequence['outputs.GetLogConfigurationResult']:
        """
        Log object configuration.
        """
        return pulumi.get(self, "configurations")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The OCID of the resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isEnabled")
    def is_enabled(self) -> _builtins.bool:
        """
        Whether or not this resource is currently enabled.
        """
        return pulumi.get(self, "is_enabled")

    @_builtins.property
    @pulumi.getter(name="logGroupId")
    def log_group_id(self) -> _builtins.str:
        """
        Log group OCID.
        """
        return pulumi.get(self, "log_group_id")

    @_builtins.property
    @pulumi.getter(name="logId")
    def log_id(self) -> _builtins.str:
        return pulumi.get(self, "log_id")

    @_builtins.property
    @pulumi.getter(name="logType")
    def log_type(self) -> _builtins.str:
        """
        The logType that the log object is for, whether custom or service.
        """
        return pulumi.get(self, "log_type")

    @_builtins.property
    @pulumi.getter(name="retentionDuration")
    def retention_duration(self) -> _builtins.int:
        """
        Log retention duration in 30-day increments (30, 60, 90 and so on until 180).
        """
        return pulumi.get(self, "retention_duration")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The pipeline state.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="tenancyId")
    def tenancy_id(self) -> _builtins.str:
        """
        The OCID of the tenancy.
        """
        return pulumi.get(self, "tenancy_id")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        Time the resource was created.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeLastModified")
    def time_last_modified(self) -> _builtins.str:
        """
        Time the resource was last modified.
        """
        return pulumi.get(self, "time_last_modified")


class AwaitableGetLogResult(GetLogResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetLogResult(
            compartment_id=self.compartment_id,
            configurations=self.configurations,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_enabled=self.is_enabled,
            log_group_id=self.log_group_id,
            log_id=self.log_id,
            log_type=self.log_type,
            retention_duration=self.retention_duration,
            state=self.state,
            tenancy_id=self.tenancy_id,
            time_created=self.time_created,
            time_last_modified=self.time_last_modified)


def get_log(log_group_id: Optional[_builtins.str] = None,
            log_id: Optional[_builtins.str] = None,
            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetLogResult:
    """
    This data source provides details about a specific Log resource in Oracle Cloud Infrastructure Logging service.

    Gets the log object configuration for the log object OCID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_log = oci.Logging.get_log(log_group_id=test_log_group["id"],
        log_id=test_log_oci_logging_log["id"])
    ```


    :param _builtins.str log_group_id: OCID of a log group to work with.
    :param _builtins.str log_id: OCID of a log to work with.
    """
    __args__ = dict()
    __args__['logGroupId'] = log_group_id
    __args__['logId'] = log_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Logging/getLog:getLog', __args__, opts=opts, typ=GetLogResult).value

    return AwaitableGetLogResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        configurations=pulumi.get(__ret__, 'configurations'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        is_enabled=pulumi.get(__ret__, 'is_enabled'),
        log_group_id=pulumi.get(__ret__, 'log_group_id'),
        log_id=pulumi.get(__ret__, 'log_id'),
        log_type=pulumi.get(__ret__, 'log_type'),
        retention_duration=pulumi.get(__ret__, 'retention_duration'),
        state=pulumi.get(__ret__, 'state'),
        tenancy_id=pulumi.get(__ret__, 'tenancy_id'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_last_modified=pulumi.get(__ret__, 'time_last_modified'))
def get_log_output(log_group_id: Optional[pulumi.Input[_builtins.str]] = None,
                   log_id: Optional[pulumi.Input[_builtins.str]] = None,
                   opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetLogResult]:
    """
    This data source provides details about a specific Log resource in Oracle Cloud Infrastructure Logging service.

    Gets the log object configuration for the log object OCID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_log = oci.Logging.get_log(log_group_id=test_log_group["id"],
        log_id=test_log_oci_logging_log["id"])
    ```


    :param _builtins.str log_group_id: OCID of a log group to work with.
    :param _builtins.str log_id: OCID of a log to work with.
    """
    __args__ = dict()
    __args__['logGroupId'] = log_group_id
    __args__['logId'] = log_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Logging/getLog:getLog', __args__, opts=opts, typ=GetLogResult)
    return __ret__.apply(lambda __response__: GetLogResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        configurations=pulumi.get(__response__, 'configurations'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        is_enabled=pulumi.get(__response__, 'is_enabled'),
        log_group_id=pulumi.get(__response__, 'log_group_id'),
        log_id=pulumi.get(__response__, 'log_id'),
        log_type=pulumi.get(__response__, 'log_type'),
        retention_duration=pulumi.get(__response__, 'retention_duration'),
        state=pulumi.get(__response__, 'state'),
        tenancy_id=pulumi.get(__response__, 'tenancy_id'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_last_modified=pulumi.get(__response__, 'time_last_modified')))
