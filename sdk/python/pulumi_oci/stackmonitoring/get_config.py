# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetConfigResult',
    'AwaitableGetConfigResult',
    'get_config',
    'get_config_output',
]

@pulumi.output_type
class GetConfigResult:
    """
    A collection of values returned by getConfig.
    """
    def __init__(__self__, compartment_id=None, config_id=None, config_type=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, is_enabled=None, resource_type=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if config_id and not isinstance(config_id, str):
            raise TypeError("Expected argument 'config_id' to be a str")
        pulumi.set(__self__, "config_id", config_id)
        if config_type and not isinstance(config_type, str):
            raise TypeError("Expected argument 'config_type' to be a str")
        pulumi.set(__self__, "config_type", config_type)
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
        if resource_type and not isinstance(resource_type, str):
            raise TypeError("Expected argument 'resource_type' to be a str")
        pulumi.set(__self__, "resource_type", resource_type)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment containing the configuration.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="configId")
    def config_id(self) -> str:
        return pulumi.get(self, "config_id")

    @property
    @pulumi.getter(name="configType")
    def config_type(self) -> str:
        """
        The type of configuration.
        """
        return pulumi.get(self, "config_type")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The Unique Oracle ID (OCID) that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isEnabled")
    def is_enabled(self) -> bool:
        """
        True if automatic promotion is enabled, false if it is not enabled.
        """
        return pulumi.get(self, "is_enabled")

    @property
    @pulumi.getter(name="resourceType")
    def resource_type(self) -> str:
        """
        The type of resource to configure for automatic promotion.
        """
        return pulumi.get(self, "resource_type")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the configuration.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the configuration was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the Config was updated.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetConfigResult(GetConfigResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetConfigResult(
            compartment_id=self.compartment_id,
            config_id=self.config_id,
            config_type=self.config_type,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_enabled=self.is_enabled,
            resource_type=self.resource_type,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_config(config_id: Optional[str] = None,
               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetConfigResult:
    """
    This data source provides details about a specific Config resource in Oracle Cloud Infrastructure Stack Monitoring service.

    Gets the details of a configuration.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_config = oci.StackMonitoring.get_config(config_id=oci_stack_monitoring_config["test_config"]["id"])
    ```


    :param str config_id: Unique Config identifier.
    """
    __args__ = dict()
    __args__['configId'] = config_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:StackMonitoring/getConfig:getConfig', __args__, opts=opts, typ=GetConfigResult).value

    return AwaitableGetConfigResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        config_id=pulumi.get(__ret__, 'config_id'),
        config_type=pulumi.get(__ret__, 'config_type'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        is_enabled=pulumi.get(__ret__, 'is_enabled'),
        resource_type=pulumi.get(__ret__, 'resource_type'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))


@_utilities.lift_output_func(get_config)
def get_config_output(config_id: Optional[pulumi.Input[str]] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetConfigResult]:
    """
    This data source provides details about a specific Config resource in Oracle Cloud Infrastructure Stack Monitoring service.

    Gets the details of a configuration.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_config = oci.StackMonitoring.get_config(config_id=oci_stack_monitoring_config["test_config"]["id"])
    ```


    :param str config_id: Unique Config identifier.
    """
    ...