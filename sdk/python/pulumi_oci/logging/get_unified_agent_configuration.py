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
    'GetUnifiedAgentConfigurationResult',
    'AwaitableGetUnifiedAgentConfigurationResult',
    'get_unified_agent_configuration',
    'get_unified_agent_configuration_output',
]

@pulumi.output_type
class GetUnifiedAgentConfigurationResult:
    """
    A collection of values returned by getUnifiedAgentConfiguration.
    """
    def __init__(__self__, compartment_id=None, configuration_state=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, group_associations=None, id=None, is_enabled=None, service_configurations=None, state=None, time_created=None, time_last_modified=None, unified_agent_configuration_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if configuration_state and not isinstance(configuration_state, str):
            raise TypeError("Expected argument 'configuration_state' to be a str")
        pulumi.set(__self__, "configuration_state", configuration_state)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if group_associations and not isinstance(group_associations, list):
            raise TypeError("Expected argument 'group_associations' to be a list")
        pulumi.set(__self__, "group_associations", group_associations)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_enabled and not isinstance(is_enabled, bool):
            raise TypeError("Expected argument 'is_enabled' to be a bool")
        pulumi.set(__self__, "is_enabled", is_enabled)
        if service_configurations and not isinstance(service_configurations, list):
            raise TypeError("Expected argument 'service_configurations' to be a list")
        pulumi.set(__self__, "service_configurations", service_configurations)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_last_modified and not isinstance(time_last_modified, str):
            raise TypeError("Expected argument 'time_last_modified' to be a str")
        pulumi.set(__self__, "time_last_modified", time_last_modified)
        if unified_agent_configuration_id and not isinstance(unified_agent_configuration_id, str):
            raise TypeError("Expected argument 'unified_agent_configuration_id' to be a str")
        pulumi.set(__self__, "unified_agent_configuration_id", unified_agent_configuration_id)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment that the resource belongs to.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="configurationState")
    def configuration_state(self) -> _builtins.str:
        """
        State of unified agent service configuration.
        """
        return pulumi.get(self, "configuration_state")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        Description for this resource.
        """
        return pulumi.get(self, "description")

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
    @pulumi.getter(name="groupAssociations")
    def group_associations(self) -> Sequence['outputs.GetUnifiedAgentConfigurationGroupAssociationResult']:
        """
        Groups using the configuration.
        """
        return pulumi.get(self, "group_associations")

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
    @pulumi.getter(name="serviceConfigurations")
    def service_configurations(self) -> Sequence['outputs.GetUnifiedAgentConfigurationServiceConfigurationResult']:
        """
        Top level Unified Agent service configuration object.
        """
        return pulumi.get(self, "service_configurations")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The pipeline state.
        """
        return pulumi.get(self, "state")

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

    @_builtins.property
    @pulumi.getter(name="unifiedAgentConfigurationId")
    def unified_agent_configuration_id(self) -> _builtins.str:
        return pulumi.get(self, "unified_agent_configuration_id")


class AwaitableGetUnifiedAgentConfigurationResult(GetUnifiedAgentConfigurationResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetUnifiedAgentConfigurationResult(
            compartment_id=self.compartment_id,
            configuration_state=self.configuration_state,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            group_associations=self.group_associations,
            id=self.id,
            is_enabled=self.is_enabled,
            service_configurations=self.service_configurations,
            state=self.state,
            time_created=self.time_created,
            time_last_modified=self.time_last_modified,
            unified_agent_configuration_id=self.unified_agent_configuration_id)


def get_unified_agent_configuration(unified_agent_configuration_id: Optional[_builtins.str] = None,
                                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetUnifiedAgentConfigurationResult:
    """
    This data source provides details about a specific Unified Agent Configuration resource in Oracle Cloud Infrastructure Logging service.

    Get the unified agent configuration for an ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_unified_agent_configuration = oci.Logging.get_unified_agent_configuration(unified_agent_configuration_id=test_unified_agent_configuration_oci_logging_unified_agent_configuration["id"])
    ```


    :param _builtins.str unified_agent_configuration_id: The OCID of the Unified Agent configuration.
    """
    __args__ = dict()
    __args__['unifiedAgentConfigurationId'] = unified_agent_configuration_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Logging/getUnifiedAgentConfiguration:getUnifiedAgentConfiguration', __args__, opts=opts, typ=GetUnifiedAgentConfigurationResult).value

    return AwaitableGetUnifiedAgentConfigurationResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        configuration_state=pulumi.get(__ret__, 'configuration_state'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        group_associations=pulumi.get(__ret__, 'group_associations'),
        id=pulumi.get(__ret__, 'id'),
        is_enabled=pulumi.get(__ret__, 'is_enabled'),
        service_configurations=pulumi.get(__ret__, 'service_configurations'),
        state=pulumi.get(__ret__, 'state'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_last_modified=pulumi.get(__ret__, 'time_last_modified'),
        unified_agent_configuration_id=pulumi.get(__ret__, 'unified_agent_configuration_id'))
def get_unified_agent_configuration_output(unified_agent_configuration_id: Optional[pulumi.Input[_builtins.str]] = None,
                                           opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetUnifiedAgentConfigurationResult]:
    """
    This data source provides details about a specific Unified Agent Configuration resource in Oracle Cloud Infrastructure Logging service.

    Get the unified agent configuration for an ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_unified_agent_configuration = oci.Logging.get_unified_agent_configuration(unified_agent_configuration_id=test_unified_agent_configuration_oci_logging_unified_agent_configuration["id"])
    ```


    :param _builtins.str unified_agent_configuration_id: The OCID of the Unified Agent configuration.
    """
    __args__ = dict()
    __args__['unifiedAgentConfigurationId'] = unified_agent_configuration_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Logging/getUnifiedAgentConfiguration:getUnifiedAgentConfiguration', __args__, opts=opts, typ=GetUnifiedAgentConfigurationResult)
    return __ret__.apply(lambda __response__: GetUnifiedAgentConfigurationResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        configuration_state=pulumi.get(__response__, 'configuration_state'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        group_associations=pulumi.get(__response__, 'group_associations'),
        id=pulumi.get(__response__, 'id'),
        is_enabled=pulumi.get(__response__, 'is_enabled'),
        service_configurations=pulumi.get(__response__, 'service_configurations'),
        state=pulumi.get(__response__, 'state'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_last_modified=pulumi.get(__response__, 'time_last_modified'),
        unified_agent_configuration_id=pulumi.get(__response__, 'unified_agent_configuration_id')))
