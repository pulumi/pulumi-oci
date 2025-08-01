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
from ._inputs import *

__all__ = [
    'GetMediaWorkflowConfigurationsResult',
    'AwaitableGetMediaWorkflowConfigurationsResult',
    'get_media_workflow_configurations',
    'get_media_workflow_configurations_output',
]

@pulumi.output_type
class GetMediaWorkflowConfigurationsResult:
    """
    A collection of values returned by getMediaWorkflowConfigurations.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, id=None, media_workflow_configuration_collections=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if media_workflow_configuration_collections and not isinstance(media_workflow_configuration_collections, list):
            raise TypeError("Expected argument 'media_workflow_configuration_collections' to be a list")
        pulumi.set(__self__, "media_workflow_configuration_collections", media_workflow_configuration_collections)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        """
        The compartment ID of the lock.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        Display name for the MediaWorkflowConfiguration. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetMediaWorkflowConfigurationsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> Optional[_builtins.str]:
        """
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="mediaWorkflowConfigurationCollections")
    def media_workflow_configuration_collections(self) -> Sequence['outputs.GetMediaWorkflowConfigurationsMediaWorkflowConfigurationCollectionResult']:
        """
        The list of media_workflow_configuration_collection.
        """
        return pulumi.get(self, "media_workflow_configuration_collections")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the MediaWorkflowConfiguration.
        """
        return pulumi.get(self, "state")


class AwaitableGetMediaWorkflowConfigurationsResult(GetMediaWorkflowConfigurationsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetMediaWorkflowConfigurationsResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            media_workflow_configuration_collections=self.media_workflow_configuration_collections,
            state=self.state)


def get_media_workflow_configurations(compartment_id: Optional[_builtins.str] = None,
                                      display_name: Optional[_builtins.str] = None,
                                      filters: Optional[Sequence[Union['GetMediaWorkflowConfigurationsFilterArgs', 'GetMediaWorkflowConfigurationsFilterArgsDict']]] = None,
                                      id: Optional[_builtins.str] = None,
                                      state: Optional[_builtins.str] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetMediaWorkflowConfigurationsResult:
    """
    This data source provides the list of Media Workflow Configurations in Oracle Cloud Infrastructure Media Services service.

    Returns a list of MediaWorkflowConfigurations.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_media_workflow_configurations = oci.MediaServices.get_media_workflow_configurations(compartment_id=compartment_id,
        display_name=media_workflow_configuration_display_name,
        id=media_workflow_configuration_id,
        state=media_workflow_configuration_state)
    ```


    :param _builtins.str compartment_id: The ID of the compartment in which to list resources.
    :param _builtins.str display_name: A filter to return only the resources that match the entire display name given.
    :param _builtins.str id: Unique MediaWorkflowConfiguration identifier.
    :param _builtins.str state: A filter to return only the resources with lifecycleState matching the given lifecycleState.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:MediaServices/getMediaWorkflowConfigurations:getMediaWorkflowConfigurations', __args__, opts=opts, typ=GetMediaWorkflowConfigurationsResult).value

    return AwaitableGetMediaWorkflowConfigurationsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        media_workflow_configuration_collections=pulumi.get(__ret__, 'media_workflow_configuration_collections'),
        state=pulumi.get(__ret__, 'state'))
def get_media_workflow_configurations_output(compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                             display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                             filters: Optional[pulumi.Input[Optional[Sequence[Union['GetMediaWorkflowConfigurationsFilterArgs', 'GetMediaWorkflowConfigurationsFilterArgsDict']]]]] = None,
                                             id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                             state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                             opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetMediaWorkflowConfigurationsResult]:
    """
    This data source provides the list of Media Workflow Configurations in Oracle Cloud Infrastructure Media Services service.

    Returns a list of MediaWorkflowConfigurations.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_media_workflow_configurations = oci.MediaServices.get_media_workflow_configurations(compartment_id=compartment_id,
        display_name=media_workflow_configuration_display_name,
        id=media_workflow_configuration_id,
        state=media_workflow_configuration_state)
    ```


    :param _builtins.str compartment_id: The ID of the compartment in which to list resources.
    :param _builtins.str display_name: A filter to return only the resources that match the entire display name given.
    :param _builtins.str id: Unique MediaWorkflowConfiguration identifier.
    :param _builtins.str state: A filter to return only the resources with lifecycleState matching the given lifecycleState.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:MediaServices/getMediaWorkflowConfigurations:getMediaWorkflowConfigurations', __args__, opts=opts, typ=GetMediaWorkflowConfigurationsResult)
    return __ret__.apply(lambda __response__: GetMediaWorkflowConfigurationsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        media_workflow_configuration_collections=pulumi.get(__response__, 'media_workflow_configuration_collections'),
        state=pulumi.get(__response__, 'state')))
