# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetFusionEnvironmentsResult',
    'AwaitableGetFusionEnvironmentsResult',
    'get_fusion_environments',
    'get_fusion_environments_output',
]

@pulumi.output_type
class GetFusionEnvironmentsResult:
    """
    A collection of values returned by getFusionEnvironments.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, fusion_environment_collections=None, fusion_environment_family_id=None, id=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if fusion_environment_collections and not isinstance(fusion_environment_collections, list):
            raise TypeError("Expected argument 'fusion_environment_collections' to be a list")
        pulumi.set(__self__, "fusion_environment_collections", fusion_environment_collections)
        if fusion_environment_family_id and not isinstance(fusion_environment_family_id, str):
            raise TypeError("Expected argument 'fusion_environment_family_id' to be a str")
        pulumi.set(__self__, "fusion_environment_family_id", fusion_environment_family_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        Compartment Identifier
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        FusionEnvironment Identifier, can be renamed
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetFusionEnvironmentsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter(name="fusionEnvironmentCollections")
    def fusion_environment_collections(self) -> Sequence['outputs.GetFusionEnvironmentsFusionEnvironmentCollectionResult']:
        """
        The list of fusion_environment_collection.
        """
        return pulumi.get(self, "fusion_environment_collections")

    @property
    @pulumi.getter(name="fusionEnvironmentFamilyId")
    def fusion_environment_family_id(self) -> Optional[str]:
        """
        FusionEnvironmentFamily Identifier
        """
        return pulumi.get(self, "fusion_environment_family_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the ServiceInstance.
        """
        return pulumi.get(self, "state")


class AwaitableGetFusionEnvironmentsResult(GetFusionEnvironmentsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetFusionEnvironmentsResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            fusion_environment_collections=self.fusion_environment_collections,
            fusion_environment_family_id=self.fusion_environment_family_id,
            id=self.id,
            state=self.state)


def get_fusion_environments(compartment_id: Optional[str] = None,
                            display_name: Optional[str] = None,
                            filters: Optional[Sequence[pulumi.InputType['GetFusionEnvironmentsFilterArgs']]] = None,
                            fusion_environment_family_id: Optional[str] = None,
                            state: Optional[str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetFusionEnvironmentsResult:
    """
    This data source provides the list of Fusion Environments in Oracle Cloud Infrastructure Fusion Apps service.

    Returns a list of FusionEnvironments.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fusion_environments = oci.Functions.get_fusion_environments(compartment_id=var["compartment_id"],
        display_name=var["fusion_environment_display_name"],
        fusion_environment_family_id=oci_fusion_apps_fusion_environment_family["test_fusion_environment_family"]["id"],
        state=var["fusion_environment_state"])
    ```


    :param str compartment_id: The ID of the compartment in which to list resources.
    :param str display_name: A filter to return only resources that match the entire display name given.
    :param str fusion_environment_family_id: The ID of the fusion environment family in which to list resources.
    :param str state: A filter that returns all resources that match the specified lifecycle state.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['fusionEnvironmentFamilyId'] = fusion_environment_family_id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Functions/getFusionEnvironments:getFusionEnvironments', __args__, opts=opts, typ=GetFusionEnvironmentsResult).value

    return AwaitableGetFusionEnvironmentsResult(
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        fusion_environment_collections=__ret__.fusion_environment_collections,
        fusion_environment_family_id=__ret__.fusion_environment_family_id,
        id=__ret__.id,
        state=__ret__.state)


@_utilities.lift_output_func(get_fusion_environments)
def get_fusion_environments_output(compartment_id: Optional[pulumi.Input[str]] = None,
                                   display_name: Optional[pulumi.Input[Optional[str]]] = None,
                                   filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetFusionEnvironmentsFilterArgs']]]]] = None,
                                   fusion_environment_family_id: Optional[pulumi.Input[Optional[str]]] = None,
                                   state: Optional[pulumi.Input[Optional[str]]] = None,
                                   opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetFusionEnvironmentsResult]:
    """
    This data source provides the list of Fusion Environments in Oracle Cloud Infrastructure Fusion Apps service.

    Returns a list of FusionEnvironments.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fusion_environments = oci.Functions.get_fusion_environments(compartment_id=var["compartment_id"],
        display_name=var["fusion_environment_display_name"],
        fusion_environment_family_id=oci_fusion_apps_fusion_environment_family["test_fusion_environment_family"]["id"],
        state=var["fusion_environment_state"])
    ```


    :param str compartment_id: The ID of the compartment in which to list resources.
    :param str display_name: A filter to return only resources that match the entire display name given.
    :param str fusion_environment_family_id: The ID of the fusion environment family in which to list resources.
    :param str state: A filter that returns all resources that match the specified lifecycle state.
    """
    ...