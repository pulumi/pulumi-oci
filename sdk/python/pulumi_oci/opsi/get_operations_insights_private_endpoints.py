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
    'GetOperationsInsightsPrivateEndpointsResult',
    'AwaitableGetOperationsInsightsPrivateEndpointsResult',
    'get_operations_insights_private_endpoints',
    'get_operations_insights_private_endpoints_output',
]

@pulumi.output_type
class GetOperationsInsightsPrivateEndpointsResult:
    """
    A collection of values returned by getOperationsInsightsPrivateEndpoints.
    """
    def __init__(__self__, compartment_id=None, compartment_id_in_subtree=None, display_name=None, filters=None, id=None, is_used_for_rac_dbs=None, operations_insights_private_endpoint_collections=None, opsi_private_endpoint_id=None, states=None, vcn_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compartment_id_in_subtree and not isinstance(compartment_id_in_subtree, bool):
            raise TypeError("Expected argument 'compartment_id_in_subtree' to be a bool")
        pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_used_for_rac_dbs and not isinstance(is_used_for_rac_dbs, bool):
            raise TypeError("Expected argument 'is_used_for_rac_dbs' to be a bool")
        pulumi.set(__self__, "is_used_for_rac_dbs", is_used_for_rac_dbs)
        if operations_insights_private_endpoint_collections and not isinstance(operations_insights_private_endpoint_collections, list):
            raise TypeError("Expected argument 'operations_insights_private_endpoint_collections' to be a list")
        pulumi.set(__self__, "operations_insights_private_endpoint_collections", operations_insights_private_endpoint_collections)
        if opsi_private_endpoint_id and not isinstance(opsi_private_endpoint_id, str):
            raise TypeError("Expected argument 'opsi_private_endpoint_id' to be a str")
        pulumi.set(__self__, "opsi_private_endpoint_id", opsi_private_endpoint_id)
        if states and not isinstance(states, list):
            raise TypeError("Expected argument 'states' to be a list")
        pulumi.set(__self__, "states", states)
        if vcn_id and not isinstance(vcn_id, str):
            raise TypeError("Expected argument 'vcn_id' to be a str")
        pulumi.set(__self__, "vcn_id", vcn_id)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        """
        The compartment OCID of the Private service accessed database.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        The display name of the private endpoint.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetOperationsInsightsPrivateEndpointsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isUsedForRacDbs")
    def is_used_for_rac_dbs(self) -> Optional[_builtins.bool]:
        """
        The flag is to identify if private endpoint is used for rac database or not. This flag is deprecated and no longer is used.
        """
        return pulumi.get(self, "is_used_for_rac_dbs")

    @_builtins.property
    @pulumi.getter(name="operationsInsightsPrivateEndpointCollections")
    def operations_insights_private_endpoint_collections(self) -> Sequence['outputs.GetOperationsInsightsPrivateEndpointsOperationsInsightsPrivateEndpointCollectionResult']:
        """
        The list of operations_insights_private_endpoint_collection.
        """
        return pulumi.get(self, "operations_insights_private_endpoint_collections")

    @_builtins.property
    @pulumi.getter(name="opsiPrivateEndpointId")
    def opsi_private_endpoint_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "opsi_private_endpoint_id")

    @_builtins.property
    @pulumi.getter
    def states(self) -> Optional[Sequence[_builtins.str]]:
        """
        The current state of the private endpoint.
        """
        return pulumi.get(self, "states")

    @_builtins.property
    @pulumi.getter(name="vcnId")
    def vcn_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the VCN.
        """
        return pulumi.get(self, "vcn_id")


class AwaitableGetOperationsInsightsPrivateEndpointsResult(GetOperationsInsightsPrivateEndpointsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetOperationsInsightsPrivateEndpointsResult(
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            is_used_for_rac_dbs=self.is_used_for_rac_dbs,
            operations_insights_private_endpoint_collections=self.operations_insights_private_endpoint_collections,
            opsi_private_endpoint_id=self.opsi_private_endpoint_id,
            states=self.states,
            vcn_id=self.vcn_id)


def get_operations_insights_private_endpoints(compartment_id: Optional[_builtins.str] = None,
                                              compartment_id_in_subtree: Optional[_builtins.bool] = None,
                                              display_name: Optional[_builtins.str] = None,
                                              filters: Optional[Sequence[Union['GetOperationsInsightsPrivateEndpointsFilterArgs', 'GetOperationsInsightsPrivateEndpointsFilterArgsDict']]] = None,
                                              is_used_for_rac_dbs: Optional[_builtins.bool] = None,
                                              opsi_private_endpoint_id: Optional[_builtins.str] = None,
                                              states: Optional[Sequence[_builtins.str]] = None,
                                              vcn_id: Optional[_builtins.str] = None,
                                              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetOperationsInsightsPrivateEndpointsResult:
    """
    This data source provides the list of Operations Insights Private Endpoints in Oracle Cloud Infrastructure Opsi service.

    Gets a list of Operation Insights private endpoints.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_operations_insights_private_endpoints = oci.Opsi.get_operations_insights_private_endpoints(compartment_id=compartment_id,
        compartment_id_in_subtree=operations_insights_private_endpoint_compartment_id_in_subtree,
        display_name=operations_insights_private_endpoint_display_name,
        is_used_for_rac_dbs=operations_insights_private_endpoint_is_used_for_rac_dbs,
        opsi_private_endpoint_id=test_private_endpoint["id"],
        states=operations_insights_private_endpoint_state,
        vcn_id=test_vcn["id"])
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.bool compartment_id_in_subtree: A flag to search all resources within a given compartment and all sub-compartments.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name.
    :param _builtins.bool is_used_for_rac_dbs: The option to filter OPSI private endpoints that can used for RAC. Should be used along with vcnId query parameter.
    :param _builtins.str opsi_private_endpoint_id: Unique Operations Insights PrivateEndpoint identifier
    :param Sequence[_builtins.str] states: Lifecycle states
    :param _builtins.str vcn_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['isUsedForRacDbs'] = is_used_for_rac_dbs
    __args__['opsiPrivateEndpointId'] = opsi_private_endpoint_id
    __args__['states'] = states
    __args__['vcnId'] = vcn_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Opsi/getOperationsInsightsPrivateEndpoints:getOperationsInsightsPrivateEndpoints', __args__, opts=opts, typ=GetOperationsInsightsPrivateEndpointsResult).value

    return AwaitableGetOperationsInsightsPrivateEndpointsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compartment_id_in_subtree=pulumi.get(__ret__, 'compartment_id_in_subtree'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        is_used_for_rac_dbs=pulumi.get(__ret__, 'is_used_for_rac_dbs'),
        operations_insights_private_endpoint_collections=pulumi.get(__ret__, 'operations_insights_private_endpoint_collections'),
        opsi_private_endpoint_id=pulumi.get(__ret__, 'opsi_private_endpoint_id'),
        states=pulumi.get(__ret__, 'states'),
        vcn_id=pulumi.get(__ret__, 'vcn_id'))
def get_operations_insights_private_endpoints_output(compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                     compartment_id_in_subtree: Optional[pulumi.Input[Optional[_builtins.bool]]] = None,
                                                     display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                     filters: Optional[pulumi.Input[Optional[Sequence[Union['GetOperationsInsightsPrivateEndpointsFilterArgs', 'GetOperationsInsightsPrivateEndpointsFilterArgsDict']]]]] = None,
                                                     is_used_for_rac_dbs: Optional[pulumi.Input[Optional[_builtins.bool]]] = None,
                                                     opsi_private_endpoint_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                     states: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                     vcn_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                     opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetOperationsInsightsPrivateEndpointsResult]:
    """
    This data source provides the list of Operations Insights Private Endpoints in Oracle Cloud Infrastructure Opsi service.

    Gets a list of Operation Insights private endpoints.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_operations_insights_private_endpoints = oci.Opsi.get_operations_insights_private_endpoints(compartment_id=compartment_id,
        compartment_id_in_subtree=operations_insights_private_endpoint_compartment_id_in_subtree,
        display_name=operations_insights_private_endpoint_display_name,
        is_used_for_rac_dbs=operations_insights_private_endpoint_is_used_for_rac_dbs,
        opsi_private_endpoint_id=test_private_endpoint["id"],
        states=operations_insights_private_endpoint_state,
        vcn_id=test_vcn["id"])
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.bool compartment_id_in_subtree: A flag to search all resources within a given compartment and all sub-compartments.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name.
    :param _builtins.bool is_used_for_rac_dbs: The option to filter OPSI private endpoints that can used for RAC. Should be used along with vcnId query parameter.
    :param _builtins.str opsi_private_endpoint_id: Unique Operations Insights PrivateEndpoint identifier
    :param Sequence[_builtins.str] states: Lifecycle states
    :param _builtins.str vcn_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['isUsedForRacDbs'] = is_used_for_rac_dbs
    __args__['opsiPrivateEndpointId'] = opsi_private_endpoint_id
    __args__['states'] = states
    __args__['vcnId'] = vcn_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Opsi/getOperationsInsightsPrivateEndpoints:getOperationsInsightsPrivateEndpoints', __args__, opts=opts, typ=GetOperationsInsightsPrivateEndpointsResult)
    return __ret__.apply(lambda __response__: GetOperationsInsightsPrivateEndpointsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        compartment_id_in_subtree=pulumi.get(__response__, 'compartment_id_in_subtree'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        is_used_for_rac_dbs=pulumi.get(__response__, 'is_used_for_rac_dbs'),
        operations_insights_private_endpoint_collections=pulumi.get(__response__, 'operations_insights_private_endpoint_collections'),
        opsi_private_endpoint_id=pulumi.get(__response__, 'opsi_private_endpoint_id'),
        states=pulumi.get(__response__, 'states'),
        vcn_id=pulumi.get(__response__, 'vcn_id')))
