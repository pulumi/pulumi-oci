# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetHistoriesResult',
    'AwaitableGetHistoriesResult',
    'get_histories',
    'get_histories_output',
]

@pulumi.output_type
class GetHistoriesResult:
    """
    A collection of values returned by getHistories.
    """
    def __init__(__self__, compartment_id=None, compartment_id_in_subtree=None, filters=None, history_collections=None, id=None, name=None, recommendation_id=None, recommendation_name=None, resource_type=None, state=None, status=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compartment_id_in_subtree and not isinstance(compartment_id_in_subtree, bool):
            raise TypeError("Expected argument 'compartment_id_in_subtree' to be a bool")
        pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if history_collections and not isinstance(history_collections, list):
            raise TypeError("Expected argument 'history_collections' to be a list")
        pulumi.set(__self__, "history_collections", history_collections)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if recommendation_id and not isinstance(recommendation_id, str):
            raise TypeError("Expected argument 'recommendation_id' to be a str")
        pulumi.set(__self__, "recommendation_id", recommendation_id)
        if recommendation_name and not isinstance(recommendation_name, str):
            raise TypeError("Expected argument 'recommendation_name' to be a str")
        pulumi.set(__self__, "recommendation_name", recommendation_name)
        if resource_type and not isinstance(resource_type, str):
            raise TypeError("Expected argument 'resource_type' to be a str")
        pulumi.set(__self__, "resource_type", resource_type)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if status and not isinstance(status, str):
            raise TypeError("Expected argument 'status' to be a str")
        pulumi.set(__self__, "status", status)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> bool:
        return pulumi.get(self, "compartment_id_in_subtree")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetHistoriesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter(name="historyCollections")
    def history_collections(self) -> Sequence['outputs.GetHistoriesHistoryCollectionResult']:
        """
        The list of history_collection.
        """
        return pulumi.get(self, "history_collections")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        The name assigned to the resource.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="recommendationId")
    def recommendation_id(self) -> Optional[str]:
        """
        The unique OCID associated with the recommendation.
        """
        return pulumi.get(self, "recommendation_id")

    @property
    @pulumi.getter(name="recommendationName")
    def recommendation_name(self) -> Optional[str]:
        """
        The name assigned to the recommendation.
        """
        return pulumi.get(self, "recommendation_name")

    @property
    @pulumi.getter(name="resourceType")
    def resource_type(self) -> Optional[str]:
        """
        The kind of resource.
        """
        return pulumi.get(self, "resource_type")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The recommendation history's current state.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter
    def status(self) -> Optional[str]:
        """
        The current status of the resource action.
        """
        return pulumi.get(self, "status")


class AwaitableGetHistoriesResult(GetHistoriesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetHistoriesResult(
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            filters=self.filters,
            history_collections=self.history_collections,
            id=self.id,
            name=self.name,
            recommendation_id=self.recommendation_id,
            recommendation_name=self.recommendation_name,
            resource_type=self.resource_type,
            state=self.state,
            status=self.status)


def get_histories(compartment_id: Optional[str] = None,
                  compartment_id_in_subtree: Optional[bool] = None,
                  filters: Optional[Sequence[pulumi.InputType['GetHistoriesFilterArgs']]] = None,
                  name: Optional[str] = None,
                  recommendation_id: Optional[str] = None,
                  recommendation_name: Optional[str] = None,
                  resource_type: Optional[str] = None,
                  state: Optional[str] = None,
                  status: Optional[str] = None,
                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetHistoriesResult:
    """
    This data source provides the list of Histories in Oracle Cloud Infrastructure Optimizer service.

    Lists changes to the recommendations based on user activity.
    For example, lists when recommendations have been implemented, dismissed, postponed, or reactivated.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_histories = oci.Optimizer.get_histories(compartment_id=var["compartment_id"],
        compartment_id_in_subtree=var["history_compartment_id_in_subtree"],
        name=var["history_name"],
        recommendation_id=oci_optimizer_recommendation["test_recommendation"]["id"],
        recommendation_name=oci_optimizer_recommendation["test_recommendation"]["name"],
        resource_type=var["history_resource_type"],
        state=var["history_state"],
        status=var["history_status"])
    ```


    :param str compartment_id: The OCID of the compartment.
    :param bool compartment_id_in_subtree: When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
    :param str name: Optional. A filter that returns results that match the name specified.
    :param str recommendation_id: The unique OCID associated with the recommendation.
    :param str recommendation_name: Optional. A filter that returns results that match the recommendation name specified.
    :param str resource_type: Optional. A filter that returns results that match the resource type specified.
    :param str state: A filter that returns results that match the lifecycle state specified.
    :param str status: A filter that returns recommendations that match the status specified.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['recommendationId'] = recommendation_id
    __args__['recommendationName'] = recommendation_name
    __args__['resourceType'] = resource_type
    __args__['state'] = state
    __args__['status'] = status
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:Optimizer/getHistories:getHistories', __args__, opts=opts, typ=GetHistoriesResult).value

    return AwaitableGetHistoriesResult(
        compartment_id=__ret__.compartment_id,
        compartment_id_in_subtree=__ret__.compartment_id_in_subtree,
        filters=__ret__.filters,
        history_collections=__ret__.history_collections,
        id=__ret__.id,
        name=__ret__.name,
        recommendation_id=__ret__.recommendation_id,
        recommendation_name=__ret__.recommendation_name,
        resource_type=__ret__.resource_type,
        state=__ret__.state,
        status=__ret__.status)


@_utilities.lift_output_func(get_histories)
def get_histories_output(compartment_id: Optional[pulumi.Input[str]] = None,
                         compartment_id_in_subtree: Optional[pulumi.Input[bool]] = None,
                         filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetHistoriesFilterArgs']]]]] = None,
                         name: Optional[pulumi.Input[Optional[str]]] = None,
                         recommendation_id: Optional[pulumi.Input[Optional[str]]] = None,
                         recommendation_name: Optional[pulumi.Input[Optional[str]]] = None,
                         resource_type: Optional[pulumi.Input[Optional[str]]] = None,
                         state: Optional[pulumi.Input[Optional[str]]] = None,
                         status: Optional[pulumi.Input[Optional[str]]] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetHistoriesResult]:
    """
    This data source provides the list of Histories in Oracle Cloud Infrastructure Optimizer service.

    Lists changes to the recommendations based on user activity.
    For example, lists when recommendations have been implemented, dismissed, postponed, or reactivated.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_histories = oci.Optimizer.get_histories(compartment_id=var["compartment_id"],
        compartment_id_in_subtree=var["history_compartment_id_in_subtree"],
        name=var["history_name"],
        recommendation_id=oci_optimizer_recommendation["test_recommendation"]["id"],
        recommendation_name=oci_optimizer_recommendation["test_recommendation"]["name"],
        resource_type=var["history_resource_type"],
        state=var["history_state"],
        status=var["history_status"])
    ```


    :param str compartment_id: The OCID of the compartment.
    :param bool compartment_id_in_subtree: When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
    :param str name: Optional. A filter that returns results that match the name specified.
    :param str recommendation_id: The unique OCID associated with the recommendation.
    :param str recommendation_name: Optional. A filter that returns results that match the recommendation name specified.
    :param str resource_type: Optional. A filter that returns results that match the resource type specified.
    :param str state: A filter that returns results that match the lifecycle state specified.
    :param str status: A filter that returns recommendations that match the status specified.
    """
    ...
