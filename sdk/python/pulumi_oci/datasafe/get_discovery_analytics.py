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
    'GetDiscoveryAnalyticsResult',
    'AwaitableGetDiscoveryAnalyticsResult',
    'get_discovery_analytics',
    'get_discovery_analytics_output',
]

@pulumi.output_type
class GetDiscoveryAnalyticsResult:
    """
    A collection of values returned by getDiscoveryAnalytics.
    """
    def __init__(__self__, compartment_id=None, compartment_id_in_subtree=None, discovery_analytics_collections=None, filters=None, group_by=None, id=None, sensitive_data_model_id=None, target_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compartment_id_in_subtree and not isinstance(compartment_id_in_subtree, bool):
            raise TypeError("Expected argument 'compartment_id_in_subtree' to be a bool")
        pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if discovery_analytics_collections and not isinstance(discovery_analytics_collections, list):
            raise TypeError("Expected argument 'discovery_analytics_collections' to be a list")
        pulumi.set(__self__, "discovery_analytics_collections", discovery_analytics_collections)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if group_by and not isinstance(group_by, str):
            raise TypeError("Expected argument 'group_by' to be a str")
        pulumi.set(__self__, "group_by", group_by)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if sensitive_data_model_id and not isinstance(sensitive_data_model_id, str):
            raise TypeError("Expected argument 'sensitive_data_model_id' to be a str")
        pulumi.set(__self__, "sensitive_data_model_id", sensitive_data_model_id)
        if target_id and not isinstance(target_id, str):
            raise TypeError("Expected argument 'target_id' to be a str")
        pulumi.set(__self__, "target_id", target_id)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @property
    @pulumi.getter(name="discoveryAnalyticsCollections")
    def discovery_analytics_collections(self) -> Sequence['outputs.GetDiscoveryAnalyticsDiscoveryAnalyticsCollectionResult']:
        """
        The list of discovery_analytics_collection.
        """
        return pulumi.get(self, "discovery_analytics_collections")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDiscoveryAnalyticsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter(name="groupBy")
    def group_by(self) -> Optional[str]:
        return pulumi.get(self, "group_by")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="sensitiveDataModelId")
    def sensitive_data_model_id(self) -> Optional[str]:
        """
        The OCID of the sensitive data model.
        """
        return pulumi.get(self, "sensitive_data_model_id")

    @property
    @pulumi.getter(name="targetId")
    def target_id(self) -> Optional[str]:
        """
        The OCID of the target database.
        """
        return pulumi.get(self, "target_id")


class AwaitableGetDiscoveryAnalyticsResult(GetDiscoveryAnalyticsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDiscoveryAnalyticsResult(
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            discovery_analytics_collections=self.discovery_analytics_collections,
            filters=self.filters,
            group_by=self.group_by,
            id=self.id,
            sensitive_data_model_id=self.sensitive_data_model_id,
            target_id=self.target_id)


def get_discovery_analytics(compartment_id: Optional[str] = None,
                            compartment_id_in_subtree: Optional[bool] = None,
                            filters: Optional[Sequence[pulumi.InputType['GetDiscoveryAnalyticsFilterArgs']]] = None,
                            group_by: Optional[str] = None,
                            sensitive_data_model_id: Optional[str] = None,
                            target_id: Optional[str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDiscoveryAnalyticsResult:
    """
    This data source provides the list of Discovery Analytics in Oracle Cloud Infrastructure Data Safe service.

    Gets consolidated discovery analytics data based on the specified query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_discovery_analytics = oci.DataSafe.get_discovery_analytics(compartment_id=var["compartment_id"],
        compartment_id_in_subtree=var["discovery_analytic_compartment_id_in_subtree"],
        group_by=var["discovery_analytic_group_by"],
        sensitive_data_model_id=oci_data_safe_sensitive_data_model["test_sensitive_data_model"]["id"],
        target_id=oci_cloud_guard_target["test_target"]["id"])
    ```


    :param str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param str group_by: Attribute by which the discovery analytics data should be grouped.
    :param str sensitive_data_model_id: A filter to return only the resources that match the specified sensitive data model OCID.
    :param str target_id: A filter to return only items related to a specific target OCID.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['filters'] = filters
    __args__['groupBy'] = group_by
    __args__['sensitiveDataModelId'] = sensitive_data_model_id
    __args__['targetId'] = target_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getDiscoveryAnalytics:getDiscoveryAnalytics', __args__, opts=opts, typ=GetDiscoveryAnalyticsResult).value

    return AwaitableGetDiscoveryAnalyticsResult(
        compartment_id=__ret__.compartment_id,
        compartment_id_in_subtree=__ret__.compartment_id_in_subtree,
        discovery_analytics_collections=__ret__.discovery_analytics_collections,
        filters=__ret__.filters,
        group_by=__ret__.group_by,
        id=__ret__.id,
        sensitive_data_model_id=__ret__.sensitive_data_model_id,
        target_id=__ret__.target_id)


@_utilities.lift_output_func(get_discovery_analytics)
def get_discovery_analytics_output(compartment_id: Optional[pulumi.Input[str]] = None,
                                   compartment_id_in_subtree: Optional[pulumi.Input[Optional[bool]]] = None,
                                   filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetDiscoveryAnalyticsFilterArgs']]]]] = None,
                                   group_by: Optional[pulumi.Input[Optional[str]]] = None,
                                   sensitive_data_model_id: Optional[pulumi.Input[Optional[str]]] = None,
                                   target_id: Optional[pulumi.Input[Optional[str]]] = None,
                                   opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetDiscoveryAnalyticsResult]:
    """
    This data source provides the list of Discovery Analytics in Oracle Cloud Infrastructure Data Safe service.

    Gets consolidated discovery analytics data based on the specified query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_discovery_analytics = oci.DataSafe.get_discovery_analytics(compartment_id=var["compartment_id"],
        compartment_id_in_subtree=var["discovery_analytic_compartment_id_in_subtree"],
        group_by=var["discovery_analytic_group_by"],
        sensitive_data_model_id=oci_data_safe_sensitive_data_model["test_sensitive_data_model"]["id"],
        target_id=oci_cloud_guard_target["test_target"]["id"])
    ```


    :param str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param str group_by: Attribute by which the discovery analytics data should be grouped.
    :param str sensitive_data_model_id: A filter to return only the resources that match the specified sensitive data model OCID.
    :param str target_id: A filter to return only items related to a specific target OCID.
    """
    ...
