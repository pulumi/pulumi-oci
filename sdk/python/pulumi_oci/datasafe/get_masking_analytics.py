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
    'GetMaskingAnalyticsResult',
    'AwaitableGetMaskingAnalyticsResult',
    'get_masking_analytics',
    'get_masking_analytics_output',
]

@pulumi.output_type
class GetMaskingAnalyticsResult:
    """
    A collection of values returned by getMaskingAnalytics.
    """
    def __init__(__self__, compartment_id=None, compartment_id_in_subtree=None, filters=None, group_by=None, id=None, masking_analytics_collections=None, masking_policy_id=None, target_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compartment_id_in_subtree and not isinstance(compartment_id_in_subtree, bool):
            raise TypeError("Expected argument 'compartment_id_in_subtree' to be a bool")
        pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if group_by and not isinstance(group_by, str):
            raise TypeError("Expected argument 'group_by' to be a str")
        pulumi.set(__self__, "group_by", group_by)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if masking_analytics_collections and not isinstance(masking_analytics_collections, list):
            raise TypeError("Expected argument 'masking_analytics_collections' to be a list")
        pulumi.set(__self__, "masking_analytics_collections", masking_analytics_collections)
        if masking_policy_id and not isinstance(masking_policy_id, str):
            raise TypeError("Expected argument 'masking_policy_id' to be a str")
        pulumi.set(__self__, "masking_policy_id", masking_policy_id)
        if target_id and not isinstance(target_id, str):
            raise TypeError("Expected argument 'target_id' to be a str")
        pulumi.set(__self__, "target_id", target_id)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetMaskingAnalyticsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter(name="groupBy")
    def group_by(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "group_by")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="maskingAnalyticsCollections")
    def masking_analytics_collections(self) -> Sequence['outputs.GetMaskingAnalyticsMaskingAnalyticsCollectionResult']:
        """
        The list of masking_analytics_collection.
        """
        return pulumi.get(self, "masking_analytics_collections")

    @_builtins.property
    @pulumi.getter(name="maskingPolicyId")
    def masking_policy_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "masking_policy_id")

    @_builtins.property
    @pulumi.getter(name="targetId")
    def target_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the target database.
        """
        return pulumi.get(self, "target_id")


class AwaitableGetMaskingAnalyticsResult(GetMaskingAnalyticsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetMaskingAnalyticsResult(
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            filters=self.filters,
            group_by=self.group_by,
            id=self.id,
            masking_analytics_collections=self.masking_analytics_collections,
            masking_policy_id=self.masking_policy_id,
            target_id=self.target_id)


def get_masking_analytics(compartment_id: Optional[_builtins.str] = None,
                          compartment_id_in_subtree: Optional[_builtins.bool] = None,
                          filters: Optional[Sequence[Union['GetMaskingAnalyticsFilterArgs', 'GetMaskingAnalyticsFilterArgsDict']]] = None,
                          group_by: Optional[_builtins.str] = None,
                          masking_policy_id: Optional[_builtins.str] = None,
                          target_id: Optional[_builtins.str] = None,
                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetMaskingAnalyticsResult:
    """
    This data source provides the list of Masking Analytics in Oracle Cloud Infrastructure Data Safe service.

    Gets consolidated masking analytics data based on the specified query parameters.
    If CompartmentIdInSubtreeQueryParam is specified as true, the behaviour
    is equivalent to accessLevel "ACCESSIBLE" by default.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_masking_analytics = oci.DataSafe.get_masking_analytics(compartment_id=compartment_id,
        compartment_id_in_subtree=masking_analytic_compartment_id_in_subtree,
        group_by=masking_analytic_group_by,
        masking_policy_id=test_masking_policy["id"],
        target_id=test_target["id"])
    ```


    :param _builtins.str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param _builtins.bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param _builtins.str group_by: Attribute by which the masking analytics data should be grouped.
    :param _builtins.str masking_policy_id: A filter to return only the resources that match the specified masking policy OCID.
    :param _builtins.str target_id: A filter to return only items related to a specific target OCID.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['filters'] = filters
    __args__['groupBy'] = group_by
    __args__['maskingPolicyId'] = masking_policy_id
    __args__['targetId'] = target_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getMaskingAnalytics:getMaskingAnalytics', __args__, opts=opts, typ=GetMaskingAnalyticsResult).value

    return AwaitableGetMaskingAnalyticsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compartment_id_in_subtree=pulumi.get(__ret__, 'compartment_id_in_subtree'),
        filters=pulumi.get(__ret__, 'filters'),
        group_by=pulumi.get(__ret__, 'group_by'),
        id=pulumi.get(__ret__, 'id'),
        masking_analytics_collections=pulumi.get(__ret__, 'masking_analytics_collections'),
        masking_policy_id=pulumi.get(__ret__, 'masking_policy_id'),
        target_id=pulumi.get(__ret__, 'target_id'))
def get_masking_analytics_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                 compartment_id_in_subtree: Optional[pulumi.Input[Optional[_builtins.bool]]] = None,
                                 filters: Optional[pulumi.Input[Optional[Sequence[Union['GetMaskingAnalyticsFilterArgs', 'GetMaskingAnalyticsFilterArgsDict']]]]] = None,
                                 group_by: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                 masking_policy_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                 target_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                 opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetMaskingAnalyticsResult]:
    """
    This data source provides the list of Masking Analytics in Oracle Cloud Infrastructure Data Safe service.

    Gets consolidated masking analytics data based on the specified query parameters.
    If CompartmentIdInSubtreeQueryParam is specified as true, the behaviour
    is equivalent to accessLevel "ACCESSIBLE" by default.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_masking_analytics = oci.DataSafe.get_masking_analytics(compartment_id=compartment_id,
        compartment_id_in_subtree=masking_analytic_compartment_id_in_subtree,
        group_by=masking_analytic_group_by,
        masking_policy_id=test_masking_policy["id"],
        target_id=test_target["id"])
    ```


    :param _builtins.str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param _builtins.bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param _builtins.str group_by: Attribute by which the masking analytics data should be grouped.
    :param _builtins.str masking_policy_id: A filter to return only the resources that match the specified masking policy OCID.
    :param _builtins.str target_id: A filter to return only items related to a specific target OCID.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['filters'] = filters
    __args__['groupBy'] = group_by
    __args__['maskingPolicyId'] = masking_policy_id
    __args__['targetId'] = target_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataSafe/getMaskingAnalytics:getMaskingAnalytics', __args__, opts=opts, typ=GetMaskingAnalyticsResult)
    return __ret__.apply(lambda __response__: GetMaskingAnalyticsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        compartment_id_in_subtree=pulumi.get(__response__, 'compartment_id_in_subtree'),
        filters=pulumi.get(__response__, 'filters'),
        group_by=pulumi.get(__response__, 'group_by'),
        id=pulumi.get(__response__, 'id'),
        masking_analytics_collections=pulumi.get(__response__, 'masking_analytics_collections'),
        masking_policy_id=pulumi.get(__response__, 'masking_policy_id'),
        target_id=pulumi.get(__response__, 'target_id')))
