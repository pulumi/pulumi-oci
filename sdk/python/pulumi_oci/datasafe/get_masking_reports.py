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
    'GetMaskingReportsResult',
    'AwaitableGetMaskingReportsResult',
    'get_masking_reports',
    'get_masking_reports_output',
]

@pulumi.output_type
class GetMaskingReportsResult:
    """
    A collection of values returned by getMaskingReports.
    """
    def __init__(__self__, access_level=None, compartment_id=None, compartment_id_in_subtree=None, filters=None, id=None, masking_policy_id=None, masking_report_collections=None, target_id=None):
        if access_level and not isinstance(access_level, str):
            raise TypeError("Expected argument 'access_level' to be a str")
        pulumi.set(__self__, "access_level", access_level)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compartment_id_in_subtree and not isinstance(compartment_id_in_subtree, bool):
            raise TypeError("Expected argument 'compartment_id_in_subtree' to be a bool")
        pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if masking_policy_id and not isinstance(masking_policy_id, str):
            raise TypeError("Expected argument 'masking_policy_id' to be a str")
        pulumi.set(__self__, "masking_policy_id", masking_policy_id)
        if masking_report_collections and not isinstance(masking_report_collections, list):
            raise TypeError("Expected argument 'masking_report_collections' to be a list")
        pulumi.set(__self__, "masking_report_collections", masking_report_collections)
        if target_id and not isinstance(target_id, str):
            raise TypeError("Expected argument 'target_id' to be a str")
        pulumi.set(__self__, "target_id", target_id)

    @property
    @pulumi.getter(name="accessLevel")
    def access_level(self) -> Optional[str]:
        return pulumi.get(self, "access_level")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment that contains the masking report.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetMaskingReportsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="maskingPolicyId")
    def masking_policy_id(self) -> Optional[str]:
        """
        The OCID of the masking policy used.
        """
        return pulumi.get(self, "masking_policy_id")

    @property
    @pulumi.getter(name="maskingReportCollections")
    def masking_report_collections(self) -> Sequence['outputs.GetMaskingReportsMaskingReportCollectionResult']:
        """
        The list of masking_report_collection.
        """
        return pulumi.get(self, "masking_report_collections")

    @property
    @pulumi.getter(name="targetId")
    def target_id(self) -> Optional[str]:
        """
        The OCID of the target database masked.
        """
        return pulumi.get(self, "target_id")


class AwaitableGetMaskingReportsResult(GetMaskingReportsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetMaskingReportsResult(
            access_level=self.access_level,
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            filters=self.filters,
            id=self.id,
            masking_policy_id=self.masking_policy_id,
            masking_report_collections=self.masking_report_collections,
            target_id=self.target_id)


def get_masking_reports(access_level: Optional[str] = None,
                        compartment_id: Optional[str] = None,
                        compartment_id_in_subtree: Optional[bool] = None,
                        filters: Optional[Sequence[pulumi.InputType['GetMaskingReportsFilterArgs']]] = None,
                        masking_policy_id: Optional[str] = None,
                        target_id: Optional[str] = None,
                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetMaskingReportsResult:
    """
    This data source provides the list of Masking Reports in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of masking reports based on the specified query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_masking_reports = oci.DataSafe.get_masking_reports(compartment_id=var["compartment_id"],
        access_level=var["masking_report_access_level"],
        compartment_id_in_subtree=var["masking_report_compartment_id_in_subtree"],
        masking_policy_id=oci_data_safe_masking_policy["test_masking_policy"]["id"],
        target_id=oci_cloud_guard_target["test_target"]["id"])
    ```


    :param str access_level: Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
    :param str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param str masking_policy_id: A filter to return only the resources that match the specified masking policy OCID.
    :param str target_id: A filter to return only items related to a specific target OCID.
    """
    __args__ = dict()
    __args__['accessLevel'] = access_level
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['filters'] = filters
    __args__['maskingPolicyId'] = masking_policy_id
    __args__['targetId'] = target_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getMaskingReports:getMaskingReports', __args__, opts=opts, typ=GetMaskingReportsResult).value

    return AwaitableGetMaskingReportsResult(
        access_level=__ret__.access_level,
        compartment_id=__ret__.compartment_id,
        compartment_id_in_subtree=__ret__.compartment_id_in_subtree,
        filters=__ret__.filters,
        id=__ret__.id,
        masking_policy_id=__ret__.masking_policy_id,
        masking_report_collections=__ret__.masking_report_collections,
        target_id=__ret__.target_id)


@_utilities.lift_output_func(get_masking_reports)
def get_masking_reports_output(access_level: Optional[pulumi.Input[Optional[str]]] = None,
                               compartment_id: Optional[pulumi.Input[str]] = None,
                               compartment_id_in_subtree: Optional[pulumi.Input[Optional[bool]]] = None,
                               filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetMaskingReportsFilterArgs']]]]] = None,
                               masking_policy_id: Optional[pulumi.Input[Optional[str]]] = None,
                               target_id: Optional[pulumi.Input[Optional[str]]] = None,
                               opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetMaskingReportsResult]:
    """
    This data source provides the list of Masking Reports in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of masking reports based on the specified query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_masking_reports = oci.DataSafe.get_masking_reports(compartment_id=var["compartment_id"],
        access_level=var["masking_report_access_level"],
        compartment_id_in_subtree=var["masking_report_compartment_id_in_subtree"],
        masking_policy_id=oci_data_safe_masking_policy["test_masking_policy"]["id"],
        target_id=oci_cloud_guard_target["test_target"]["id"])
    ```


    :param str access_level: Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
    :param str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param str masking_policy_id: A filter to return only the resources that match the specified masking policy OCID.
    :param str target_id: A filter to return only items related to a specific target OCID.
    """
    ...