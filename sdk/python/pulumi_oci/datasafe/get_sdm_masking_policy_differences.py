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
    'GetSdmMaskingPolicyDifferencesResult',
    'AwaitableGetSdmMaskingPolicyDifferencesResult',
    'get_sdm_masking_policy_differences',
    'get_sdm_masking_policy_differences_output',
]

@pulumi.output_type
class GetSdmMaskingPolicyDifferencesResult:
    """
    A collection of values returned by getSdmMaskingPolicyDifferences.
    """
    def __init__(__self__, compartment_id=None, compartment_id_in_subtree=None, difference_access_level=None, display_name=None, filters=None, id=None, masking_policy_id=None, sdm_masking_policy_difference_collections=None, sensitive_data_model_id=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compartment_id_in_subtree and not isinstance(compartment_id_in_subtree, bool):
            raise TypeError("Expected argument 'compartment_id_in_subtree' to be a bool")
        pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if difference_access_level and not isinstance(difference_access_level, str):
            raise TypeError("Expected argument 'difference_access_level' to be a str")
        pulumi.set(__self__, "difference_access_level", difference_access_level)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if masking_policy_id and not isinstance(masking_policy_id, str):
            raise TypeError("Expected argument 'masking_policy_id' to be a str")
        pulumi.set(__self__, "masking_policy_id", masking_policy_id)
        if sdm_masking_policy_difference_collections and not isinstance(sdm_masking_policy_difference_collections, list):
            raise TypeError("Expected argument 'sdm_masking_policy_difference_collections' to be a list")
        pulumi.set(__self__, "sdm_masking_policy_difference_collections", sdm_masking_policy_difference_collections)
        if sensitive_data_model_id and not isinstance(sensitive_data_model_id, str):
            raise TypeError("Expected argument 'sensitive_data_model_id' to be a str")
        pulumi.set(__self__, "sensitive_data_model_id", sensitive_data_model_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment that contains the SDM masking policy difference.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @property
    @pulumi.getter(name="differenceAccessLevel")
    def difference_access_level(self) -> Optional[str]:
        return pulumi.get(self, "difference_access_level")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        The display name of the SDM masking policy difference.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSdmMaskingPolicyDifferencesFilterResult']]:
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
        The OCID of the masking policy associated with the SDM masking policy difference.
        """
        return pulumi.get(self, "masking_policy_id")

    @property
    @pulumi.getter(name="sdmMaskingPolicyDifferenceCollections")
    def sdm_masking_policy_difference_collections(self) -> Sequence['outputs.GetSdmMaskingPolicyDifferencesSdmMaskingPolicyDifferenceCollectionResult']:
        """
        The list of sdm_masking_policy_difference_collection.
        """
        return pulumi.get(self, "sdm_masking_policy_difference_collections")

    @property
    @pulumi.getter(name="sensitiveDataModelId")
    def sensitive_data_model_id(self) -> Optional[str]:
        """
        The OCID of the sensitive data model associated with the SDM masking policy difference.
        """
        return pulumi.get(self, "sensitive_data_model_id")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the SDM masking policy difference.
        """
        return pulumi.get(self, "state")


class AwaitableGetSdmMaskingPolicyDifferencesResult(GetSdmMaskingPolicyDifferencesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSdmMaskingPolicyDifferencesResult(
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            difference_access_level=self.difference_access_level,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            masking_policy_id=self.masking_policy_id,
            sdm_masking_policy_difference_collections=self.sdm_masking_policy_difference_collections,
            sensitive_data_model_id=self.sensitive_data_model_id,
            state=self.state)


def get_sdm_masking_policy_differences(compartment_id: Optional[str] = None,
                                       compartment_id_in_subtree: Optional[bool] = None,
                                       difference_access_level: Optional[str] = None,
                                       display_name: Optional[str] = None,
                                       filters: Optional[Sequence[pulumi.InputType['GetSdmMaskingPolicyDifferencesFilterArgs']]] = None,
                                       masking_policy_id: Optional[str] = None,
                                       sensitive_data_model_id: Optional[str] = None,
                                       state: Optional[str] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSdmMaskingPolicyDifferencesResult:
    """
    This data source provides the list of Sdm Masking Policy Differences in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of SDM and masking policy difference resources based on the specified query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_sdm_masking_policy_differences = oci.DataSafe.get_sdm_masking_policy_differences(compartment_id=var["compartment_id"],
        compartment_id_in_subtree=var["sdm_masking_policy_difference_compartment_id_in_subtree"],
        difference_access_level=var["sdm_masking_policy_difference_difference_access_level"],
        display_name=var["sdm_masking_policy_difference_display_name"],
        masking_policy_id=oci_data_safe_masking_policy["test_masking_policy"]["id"],
        sensitive_data_model_id=oci_data_safe_sensitive_data_model["test_sensitive_data_model"]["id"],
        state=var["sdm_masking_policy_difference_state"])
    ```


    :param str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param str difference_access_level: Valid value is ACCESSIBLE. Default is ACCESSIBLE. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment).
    :param str display_name: A filter to return only resources that match the specified display name.
    :param str masking_policy_id: A filter to return only the resources that match the specified masking policy OCID.
    :param str sensitive_data_model_id: A filter to return only the resources that match the specified sensitive data model OCID.
    :param str state: A filter to return only the resources that match the specified lifecycle states.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['differenceAccessLevel'] = difference_access_level
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['maskingPolicyId'] = masking_policy_id
    __args__['sensitiveDataModelId'] = sensitive_data_model_id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getSdmMaskingPolicyDifferences:getSdmMaskingPolicyDifferences', __args__, opts=opts, typ=GetSdmMaskingPolicyDifferencesResult).value

    return AwaitableGetSdmMaskingPolicyDifferencesResult(
        compartment_id=__ret__.compartment_id,
        compartment_id_in_subtree=__ret__.compartment_id_in_subtree,
        difference_access_level=__ret__.difference_access_level,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        masking_policy_id=__ret__.masking_policy_id,
        sdm_masking_policy_difference_collections=__ret__.sdm_masking_policy_difference_collections,
        sensitive_data_model_id=__ret__.sensitive_data_model_id,
        state=__ret__.state)


@_utilities.lift_output_func(get_sdm_masking_policy_differences)
def get_sdm_masking_policy_differences_output(compartment_id: Optional[pulumi.Input[str]] = None,
                                              compartment_id_in_subtree: Optional[pulumi.Input[Optional[bool]]] = None,
                                              difference_access_level: Optional[pulumi.Input[Optional[str]]] = None,
                                              display_name: Optional[pulumi.Input[Optional[str]]] = None,
                                              filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetSdmMaskingPolicyDifferencesFilterArgs']]]]] = None,
                                              masking_policy_id: Optional[pulumi.Input[Optional[str]]] = None,
                                              sensitive_data_model_id: Optional[pulumi.Input[Optional[str]]] = None,
                                              state: Optional[pulumi.Input[Optional[str]]] = None,
                                              opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetSdmMaskingPolicyDifferencesResult]:
    """
    This data source provides the list of Sdm Masking Policy Differences in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of SDM and masking policy difference resources based on the specified query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_sdm_masking_policy_differences = oci.DataSafe.get_sdm_masking_policy_differences(compartment_id=var["compartment_id"],
        compartment_id_in_subtree=var["sdm_masking_policy_difference_compartment_id_in_subtree"],
        difference_access_level=var["sdm_masking_policy_difference_difference_access_level"],
        display_name=var["sdm_masking_policy_difference_display_name"],
        masking_policy_id=oci_data_safe_masking_policy["test_masking_policy"]["id"],
        sensitive_data_model_id=oci_data_safe_sensitive_data_model["test_sensitive_data_model"]["id"],
        state=var["sdm_masking_policy_difference_state"])
    ```


    :param str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param str difference_access_level: Valid value is ACCESSIBLE. Default is ACCESSIBLE. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment).
    :param str display_name: A filter to return only resources that match the specified display name.
    :param str masking_policy_id: A filter to return only the resources that match the specified masking policy OCID.
    :param str sensitive_data_model_id: A filter to return only the resources that match the specified sensitive data model OCID.
    :param str state: A filter to return only the resources that match the specified lifecycle states.
    """
    ...