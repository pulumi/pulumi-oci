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
    'GetProfileLevelsResult',
    'AwaitableGetProfileLevelsResult',
    'get_profile_levels',
    'get_profile_levels_output',
]

@pulumi.output_type
class GetProfileLevelsResult:
    """
    A collection of values returned by getProfileLevels.
    """
    def __init__(__self__, compartment_id=None, compartment_id_in_subtree=None, filters=None, id=None, name=None, profile_level_collections=None, recommendation_name=None):
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
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if profile_level_collections and not isinstance(profile_level_collections, list):
            raise TypeError("Expected argument 'profile_level_collections' to be a list")
        pulumi.set(__self__, "profile_level_collections", profile_level_collections)
        if recommendation_name and not isinstance(recommendation_name, str):
            raise TypeError("Expected argument 'recommendation_name' to be a str")
        pulumi.set(__self__, "recommendation_name", recommendation_name)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> bool:
        return pulumi.get(self, "compartment_id_in_subtree")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetProfileLevelsFilterResult']]:
        return pulumi.get(self, "filters")

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
        A unique name for the profile level.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="profileLevelCollections")
    def profile_level_collections(self) -> Sequence['outputs.GetProfileLevelsProfileLevelCollectionResult']:
        """
        The list of profile_level_collection.
        """
        return pulumi.get(self, "profile_level_collections")

    @property
    @pulumi.getter(name="recommendationName")
    def recommendation_name(self) -> Optional[str]:
        """
        The name of the recommendation this profile level applies to.
        """
        return pulumi.get(self, "recommendation_name")


class AwaitableGetProfileLevelsResult(GetProfileLevelsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetProfileLevelsResult(
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            filters=self.filters,
            id=self.id,
            name=self.name,
            profile_level_collections=self.profile_level_collections,
            recommendation_name=self.recommendation_name)


def get_profile_levels(compartment_id: Optional[str] = None,
                       compartment_id_in_subtree: Optional[bool] = None,
                       filters: Optional[Sequence[pulumi.InputType['GetProfileLevelsFilterArgs']]] = None,
                       name: Optional[str] = None,
                       recommendation_name: Optional[str] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetProfileLevelsResult:
    """
    This data source provides the list of Profile Levels in Oracle Cloud Infrastructure Optimizer service.

    Lists the existing profile levels.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_profile_levels = oci.Optimizer.get_profile_levels(compartment_id=var["compartment_id"],
        compartment_id_in_subtree=var["profile_level_compartment_id_in_subtree"],
        name=var["profile_level_name"],
        recommendation_name=oci_optimizer_recommendation["test_recommendation"]["name"])
    ```


    :param str compartment_id: The OCID of the compartment.
    :param bool compartment_id_in_subtree: When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
    :param str name: Optional. A filter that returns results that match the name specified.
    :param str recommendation_name: Optional. A filter that returns results that match the recommendation name specified.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['recommendationName'] = recommendation_name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Optimizer/getProfileLevels:getProfileLevels', __args__, opts=opts, typ=GetProfileLevelsResult).value

    return AwaitableGetProfileLevelsResult(
        compartment_id=__ret__.compartment_id,
        compartment_id_in_subtree=__ret__.compartment_id_in_subtree,
        filters=__ret__.filters,
        id=__ret__.id,
        name=__ret__.name,
        profile_level_collections=__ret__.profile_level_collections,
        recommendation_name=__ret__.recommendation_name)


@_utilities.lift_output_func(get_profile_levels)
def get_profile_levels_output(compartment_id: Optional[pulumi.Input[str]] = None,
                              compartment_id_in_subtree: Optional[pulumi.Input[bool]] = None,
                              filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetProfileLevelsFilterArgs']]]]] = None,
                              name: Optional[pulumi.Input[Optional[str]]] = None,
                              recommendation_name: Optional[pulumi.Input[Optional[str]]] = None,
                              opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetProfileLevelsResult]:
    """
    This data source provides the list of Profile Levels in Oracle Cloud Infrastructure Optimizer service.

    Lists the existing profile levels.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_profile_levels = oci.Optimizer.get_profile_levels(compartment_id=var["compartment_id"],
        compartment_id_in_subtree=var["profile_level_compartment_id_in_subtree"],
        name=var["profile_level_name"],
        recommendation_name=oci_optimizer_recommendation["test_recommendation"]["name"])
    ```


    :param str compartment_id: The OCID of the compartment.
    :param bool compartment_id_in_subtree: When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
    :param str name: Optional. A filter that returns results that match the name specified.
    :param str recommendation_name: Optional. A filter that returns results that match the recommendation name specified.
    """
    ...