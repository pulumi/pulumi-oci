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
    'GetCategoriesResult',
    'AwaitableGetCategoriesResult',
    'get_categories',
    'get_categories_output',
]

@pulumi.output_type
class GetCategoriesResult:
    """
    A collection of values returned by getCategories.
    """
    def __init__(__self__, category_collections=None, child_tenancy_ids=None, compartment_id=None, compartment_id_in_subtree=None, filters=None, id=None, include_organization=None, name=None, state=None):
        if category_collections and not isinstance(category_collections, list):
            raise TypeError("Expected argument 'category_collections' to be a list")
        pulumi.set(__self__, "category_collections", category_collections)
        if child_tenancy_ids and not isinstance(child_tenancy_ids, list):
            raise TypeError("Expected argument 'child_tenancy_ids' to be a list")
        pulumi.set(__self__, "child_tenancy_ids", child_tenancy_ids)
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
        if include_organization and not isinstance(include_organization, bool):
            raise TypeError("Expected argument 'include_organization' to be a bool")
        pulumi.set(__self__, "include_organization", include_organization)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="categoryCollections")
    def category_collections(self) -> Sequence['outputs.GetCategoriesCategoryCollectionResult']:
        """
        The list of category_collection.
        """
        return pulumi.get(self, "category_collections")

    @property
    @pulumi.getter(name="childTenancyIds")
    def child_tenancy_ids(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "child_tenancy_ids")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the tenancy. The tenancy is the root compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> bool:
        return pulumi.get(self, "compartment_id_in_subtree")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetCategoriesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="includeOrganization")
    def include_organization(self) -> Optional[bool]:
        return pulumi.get(self, "include_organization")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        The name assigned to the category.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The category's current state.
        """
        return pulumi.get(self, "state")


class AwaitableGetCategoriesResult(GetCategoriesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetCategoriesResult(
            category_collections=self.category_collections,
            child_tenancy_ids=self.child_tenancy_ids,
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            filters=self.filters,
            id=self.id,
            include_organization=self.include_organization,
            name=self.name,
            state=self.state)


def get_categories(child_tenancy_ids: Optional[Sequence[str]] = None,
                   compartment_id: Optional[str] = None,
                   compartment_id_in_subtree: Optional[bool] = None,
                   filters: Optional[Sequence[pulumi.InputType['GetCategoriesFilterArgs']]] = None,
                   include_organization: Optional[bool] = None,
                   name: Optional[str] = None,
                   state: Optional[str] = None,
                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetCategoriesResult:
    """
    This data source provides the list of Categories in Oracle Cloud Infrastructure Optimizer service.

    Lists the supported Cloud Advisor categories.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_categories = oci.Optimizer.get_categories(compartment_id=var["compartment_id"],
        compartment_id_in_subtree=var["category_compartment_id_in_subtree"],
        child_tenancy_ids=var["category_child_tenancy_ids"],
        include_organization=var["category_include_organization"],
        name=var["category_name"],
        state=var["category_state"])
    ```


    :param Sequence[str] child_tenancy_ids: A list of child tenancies for which the respective data will be returned. Please note that  the parent tenancy id can also be included in this list. For example, if there is a parent P with two children A and B, to return results of only parent P and child A, this list should be populated with  tenancy id of parent P and child A.
    :param str compartment_id: The OCID of the compartment.
    :param bool compartment_id_in_subtree: When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
    :param bool include_organization: When set to true, the data for all child tenancies including the parent is returned. That is, if  there is an organization with parent P and children A and B, to return the data for the parent P, child  A and child B, this parameter value should be set to true.
    :param str name: Optional. A filter that returns results that match the name specified.
    :param str state: A filter that returns results that match the lifecycle state specified.
    """
    __args__ = dict()
    __args__['childTenancyIds'] = child_tenancy_ids
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['filters'] = filters
    __args__['includeOrganization'] = include_organization
    __args__['name'] = name
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Optimizer/getCategories:getCategories', __args__, opts=opts, typ=GetCategoriesResult).value

    return AwaitableGetCategoriesResult(
        category_collections=__ret__.category_collections,
        child_tenancy_ids=__ret__.child_tenancy_ids,
        compartment_id=__ret__.compartment_id,
        compartment_id_in_subtree=__ret__.compartment_id_in_subtree,
        filters=__ret__.filters,
        id=__ret__.id,
        include_organization=__ret__.include_organization,
        name=__ret__.name,
        state=__ret__.state)


@_utilities.lift_output_func(get_categories)
def get_categories_output(child_tenancy_ids: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                          compartment_id: Optional[pulumi.Input[str]] = None,
                          compartment_id_in_subtree: Optional[pulumi.Input[bool]] = None,
                          filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetCategoriesFilterArgs']]]]] = None,
                          include_organization: Optional[pulumi.Input[Optional[bool]]] = None,
                          name: Optional[pulumi.Input[Optional[str]]] = None,
                          state: Optional[pulumi.Input[Optional[str]]] = None,
                          opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetCategoriesResult]:
    """
    This data source provides the list of Categories in Oracle Cloud Infrastructure Optimizer service.

    Lists the supported Cloud Advisor categories.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_categories = oci.Optimizer.get_categories(compartment_id=var["compartment_id"],
        compartment_id_in_subtree=var["category_compartment_id_in_subtree"],
        child_tenancy_ids=var["category_child_tenancy_ids"],
        include_organization=var["category_include_organization"],
        name=var["category_name"],
        state=var["category_state"])
    ```


    :param Sequence[str] child_tenancy_ids: A list of child tenancies for which the respective data will be returned. Please note that  the parent tenancy id can also be included in this list. For example, if there is a parent P with two children A and B, to return results of only parent P and child A, this list should be populated with  tenancy id of parent P and child A.
    :param str compartment_id: The OCID of the compartment.
    :param bool compartment_id_in_subtree: When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
    :param bool include_organization: When set to true, the data for all child tenancies including the parent is returned. That is, if  there is an organization with parent P and children A and B, to return the data for the parent P, child  A and child B, this parameter value should be set to true.
    :param str name: Optional. A filter that returns results that match the name specified.
    :param str state: A filter that returns results that match the lifecycle state specified.
    """
    ...