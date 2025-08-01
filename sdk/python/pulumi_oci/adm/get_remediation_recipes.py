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
    'GetRemediationRecipesResult',
    'AwaitableGetRemediationRecipesResult',
    'get_remediation_recipes',
    'get_remediation_recipes_output',
]

@pulumi.output_type
class GetRemediationRecipesResult:
    """
    A collection of values returned by getRemediationRecipes.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, id=None, remediation_recipe_collections=None, state=None):
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
        if remediation_recipe_collections and not isinstance(remediation_recipe_collections, list):
            raise TypeError("Expected argument 'remediation_recipe_collections' to be a list")
        pulumi.set(__self__, "remediation_recipe_collections", remediation_recipe_collections)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        """
        The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation recipe.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        The name of the Remediation Recipe.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetRemediationRecipesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> Optional[_builtins.str]:
        """
        The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation recipe.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="remediationRecipeCollections")
    def remediation_recipe_collections(self) -> Sequence['outputs.GetRemediationRecipesRemediationRecipeCollectionResult']:
        """
        The list of remediation_recipe_collection.
        """
        return pulumi.get(self, "remediation_recipe_collections")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current lifecycle state of the Remediation Recipe.
        """
        return pulumi.get(self, "state")


class AwaitableGetRemediationRecipesResult(GetRemediationRecipesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetRemediationRecipesResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            remediation_recipe_collections=self.remediation_recipe_collections,
            state=self.state)


def get_remediation_recipes(compartment_id: Optional[_builtins.str] = None,
                            display_name: Optional[_builtins.str] = None,
                            filters: Optional[Sequence[Union['GetRemediationRecipesFilterArgs', 'GetRemediationRecipesFilterArgsDict']]] = None,
                            id: Optional[_builtins.str] = None,
                            state: Optional[_builtins.str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetRemediationRecipesResult:
    """
    This data source provides the list of Remediation Recipes in Oracle Cloud Infrastructure Adm service.

    Returns a list of Remediation Recipes based on the specified query parameters.
    The query parameters `compartmentId` or `id` must be provided.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_remediation_recipes = oci.Adm.get_remediation_recipes(compartment_id=compartment_id,
        display_name=remediation_recipe_display_name,
        id=remediation_recipe_id,
        state=remediation_recipe_state)
    ```


    :param _builtins.str compartment_id: A filter to return only resources that belong to the specified compartment identifier. Required only if the id query param is not specified.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str id: A filter to return only resources that match the specified identifier. Required only if the compartmentId query parameter is not specified.
    :param _builtins.str state: A filter to return only Remediation Recipes that match the specified lifecycleState.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Adm/getRemediationRecipes:getRemediationRecipes', __args__, opts=opts, typ=GetRemediationRecipesResult).value

    return AwaitableGetRemediationRecipesResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        remediation_recipe_collections=pulumi.get(__ret__, 'remediation_recipe_collections'),
        state=pulumi.get(__ret__, 'state'))
def get_remediation_recipes_output(compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   filters: Optional[pulumi.Input[Optional[Sequence[Union['GetRemediationRecipesFilterArgs', 'GetRemediationRecipesFilterArgsDict']]]]] = None,
                                   id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetRemediationRecipesResult]:
    """
    This data source provides the list of Remediation Recipes in Oracle Cloud Infrastructure Adm service.

    Returns a list of Remediation Recipes based on the specified query parameters.
    The query parameters `compartmentId` or `id` must be provided.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_remediation_recipes = oci.Adm.get_remediation_recipes(compartment_id=compartment_id,
        display_name=remediation_recipe_display_name,
        id=remediation_recipe_id,
        state=remediation_recipe_state)
    ```


    :param _builtins.str compartment_id: A filter to return only resources that belong to the specified compartment identifier. Required only if the id query param is not specified.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str id: A filter to return only resources that match the specified identifier. Required only if the compartmentId query parameter is not specified.
    :param _builtins.str state: A filter to return only Remediation Recipes that match the specified lifecycleState.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Adm/getRemediationRecipes:getRemediationRecipes', __args__, opts=opts, typ=GetRemediationRecipesResult)
    return __ret__.apply(lambda __response__: GetRemediationRecipesResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        remediation_recipe_collections=pulumi.get(__response__, 'remediation_recipe_collections'),
        state=pulumi.get(__response__, 'state')))
