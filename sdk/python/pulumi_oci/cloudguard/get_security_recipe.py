# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetSecurityRecipeResult',
    'AwaitableGetSecurityRecipeResult',
    'get_security_recipe',
    'get_security_recipe_output',
]

@pulumi.output_type
class GetSecurityRecipeResult:
    """
    A collection of values returned by getSecurityRecipe.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, id=None, lifecycle_details=None, owner=None, security_policies=None, security_recipe_id=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if owner and not isinstance(owner, str):
            raise TypeError("Expected argument 'owner' to be a str")
        pulumi.set(__self__, "owner", owner)
        if security_policies and not isinstance(security_policies, list):
            raise TypeError("Expected argument 'security_policies' to be a list")
        pulumi.set(__self__, "security_policies", security_policies)
        if security_recipe_id and not isinstance(security_recipe_id, str):
            raise TypeError("Expected argument 'security_recipe_id' to be a str")
        pulumi.set(__self__, "security_recipe_id", security_recipe_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The id of the compartment that contains the recipe
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        The recipe's description
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        The recipe's name
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        Unique identifier that is immutable on creation
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        A message describing the current state in more detail. For example, this can be used to provide actionable information for a recipe in the `Failed` state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter
    def owner(self) -> str:
        """
        The owner of the recipe
        """
        return pulumi.get(self, "owner")

    @property
    @pulumi.getter(name="securityPolicies")
    def security_policies(self) -> Sequence[str]:
        """
        The list of `SecurityPolicy` ids that are included in the recipe
        """
        return pulumi.get(self, "security_policies")

    @property
    @pulumi.getter(name="securityRecipeId")
    def security_recipe_id(self) -> str:
        return pulumi.get(self, "security_recipe_id")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the recipe
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the recipe was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the recipe was last updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetSecurityRecipeResult(GetSecurityRecipeResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSecurityRecipeResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            owner=self.owner,
            security_policies=self.security_policies,
            security_recipe_id=self.security_recipe_id,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_security_recipe(security_recipe_id: Optional[str] = None,
                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSecurityRecipeResult:
    """
    This data source provides details about a specific Security Recipe resource in Oracle Cloud Infrastructure Cloud Guard service.

    Gets a security zone recipe by identifier. A security zone recipe is a collection of security zone policies.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_recipe = oci.CloudGuard.get_security_recipe(security_recipe_id=oci_cloud_guard_security_recipe["test_security_recipe"]["id"])
    ```


    :param str security_recipe_id: The unique identifier of the security zone recipe (`SecurityRecipe`)
    """
    __args__ = dict()
    __args__['securityRecipeId'] = security_recipe_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:CloudGuard/getSecurityRecipe:getSecurityRecipe', __args__, opts=opts, typ=GetSecurityRecipeResult).value

    return AwaitableGetSecurityRecipeResult(
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        description=__ret__.description,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        lifecycle_details=__ret__.lifecycle_details,
        owner=__ret__.owner,
        security_policies=__ret__.security_policies,
        security_recipe_id=__ret__.security_recipe_id,
        state=__ret__.state,
        system_tags=__ret__.system_tags,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)


@_utilities.lift_output_func(get_security_recipe)
def get_security_recipe_output(security_recipe_id: Optional[pulumi.Input[str]] = None,
                               opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetSecurityRecipeResult]:
    """
    This data source provides details about a specific Security Recipe resource in Oracle Cloud Infrastructure Cloud Guard service.

    Gets a security zone recipe by identifier. A security zone recipe is a collection of security zone policies.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_recipe = oci.CloudGuard.get_security_recipe(security_recipe_id=oci_cloud_guard_security_recipe["test_security_recipe"]["id"])
    ```


    :param str security_recipe_id: The unique identifier of the security zone recipe (`SecurityRecipe`)
    """
    ...