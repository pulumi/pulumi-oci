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
    'GetProtectionPoliciesResult',
    'AwaitableGetProtectionPoliciesResult',
    'get_protection_policies',
    'get_protection_policies_output',
]

@pulumi.output_type
class GetProtectionPoliciesResult:
    """
    A collection of values returned by getProtectionPolicies.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, id=None, owner=None, protection_policy_collections=None, protection_policy_id=None, state=None):
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
        if owner and not isinstance(owner, str):
            raise TypeError("Expected argument 'owner' to be a str")
        pulumi.set(__self__, "owner", owner)
        if protection_policy_collections and not isinstance(protection_policy_collections, list):
            raise TypeError("Expected argument 'protection_policy_collections' to be a list")
        pulumi.set(__self__, "protection_policy_collections", protection_policy_collections)
        if protection_policy_id and not isinstance(protection_policy_id, str):
            raise TypeError("Expected argument 'protection_policy_id' to be a str")
        pulumi.set(__self__, "protection_policy_id", protection_policy_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment that contains the protection policy.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        A user provided name for the protection policy.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetProtectionPoliciesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def owner(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "owner")

    @_builtins.property
    @pulumi.getter(name="protectionPolicyCollections")
    def protection_policy_collections(self) -> Sequence['outputs.GetProtectionPoliciesProtectionPolicyCollectionResult']:
        """
        The list of protection_policy_collection.
        """
        return pulumi.get(self, "protection_policy_collections")

    @_builtins.property
    @pulumi.getter(name="protectionPolicyId")
    def protection_policy_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "protection_policy_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the protection policy.
        """
        return pulumi.get(self, "state")


class AwaitableGetProtectionPoliciesResult(GetProtectionPoliciesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetProtectionPoliciesResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            owner=self.owner,
            protection_policy_collections=self.protection_policy_collections,
            protection_policy_id=self.protection_policy_id,
            state=self.state)


def get_protection_policies(compartment_id: Optional[_builtins.str] = None,
                            display_name: Optional[_builtins.str] = None,
                            filters: Optional[Sequence[Union['GetProtectionPoliciesFilterArgs', 'GetProtectionPoliciesFilterArgsDict']]] = None,
                            owner: Optional[_builtins.str] = None,
                            protection_policy_id: Optional[_builtins.str] = None,
                            state: Optional[_builtins.str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetProtectionPoliciesResult:
    """
    This data source provides the list of Protection Policies in Oracle Cloud Infrastructure Recovery service.

    Gets a list of protection policies based on the specified parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_protection_policies = oci.RecoveryMod.get_protection_policies(compartment_id=compartment_id,
        display_name=protection_policy_display_name,
        owner=protection_policy_owner,
        protection_policy_id=test_protection_policy["id"],
        state=protection_policy_state)
    ```


    :param _builtins.str compartment_id: The compartment OCID.
    :param _builtins.str display_name: A filter to return only resources that match the entire 'displayname' given.
    :param _builtins.str owner: A filter to return only the policies that match the owner as 'Customer' or 'Oracle'.
    :param _builtins.str protection_policy_id: The protection policy OCID.
    :param _builtins.str state: A filter to return only resources their lifecycleState matches the given lifecycleState.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['owner'] = owner
    __args__['protectionPolicyId'] = protection_policy_id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:RecoveryMod/getProtectionPolicies:getProtectionPolicies', __args__, opts=opts, typ=GetProtectionPoliciesResult).value

    return AwaitableGetProtectionPoliciesResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        owner=pulumi.get(__ret__, 'owner'),
        protection_policy_collections=pulumi.get(__ret__, 'protection_policy_collections'),
        protection_policy_id=pulumi.get(__ret__, 'protection_policy_id'),
        state=pulumi.get(__ret__, 'state'))
def get_protection_policies_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                   display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   filters: Optional[pulumi.Input[Optional[Sequence[Union['GetProtectionPoliciesFilterArgs', 'GetProtectionPoliciesFilterArgsDict']]]]] = None,
                                   owner: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   protection_policy_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetProtectionPoliciesResult]:
    """
    This data source provides the list of Protection Policies in Oracle Cloud Infrastructure Recovery service.

    Gets a list of protection policies based on the specified parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_protection_policies = oci.RecoveryMod.get_protection_policies(compartment_id=compartment_id,
        display_name=protection_policy_display_name,
        owner=protection_policy_owner,
        protection_policy_id=test_protection_policy["id"],
        state=protection_policy_state)
    ```


    :param _builtins.str compartment_id: The compartment OCID.
    :param _builtins.str display_name: A filter to return only resources that match the entire 'displayname' given.
    :param _builtins.str owner: A filter to return only the policies that match the owner as 'Customer' or 'Oracle'.
    :param _builtins.str protection_policy_id: The protection policy OCID.
    :param _builtins.str state: A filter to return only resources their lifecycleState matches the given lifecycleState.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['owner'] = owner
    __args__['protectionPolicyId'] = protection_policy_id
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:RecoveryMod/getProtectionPolicies:getProtectionPolicies', __args__, opts=opts, typ=GetProtectionPoliciesResult)
    return __ret__.apply(lambda __response__: GetProtectionPoliciesResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        owner=pulumi.get(__response__, 'owner'),
        protection_policy_collections=pulumi.get(__response__, 'protection_policy_collections'),
        protection_policy_id=pulumi.get(__response__, 'protection_policy_id'),
        state=pulumi.get(__response__, 'state')))
