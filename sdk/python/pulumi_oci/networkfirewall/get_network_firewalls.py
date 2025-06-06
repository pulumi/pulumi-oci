# coding=utf-8
# *** WARNING: this file was generated by pulumi-language-python. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import builtins
import copy
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
    'GetNetworkFirewallsResult',
    'AwaitableGetNetworkFirewallsResult',
    'get_network_firewalls',
    'get_network_firewalls_output',
]

@pulumi.output_type
class GetNetworkFirewallsResult:
    """
    A collection of values returned by getNetworkFirewalls.
    """
    def __init__(__self__, availability_domain=None, compartment_id=None, display_name=None, filters=None, id=None, network_firewall_collections=None, network_firewall_policy_id=None, state=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
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
        if network_firewall_collections and not isinstance(network_firewall_collections, list):
            raise TypeError("Expected argument 'network_firewall_collections' to be a list")
        pulumi.set(__self__, "network_firewall_collections", network_firewall_collections)
        if network_firewall_policy_id and not isinstance(network_firewall_policy_id, str):
            raise TypeError("Expected argument 'network_firewall_policy_id' to be a str")
        pulumi.set(__self__, "network_firewall_policy_id", network_firewall_policy_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> Optional[builtins.str]:
        """
        Availability Domain where Network Firewall instance is created. To get a list of availability domains for a tenancy, use the [ListAvailabilityDomains](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains) operation. Example: `kIdk:PHX-AD-1`
        """
        return pulumi.get(self, "availability_domain")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Network Firewall.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[builtins.str]:
        """
        A user-friendly name for the Network Firewall. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetNetworkFirewallsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> Optional[builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Network Firewall resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="networkFirewallCollections")
    def network_firewall_collections(self) -> Sequence['outputs.GetNetworkFirewallsNetworkFirewallCollectionResult']:
        """
        The list of network_firewall_collection.
        """
        return pulumi.get(self, "network_firewall_collections")

    @property
    @pulumi.getter(name="networkFirewallPolicyId")
    def network_firewall_policy_id(self) -> Optional[builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Network Firewall Policy.
        """
        return pulumi.get(self, "network_firewall_policy_id")

    @property
    @pulumi.getter
    def state(self) -> Optional[builtins.str]:
        """
        The current state of the Network Firewall.
        """
        return pulumi.get(self, "state")


class AwaitableGetNetworkFirewallsResult(GetNetworkFirewallsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNetworkFirewallsResult(
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            network_firewall_collections=self.network_firewall_collections,
            network_firewall_policy_id=self.network_firewall_policy_id,
            state=self.state)


def get_network_firewalls(availability_domain: Optional[builtins.str] = None,
                          compartment_id: Optional[builtins.str] = None,
                          display_name: Optional[builtins.str] = None,
                          filters: Optional[Sequence[Union['GetNetworkFirewallsFilterArgs', 'GetNetworkFirewallsFilterArgsDict']]] = None,
                          id: Optional[builtins.str] = None,
                          network_firewall_policy_id: Optional[builtins.str] = None,
                          state: Optional[builtins.str] = None,
                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNetworkFirewallsResult:
    """
    This data source provides the list of Network Firewalls in Oracle Cloud Infrastructure Network Firewall service.

    Returns a list of NetworkFirewalls.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_network_firewalls = oci.NetworkFirewall.get_network_firewalls(compartment_id=compartment_id,
        availability_domain=network_firewall_availability_domain,
        display_name=network_firewall_display_name,
        id=network_firewall_id,
        network_firewall_policy_id=test_network_firewall_policy["id"],
        state=network_firewall_state)
    ```


    :param builtins.str availability_domain: A filter to return only resources that are present within the specified availability domain. To get a list of availability domains for a tenancy, use [ListAvailabilityDomains](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains) operation. Example: `kIdk:PHX-AD-1`
    :param builtins.str compartment_id: The ID of the compartment in which to list resources.
    :param builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param builtins.str id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Network Firewall resource.
    :param builtins.str network_firewall_policy_id: A filter to return only resources that match the entire networkFirewallPolicyId given.
    :param builtins.str state: A filter to return only resources with a lifecycleState matching the given value.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['networkFirewallPolicyId'] = network_firewall_policy_id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:NetworkFirewall/getNetworkFirewalls:getNetworkFirewalls', __args__, opts=opts, typ=GetNetworkFirewallsResult).value

    return AwaitableGetNetworkFirewallsResult(
        availability_domain=pulumi.get(__ret__, 'availability_domain'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        network_firewall_collections=pulumi.get(__ret__, 'network_firewall_collections'),
        network_firewall_policy_id=pulumi.get(__ret__, 'network_firewall_policy_id'),
        state=pulumi.get(__ret__, 'state'))
def get_network_firewalls_output(availability_domain: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                 compartment_id: Optional[pulumi.Input[builtins.str]] = None,
                                 display_name: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                 filters: Optional[pulumi.Input[Optional[Sequence[Union['GetNetworkFirewallsFilterArgs', 'GetNetworkFirewallsFilterArgsDict']]]]] = None,
                                 id: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                 network_firewall_policy_id: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                 state: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                 opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetNetworkFirewallsResult]:
    """
    This data source provides the list of Network Firewalls in Oracle Cloud Infrastructure Network Firewall service.

    Returns a list of NetworkFirewalls.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_network_firewalls = oci.NetworkFirewall.get_network_firewalls(compartment_id=compartment_id,
        availability_domain=network_firewall_availability_domain,
        display_name=network_firewall_display_name,
        id=network_firewall_id,
        network_firewall_policy_id=test_network_firewall_policy["id"],
        state=network_firewall_state)
    ```


    :param builtins.str availability_domain: A filter to return only resources that are present within the specified availability domain. To get a list of availability domains for a tenancy, use [ListAvailabilityDomains](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains) operation. Example: `kIdk:PHX-AD-1`
    :param builtins.str compartment_id: The ID of the compartment in which to list resources.
    :param builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param builtins.str id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Network Firewall resource.
    :param builtins.str network_firewall_policy_id: A filter to return only resources that match the entire networkFirewallPolicyId given.
    :param builtins.str state: A filter to return only resources with a lifecycleState matching the given value.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['networkFirewallPolicyId'] = network_firewall_policy_id
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:NetworkFirewall/getNetworkFirewalls:getNetworkFirewalls', __args__, opts=opts, typ=GetNetworkFirewallsResult)
    return __ret__.apply(lambda __response__: GetNetworkFirewallsResult(
        availability_domain=pulumi.get(__response__, 'availability_domain'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        network_firewall_collections=pulumi.get(__response__, 'network_firewall_collections'),
        network_firewall_policy_id=pulumi.get(__response__, 'network_firewall_policy_id'),
        state=pulumi.get(__response__, 'state')))
