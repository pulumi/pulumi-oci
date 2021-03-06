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
    'GetClusterNetworksResult',
    'AwaitableGetClusterNetworksResult',
    'get_cluster_networks',
    'get_cluster_networks_output',
]

@pulumi.output_type
class GetClusterNetworksResult:
    """
    A collection of values returned by getClusterNetworks.
    """
    def __init__(__self__, cluster_networks=None, compartment_id=None, display_name=None, filters=None, id=None, state=None):
        if cluster_networks and not isinstance(cluster_networks, list):
            raise TypeError("Expected argument 'cluster_networks' to be a list")
        pulumi.set(__self__, "cluster_networks", cluster_networks)
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
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="clusterNetworks")
    def cluster_networks(self) -> Sequence['outputs.GetClusterNetworksClusterNetworkResult']:
        """
        The list of cluster_networks.
        """
        return pulumi.get(self, "cluster_networks")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetClusterNetworksFilterResult']]:
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
    def state(self) -> Optional[str]:
        """
        The current state of the cluster network.
        """
        return pulumi.get(self, "state")


class AwaitableGetClusterNetworksResult(GetClusterNetworksResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetClusterNetworksResult(
            cluster_networks=self.cluster_networks,
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            state=self.state)


def get_cluster_networks(compartment_id: Optional[str] = None,
                         display_name: Optional[str] = None,
                         filters: Optional[Sequence[pulumi.InputType['GetClusterNetworksFilterArgs']]] = None,
                         state: Optional[str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetClusterNetworksResult:
    """
    This data source provides the list of Cluster Networks in Oracle Cloud Infrastructure Core service.

    Lists the cluster networks in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_cluster_networks = oci.Core.get_cluster_networks(compartment_id=var["compartment_id"],
        display_name=var["cluster_network_display_name"],
        state=var["cluster_network_state"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str display_name: A filter to return only resources that match the given display name exactly.
    :param str state: A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:Core/getClusterNetworks:getClusterNetworks', __args__, opts=opts, typ=GetClusterNetworksResult).value

    return AwaitableGetClusterNetworksResult(
        cluster_networks=__ret__.cluster_networks,
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        state=__ret__.state)


@_utilities.lift_output_func(get_cluster_networks)
def get_cluster_networks_output(compartment_id: Optional[pulumi.Input[str]] = None,
                                display_name: Optional[pulumi.Input[Optional[str]]] = None,
                                filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetClusterNetworksFilterArgs']]]]] = None,
                                state: Optional[pulumi.Input[Optional[str]]] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetClusterNetworksResult]:
    """
    This data source provides the list of Cluster Networks in Oracle Cloud Infrastructure Core service.

    Lists the cluster networks in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_cluster_networks = oci.Core.get_cluster_networks(compartment_id=var["compartment_id"],
        display_name=var["cluster_network_display_name"],
        state=var["cluster_network_state"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str display_name: A filter to return only resources that match the given display name exactly.
    :param str state: A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
    """
    ...
