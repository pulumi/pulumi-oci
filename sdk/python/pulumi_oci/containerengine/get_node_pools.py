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
    'GetNodePoolsResult',
    'AwaitableGetNodePoolsResult',
    'get_node_pools',
    'get_node_pools_output',
]

@pulumi.output_type
class GetNodePoolsResult:
    """
    A collection of values returned by getNodePools.
    """
    def __init__(__self__, cluster_id=None, compartment_id=None, filters=None, id=None, name=None, node_pools=None, states=None):
        if cluster_id and not isinstance(cluster_id, str):
            raise TypeError("Expected argument 'cluster_id' to be a str")
        pulumi.set(__self__, "cluster_id", cluster_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if node_pools and not isinstance(node_pools, list):
            raise TypeError("Expected argument 'node_pools' to be a list")
        pulumi.set(__self__, "node_pools", node_pools)
        if states and not isinstance(states, list):
            raise TypeError("Expected argument 'states' to be a list")
        pulumi.set(__self__, "states", states)

    @property
    @pulumi.getter(name="clusterId")
    def cluster_id(self) -> Optional[str]:
        """
        The OCID of the cluster to which this node pool is attached.
        """
        return pulumi.get(self, "cluster_id")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment in which the node pool exists.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetNodePoolsFilterResult']]:
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
        The name of the node.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="nodePools")
    def node_pools(self) -> Sequence['outputs.GetNodePoolsNodePoolResult']:
        """
        The list of node_pools.
        """
        return pulumi.get(self, "node_pools")

    @property
    @pulumi.getter
    def states(self) -> Optional[Sequence[str]]:
        """
        The state of the nodepool.
        """
        return pulumi.get(self, "states")


class AwaitableGetNodePoolsResult(GetNodePoolsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNodePoolsResult(
            cluster_id=self.cluster_id,
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            name=self.name,
            node_pools=self.node_pools,
            states=self.states)


def get_node_pools(cluster_id: Optional[str] = None,
                   compartment_id: Optional[str] = None,
                   filters: Optional[Sequence[pulumi.InputType['GetNodePoolsFilterArgs']]] = None,
                   name: Optional[str] = None,
                   states: Optional[Sequence[str]] = None,
                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNodePoolsResult:
    """
    This data source provides the list of Node Pools in Oracle Cloud Infrastructure Container Engine service.

    List all the node pools in a compartment, and optionally filter by cluster.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_node_pools = oci.ContainerEngine.get_node_pools(compartment_id=var["compartment_id"],
        cluster_id=oci_containerengine_cluster["test_cluster"]["id"],
        name=var["node_pool_name"],
        states=var["node_pool_state"])
    ```


    :param str cluster_id: The OCID of the cluster.
    :param str compartment_id: The OCID of the compartment.
    :param str name: The name to filter on.
    :param Sequence[str] states: A list of nodepool lifecycle states on which to filter on, matching any of the list items (OR logic). eg. [ACTIVE, DELETING]
    """
    __args__ = dict()
    __args__['clusterId'] = cluster_id
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['states'] = states
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ContainerEngine/getNodePools:getNodePools', __args__, opts=opts, typ=GetNodePoolsResult).value

    return AwaitableGetNodePoolsResult(
        cluster_id=__ret__.cluster_id,
        compartment_id=__ret__.compartment_id,
        filters=__ret__.filters,
        id=__ret__.id,
        name=__ret__.name,
        node_pools=__ret__.node_pools,
        states=__ret__.states)


@_utilities.lift_output_func(get_node_pools)
def get_node_pools_output(cluster_id: Optional[pulumi.Input[Optional[str]]] = None,
                          compartment_id: Optional[pulumi.Input[str]] = None,
                          filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetNodePoolsFilterArgs']]]]] = None,
                          name: Optional[pulumi.Input[Optional[str]]] = None,
                          states: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                          opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetNodePoolsResult]:
    """
    This data source provides the list of Node Pools in Oracle Cloud Infrastructure Container Engine service.

    List all the node pools in a compartment, and optionally filter by cluster.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_node_pools = oci.ContainerEngine.get_node_pools(compartment_id=var["compartment_id"],
        cluster_id=oci_containerengine_cluster["test_cluster"]["id"],
        name=var["node_pool_name"],
        states=var["node_pool_state"])
    ```


    :param str cluster_id: The OCID of the cluster.
    :param str compartment_id: The OCID of the compartment.
    :param str name: The name to filter on.
    :param Sequence[str] states: A list of nodepool lifecycle states on which to filter on, matching any of the list items (OR logic). eg. [ACTIVE, DELETING]
    """
    ...