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

__all__ = [
    'GetNodePoolResult',
    'AwaitableGetNodePoolResult',
    'get_node_pool',
    'get_node_pool_output',
]

@pulumi.output_type
class GetNodePoolResult:
    """
    A collection of values returned by getNodePool.
    """
    def __init__(__self__, cluster_id=None, compartment_id=None, defined_tags=None, freeform_tags=None, id=None, initial_node_labels=None, kubernetes_version=None, lifecycle_details=None, name=None, node_config_details=None, node_eviction_node_pool_settings=None, node_image_id=None, node_image_name=None, node_metadata=None, node_pool_cycling_details=None, node_pool_id=None, node_shape=None, node_shape_configs=None, node_source_details=None, node_sources=None, nodes=None, quantity_per_subnet=None, ssh_public_key=None, state=None, subnet_ids=None):
        if cluster_id and not isinstance(cluster_id, str):
            raise TypeError("Expected argument 'cluster_id' to be a str")
        pulumi.set(__self__, "cluster_id", cluster_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if initial_node_labels and not isinstance(initial_node_labels, list):
            raise TypeError("Expected argument 'initial_node_labels' to be a list")
        pulumi.set(__self__, "initial_node_labels", initial_node_labels)
        if kubernetes_version and not isinstance(kubernetes_version, str):
            raise TypeError("Expected argument 'kubernetes_version' to be a str")
        pulumi.set(__self__, "kubernetes_version", kubernetes_version)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if node_config_details and not isinstance(node_config_details, list):
            raise TypeError("Expected argument 'node_config_details' to be a list")
        pulumi.set(__self__, "node_config_details", node_config_details)
        if node_eviction_node_pool_settings and not isinstance(node_eviction_node_pool_settings, list):
            raise TypeError("Expected argument 'node_eviction_node_pool_settings' to be a list")
        pulumi.set(__self__, "node_eviction_node_pool_settings", node_eviction_node_pool_settings)
        if node_image_id and not isinstance(node_image_id, str):
            raise TypeError("Expected argument 'node_image_id' to be a str")
        pulumi.set(__self__, "node_image_id", node_image_id)
        if node_image_name and not isinstance(node_image_name, str):
            raise TypeError("Expected argument 'node_image_name' to be a str")
        pulumi.set(__self__, "node_image_name", node_image_name)
        if node_metadata and not isinstance(node_metadata, dict):
            raise TypeError("Expected argument 'node_metadata' to be a dict")
        pulumi.set(__self__, "node_metadata", node_metadata)
        if node_pool_cycling_details and not isinstance(node_pool_cycling_details, list):
            raise TypeError("Expected argument 'node_pool_cycling_details' to be a list")
        pulumi.set(__self__, "node_pool_cycling_details", node_pool_cycling_details)
        if node_pool_id and not isinstance(node_pool_id, str):
            raise TypeError("Expected argument 'node_pool_id' to be a str")
        pulumi.set(__self__, "node_pool_id", node_pool_id)
        if node_shape and not isinstance(node_shape, str):
            raise TypeError("Expected argument 'node_shape' to be a str")
        pulumi.set(__self__, "node_shape", node_shape)
        if node_shape_configs and not isinstance(node_shape_configs, list):
            raise TypeError("Expected argument 'node_shape_configs' to be a list")
        pulumi.set(__self__, "node_shape_configs", node_shape_configs)
        if node_source_details and not isinstance(node_source_details, list):
            raise TypeError("Expected argument 'node_source_details' to be a list")
        pulumi.set(__self__, "node_source_details", node_source_details)
        if node_sources and not isinstance(node_sources, list):
            raise TypeError("Expected argument 'node_sources' to be a list")
        pulumi.set(__self__, "node_sources", node_sources)
        if nodes and not isinstance(nodes, list):
            raise TypeError("Expected argument 'nodes' to be a list")
        pulumi.set(__self__, "nodes", nodes)
        if quantity_per_subnet and not isinstance(quantity_per_subnet, int):
            raise TypeError("Expected argument 'quantity_per_subnet' to be a int")
        pulumi.set(__self__, "quantity_per_subnet", quantity_per_subnet)
        if ssh_public_key and not isinstance(ssh_public_key, str):
            raise TypeError("Expected argument 'ssh_public_key' to be a str")
        pulumi.set(__self__, "ssh_public_key", ssh_public_key)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if subnet_ids and not isinstance(subnet_ids, list):
            raise TypeError("Expected argument 'subnet_ids' to be a list")
        pulumi.set(__self__, "subnet_ids", subnet_ids)

    @_builtins.property
    @pulumi.getter(name="clusterId")
    def cluster_id(self) -> _builtins.str:
        """
        The OCID of the cluster to which this node pool is attached.
        """
        return pulumi.get(self, "cluster_id")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment in which the node pool exists.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The OCID of the compute instance backing this node.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="initialNodeLabels")
    def initial_node_labels(self) -> Sequence['outputs.GetNodePoolInitialNodeLabelResult']:
        """
        A list of key/value pairs to add to nodes after they join the Kubernetes cluster.
        """
        return pulumi.get(self, "initial_node_labels")

    @_builtins.property
    @pulumi.getter(name="kubernetesVersion")
    def kubernetes_version(self) -> _builtins.str:
        """
        The version of Kubernetes this node is running.
        """
        return pulumi.get(self, "kubernetes_version")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        Details about the state of the node.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name of the node.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="nodeConfigDetails")
    def node_config_details(self) -> Sequence['outputs.GetNodePoolNodeConfigDetailResult']:
        """
        The configuration of nodes in the node pool.
        """
        return pulumi.get(self, "node_config_details")

    @_builtins.property
    @pulumi.getter(name="nodeEvictionNodePoolSettings")
    def node_eviction_node_pool_settings(self) -> Sequence['outputs.GetNodePoolNodeEvictionNodePoolSettingResult']:
        """
        Node Eviction Details configuration
        """
        return pulumi.get(self, "node_eviction_node_pool_settings")

    @_builtins.property
    @pulumi.getter(name="nodeImageId")
    @_utilities.deprecated("""The 'node_image_id' field has been deprecated. Please use 'node_source_details' instead. If both fields are specified, then 'node_source_details' will be used.""")
    def node_image_id(self) -> _builtins.str:
        """
        Deprecated. see `nodeSource`. The OCID of the image running on the nodes in the node pool.
        """
        return pulumi.get(self, "node_image_id")

    @_builtins.property
    @pulumi.getter(name="nodeImageName")
    @_utilities.deprecated("""The 'node_image_name' field has been deprecated. Please use 'node_source_details' instead. If both fields are specified, then 'node_source_details' will be used.""")
    def node_image_name(self) -> _builtins.str:
        """
        Deprecated. see `nodeSource`. The name of the image running on the nodes in the node pool.
        """
        return pulumi.get(self, "node_image_name")

    @_builtins.property
    @pulumi.getter(name="nodeMetadata")
    def node_metadata(self) -> Mapping[str, _builtins.str]:
        """
        A list of key/value pairs to add to each underlying Oracle Cloud Infrastructure instance in the node pool on launch.
        """
        return pulumi.get(self, "node_metadata")

    @_builtins.property
    @pulumi.getter(name="nodePoolCyclingDetails")
    def node_pool_cycling_details(self) -> Sequence['outputs.GetNodePoolNodePoolCyclingDetailResult']:
        """
        Node Pool Cycling Details
        """
        return pulumi.get(self, "node_pool_cycling_details")

    @_builtins.property
    @pulumi.getter(name="nodePoolId")
    def node_pool_id(self) -> _builtins.str:
        """
        The OCID of the node pool to which this node belongs.
        """
        return pulumi.get(self, "node_pool_id")

    @_builtins.property
    @pulumi.getter(name="nodeShape")
    def node_shape(self) -> _builtins.str:
        """
        The name of the node shape of the nodes in the node pool.
        """
        return pulumi.get(self, "node_shape")

    @_builtins.property
    @pulumi.getter(name="nodeShapeConfigs")
    def node_shape_configs(self) -> Sequence['outputs.GetNodePoolNodeShapeConfigResult']:
        """
        The shape configuration of the nodes.
        """
        return pulumi.get(self, "node_shape_configs")

    @_builtins.property
    @pulumi.getter(name="nodeSourceDetails")
    def node_source_details(self) -> Sequence['outputs.GetNodePoolNodeSourceDetailResult']:
        """
        Source running on the nodes in the node pool.
        """
        return pulumi.get(self, "node_source_details")

    @_builtins.property
    @pulumi.getter(name="nodeSources")
    def node_sources(self) -> Sequence['outputs.GetNodePoolNodeSourceResult']:
        """
        Deprecated. see `nodeSourceDetails`. Source running on the nodes in the node pool.
        """
        return pulumi.get(self, "node_sources")

    @_builtins.property
    @pulumi.getter
    def nodes(self) -> Sequence['outputs.GetNodePoolNodeResult']:
        """
        The nodes in the node pool.
        """
        return pulumi.get(self, "nodes")

    @_builtins.property
    @pulumi.getter(name="quantityPerSubnet")
    def quantity_per_subnet(self) -> _builtins.int:
        """
        The number of nodes in each subnet.
        """
        return pulumi.get(self, "quantity_per_subnet")

    @_builtins.property
    @pulumi.getter(name="sshPublicKey")
    def ssh_public_key(self) -> _builtins.str:
        """
        The SSH public key on each node in the node pool on launch.
        """
        return pulumi.get(self, "ssh_public_key")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The state of the nodepool.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="subnetIds")
    def subnet_ids(self) -> Sequence[_builtins.str]:
        """
        The OCIDs of the subnets in which to place nodes for this node pool.
        """
        return pulumi.get(self, "subnet_ids")


class AwaitableGetNodePoolResult(GetNodePoolResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNodePoolResult(
            cluster_id=self.cluster_id,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            freeform_tags=self.freeform_tags,
            id=self.id,
            initial_node_labels=self.initial_node_labels,
            kubernetes_version=self.kubernetes_version,
            lifecycle_details=self.lifecycle_details,
            name=self.name,
            node_config_details=self.node_config_details,
            node_eviction_node_pool_settings=self.node_eviction_node_pool_settings,
            node_image_id=self.node_image_id,
            node_image_name=self.node_image_name,
            node_metadata=self.node_metadata,
            node_pool_cycling_details=self.node_pool_cycling_details,
            node_pool_id=self.node_pool_id,
            node_shape=self.node_shape,
            node_shape_configs=self.node_shape_configs,
            node_source_details=self.node_source_details,
            node_sources=self.node_sources,
            nodes=self.nodes,
            quantity_per_subnet=self.quantity_per_subnet,
            ssh_public_key=self.ssh_public_key,
            state=self.state,
            subnet_ids=self.subnet_ids)


def get_node_pool(node_pool_id: Optional[_builtins.str] = None,
                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNodePoolResult:
    """
    This data source provides details about a specific Node Pool resource in Oracle Cloud Infrastructure Container Engine service.

    Get the details of a node pool.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_node_pool = oci.ContainerEngine.get_node_pool(node_pool_id=test_node_pool_oci_containerengine_node_pool["id"])
    ```


    :param _builtins.str node_pool_id: The OCID of the node pool.
    """
    __args__ = dict()
    __args__['nodePoolId'] = node_pool_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ContainerEngine/getNodePool:getNodePool', __args__, opts=opts, typ=GetNodePoolResult).value

    return AwaitableGetNodePoolResult(
        cluster_id=pulumi.get(__ret__, 'cluster_id'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        initial_node_labels=pulumi.get(__ret__, 'initial_node_labels'),
        kubernetes_version=pulumi.get(__ret__, 'kubernetes_version'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        name=pulumi.get(__ret__, 'name'),
        node_config_details=pulumi.get(__ret__, 'node_config_details'),
        node_eviction_node_pool_settings=pulumi.get(__ret__, 'node_eviction_node_pool_settings'),
        node_image_id=pulumi.get(__ret__, 'node_image_id'),
        node_image_name=pulumi.get(__ret__, 'node_image_name'),
        node_metadata=pulumi.get(__ret__, 'node_metadata'),
        node_pool_cycling_details=pulumi.get(__ret__, 'node_pool_cycling_details'),
        node_pool_id=pulumi.get(__ret__, 'node_pool_id'),
        node_shape=pulumi.get(__ret__, 'node_shape'),
        node_shape_configs=pulumi.get(__ret__, 'node_shape_configs'),
        node_source_details=pulumi.get(__ret__, 'node_source_details'),
        node_sources=pulumi.get(__ret__, 'node_sources'),
        nodes=pulumi.get(__ret__, 'nodes'),
        quantity_per_subnet=pulumi.get(__ret__, 'quantity_per_subnet'),
        ssh_public_key=pulumi.get(__ret__, 'ssh_public_key'),
        state=pulumi.get(__ret__, 'state'),
        subnet_ids=pulumi.get(__ret__, 'subnet_ids'))
def get_node_pool_output(node_pool_id: Optional[pulumi.Input[_builtins.str]] = None,
                         opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetNodePoolResult]:
    """
    This data source provides details about a specific Node Pool resource in Oracle Cloud Infrastructure Container Engine service.

    Get the details of a node pool.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_node_pool = oci.ContainerEngine.get_node_pool(node_pool_id=test_node_pool_oci_containerengine_node_pool["id"])
    ```


    :param _builtins.str node_pool_id: The OCID of the node pool.
    """
    __args__ = dict()
    __args__['nodePoolId'] = node_pool_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:ContainerEngine/getNodePool:getNodePool', __args__, opts=opts, typ=GetNodePoolResult)
    return __ret__.apply(lambda __response__: GetNodePoolResult(
        cluster_id=pulumi.get(__response__, 'cluster_id'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        initial_node_labels=pulumi.get(__response__, 'initial_node_labels'),
        kubernetes_version=pulumi.get(__response__, 'kubernetes_version'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        name=pulumi.get(__response__, 'name'),
        node_config_details=pulumi.get(__response__, 'node_config_details'),
        node_eviction_node_pool_settings=pulumi.get(__response__, 'node_eviction_node_pool_settings'),
        node_image_id=pulumi.get(__response__, 'node_image_id'),
        node_image_name=pulumi.get(__response__, 'node_image_name'),
        node_metadata=pulumi.get(__response__, 'node_metadata'),
        node_pool_cycling_details=pulumi.get(__response__, 'node_pool_cycling_details'),
        node_pool_id=pulumi.get(__response__, 'node_pool_id'),
        node_shape=pulumi.get(__response__, 'node_shape'),
        node_shape_configs=pulumi.get(__response__, 'node_shape_configs'),
        node_source_details=pulumi.get(__response__, 'node_source_details'),
        node_sources=pulumi.get(__response__, 'node_sources'),
        nodes=pulumi.get(__response__, 'nodes'),
        quantity_per_subnet=pulumi.get(__response__, 'quantity_per_subnet'),
        ssh_public_key=pulumi.get(__response__, 'ssh_public_key'),
        state=pulumi.get(__response__, 'state'),
        subnet_ids=pulumi.get(__response__, 'subnet_ids')))
