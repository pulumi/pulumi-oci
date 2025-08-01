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
    'GetExadbVmClustersResult',
    'AwaitableGetExadbVmClustersResult',
    'get_exadb_vm_clusters',
    'get_exadb_vm_clusters_output',
]

@pulumi.output_type
class GetExadbVmClustersResult:
    """
    A collection of values returned by getExadbVmClusters.
    """
    def __init__(__self__, cluster_placement_group_id=None, compartment_id=None, display_name=None, exadb_vm_clusters=None, exascale_db_storage_vault_id=None, filters=None, id=None, state=None):
        if cluster_placement_group_id and not isinstance(cluster_placement_group_id, str):
            raise TypeError("Expected argument 'cluster_placement_group_id' to be a str")
        pulumi.set(__self__, "cluster_placement_group_id", cluster_placement_group_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if exadb_vm_clusters and not isinstance(exadb_vm_clusters, list):
            raise TypeError("Expected argument 'exadb_vm_clusters' to be a list")
        pulumi.set(__self__, "exadb_vm_clusters", exadb_vm_clusters)
        if exascale_db_storage_vault_id and not isinstance(exascale_db_storage_vault_id, str):
            raise TypeError("Expected argument 'exascale_db_storage_vault_id' to be a str")
        pulumi.set(__self__, "exascale_db_storage_vault_id", exascale_db_storage_vault_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="clusterPlacementGroupId")
    def cluster_placement_group_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group of the Exadata Infrastructure.
        """
        return pulumi.get(self, "cluster_placement_group_id")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        The user-friendly name for the Exadata VM cluster on Exascale Infrastructure. The name does not need to be unique.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="exadbVmClusters")
    def exadb_vm_clusters(self) -> Sequence['outputs.GetExadbVmClustersExadbVmClusterResult']:
        """
        The list of exadb_vm_clusters.
        """
        return pulumi.get(self, "exadb_vm_clusters")

    @_builtins.property
    @pulumi.getter(name="exascaleDbStorageVaultId")
    def exascale_db_storage_vault_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata Database Storage Vault.
        """
        return pulumi.get(self, "exascale_db_storage_vault_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetExadbVmClustersFilterResult']]:
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
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the Exadata VM cluster on Exascale Infrastructure.
        """
        return pulumi.get(self, "state")


class AwaitableGetExadbVmClustersResult(GetExadbVmClustersResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetExadbVmClustersResult(
            cluster_placement_group_id=self.cluster_placement_group_id,
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            exadb_vm_clusters=self.exadb_vm_clusters,
            exascale_db_storage_vault_id=self.exascale_db_storage_vault_id,
            filters=self.filters,
            id=self.id,
            state=self.state)


def get_exadb_vm_clusters(cluster_placement_group_id: Optional[_builtins.str] = None,
                          compartment_id: Optional[_builtins.str] = None,
                          display_name: Optional[_builtins.str] = None,
                          exascale_db_storage_vault_id: Optional[_builtins.str] = None,
                          filters: Optional[Sequence[Union['GetExadbVmClustersFilterArgs', 'GetExadbVmClustersFilterArgsDict']]] = None,
                          state: Optional[_builtins.str] = None,
                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetExadbVmClustersResult:
    """
    This data source provides the list of Exadb Vm Clusters in Oracle Cloud Infrastructure Database service.

    Gets a list of the Exadata VM clusters on Exascale Infrastructure in the specified compartment. Applies to Exadata Database Service on Exascale Infrastructure only.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_exadb_vm_clusters = oci.Database.get_exadb_vm_clusters(compartment_id=compartment_id,
        cluster_placement_group_id=test_cluster_placement_group["id"],
        display_name=exadb_vm_cluster_display_name,
        exascale_db_storage_vault_id=test_exascale_db_storage_vault["id"],
        state=exadb_vm_cluster_state)
    ```


    :param _builtins.str cluster_placement_group_id: A filter to return only resources that match the given cluster placement group ID exactly.
    :param _builtins.str compartment_id: The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given. The match is not case sensitive.
    :param _builtins.str exascale_db_storage_vault_id: A filter to return only Exadata VM clusters on Exascale Infrastructure that match the given Exascale Database Storage Vault ID.
    :param _builtins.str state: A filter to return only Exadata VM clusters on Exascale Infrastructure that match the given lifecycle state exactly.
    """
    __args__ = dict()
    __args__['clusterPlacementGroupId'] = cluster_placement_group_id
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['exascaleDbStorageVaultId'] = exascale_db_storage_vault_id
    __args__['filters'] = filters
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Database/getExadbVmClusters:getExadbVmClusters', __args__, opts=opts, typ=GetExadbVmClustersResult).value

    return AwaitableGetExadbVmClustersResult(
        cluster_placement_group_id=pulumi.get(__ret__, 'cluster_placement_group_id'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        exadb_vm_clusters=pulumi.get(__ret__, 'exadb_vm_clusters'),
        exascale_db_storage_vault_id=pulumi.get(__ret__, 'exascale_db_storage_vault_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        state=pulumi.get(__ret__, 'state'))
def get_exadb_vm_clusters_output(cluster_placement_group_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                 display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                 exascale_db_storage_vault_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                 filters: Optional[pulumi.Input[Optional[Sequence[Union['GetExadbVmClustersFilterArgs', 'GetExadbVmClustersFilterArgsDict']]]]] = None,
                                 state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                 opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetExadbVmClustersResult]:
    """
    This data source provides the list of Exadb Vm Clusters in Oracle Cloud Infrastructure Database service.

    Gets a list of the Exadata VM clusters on Exascale Infrastructure in the specified compartment. Applies to Exadata Database Service on Exascale Infrastructure only.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_exadb_vm_clusters = oci.Database.get_exadb_vm_clusters(compartment_id=compartment_id,
        cluster_placement_group_id=test_cluster_placement_group["id"],
        display_name=exadb_vm_cluster_display_name,
        exascale_db_storage_vault_id=test_exascale_db_storage_vault["id"],
        state=exadb_vm_cluster_state)
    ```


    :param _builtins.str cluster_placement_group_id: A filter to return only resources that match the given cluster placement group ID exactly.
    :param _builtins.str compartment_id: The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given. The match is not case sensitive.
    :param _builtins.str exascale_db_storage_vault_id: A filter to return only Exadata VM clusters on Exascale Infrastructure that match the given Exascale Database Storage Vault ID.
    :param _builtins.str state: A filter to return only Exadata VM clusters on Exascale Infrastructure that match the given lifecycle state exactly.
    """
    __args__ = dict()
    __args__['clusterPlacementGroupId'] = cluster_placement_group_id
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['exascaleDbStorageVaultId'] = exascale_db_storage_vault_id
    __args__['filters'] = filters
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Database/getExadbVmClusters:getExadbVmClusters', __args__, opts=opts, typ=GetExadbVmClustersResult)
    return __ret__.apply(lambda __response__: GetExadbVmClustersResult(
        cluster_placement_group_id=pulumi.get(__response__, 'cluster_placement_group_id'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        exadb_vm_clusters=pulumi.get(__response__, 'exadb_vm_clusters'),
        exascale_db_storage_vault_id=pulumi.get(__response__, 'exascale_db_storage_vault_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        state=pulumi.get(__response__, 'state')))
