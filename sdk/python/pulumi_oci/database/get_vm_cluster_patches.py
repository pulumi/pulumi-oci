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
    'GetVmClusterPatchesResult',
    'AwaitableGetVmClusterPatchesResult',
    'get_vm_cluster_patches',
    'get_vm_cluster_patches_output',
]

@pulumi.output_type
class GetVmClusterPatchesResult:
    """
    A collection of values returned by getVmClusterPatches.
    """
    def __init__(__self__, filters=None, id=None, patches=None, vm_cluster_id=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if patches and not isinstance(patches, list):
            raise TypeError("Expected argument 'patches' to be a list")
        pulumi.set(__self__, "patches", patches)
        if vm_cluster_id and not isinstance(vm_cluster_id, str):
            raise TypeError("Expected argument 'vm_cluster_id' to be a str")
        pulumi.set(__self__, "vm_cluster_id", vm_cluster_id)

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetVmClusterPatchesFilterResult']]:
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
    def patches(self) -> Sequence['outputs.GetVmClusterPatchesPatchResult']:
        """
        The list of patches.
        """
        return pulumi.get(self, "patches")

    @property
    @pulumi.getter(name="vmClusterId")
    def vm_cluster_id(self) -> str:
        return pulumi.get(self, "vm_cluster_id")


class AwaitableGetVmClusterPatchesResult(GetVmClusterPatchesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetVmClusterPatchesResult(
            filters=self.filters,
            id=self.id,
            patches=self.patches,
            vm_cluster_id=self.vm_cluster_id)


def get_vm_cluster_patches(filters: Optional[Sequence[pulumi.InputType['GetVmClusterPatchesFilterArgs']]] = None,
                           vm_cluster_id: Optional[str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetVmClusterPatchesResult:
    """
    This data source provides the list of Vm Cluster Patches in Oracle Cloud Infrastructure Database service.

    Lists the patches applicable to the specified VM cluster in an Exadata Cloud@Customer system.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_vm_cluster_patches = oci.Database.get_vm_cluster_patches(vm_cluster_id=oci_database_vm_cluster["test_vm_cluster"]["id"])
    ```


    :param str vm_cluster_id: The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['vmClusterId'] = vm_cluster_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Database/getVmClusterPatches:getVmClusterPatches', __args__, opts=opts, typ=GetVmClusterPatchesResult).value

    return AwaitableGetVmClusterPatchesResult(
        filters=__ret__.filters,
        id=__ret__.id,
        patches=__ret__.patches,
        vm_cluster_id=__ret__.vm_cluster_id)


@_utilities.lift_output_func(get_vm_cluster_patches)
def get_vm_cluster_patches_output(filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetVmClusterPatchesFilterArgs']]]]] = None,
                                  vm_cluster_id: Optional[pulumi.Input[str]] = None,
                                  opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetVmClusterPatchesResult]:
    """
    This data source provides the list of Vm Cluster Patches in Oracle Cloud Infrastructure Database service.

    Lists the patches applicable to the specified VM cluster in an Exadata Cloud@Customer system.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_vm_cluster_patches = oci.Database.get_vm_cluster_patches(vm_cluster_id=oci_database_vm_cluster["test_vm_cluster"]["id"])
    ```


    :param str vm_cluster_id: The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    ...