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
    'GetAutonomousContainerPatchesResult',
    'AwaitableGetAutonomousContainerPatchesResult',
    'get_autonomous_container_patches',
    'get_autonomous_container_patches_output',
]

@pulumi.output_type
class GetAutonomousContainerPatchesResult:
    """
    A collection of values returned by getAutonomousContainerPatches.
    """
    def __init__(__self__, autonomous_container_database_id=None, autonomous_patch_type=None, autonomous_patches=None, compartment_id=None, filters=None, id=None):
        if autonomous_container_database_id and not isinstance(autonomous_container_database_id, str):
            raise TypeError("Expected argument 'autonomous_container_database_id' to be a str")
        pulumi.set(__self__, "autonomous_container_database_id", autonomous_container_database_id)
        if autonomous_patch_type and not isinstance(autonomous_patch_type, str):
            raise TypeError("Expected argument 'autonomous_patch_type' to be a str")
        pulumi.set(__self__, "autonomous_patch_type", autonomous_patch_type)
        if autonomous_patches and not isinstance(autonomous_patches, list):
            raise TypeError("Expected argument 'autonomous_patches' to be a list")
        pulumi.set(__self__, "autonomous_patches", autonomous_patches)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @_builtins.property
    @pulumi.getter(name="autonomousContainerDatabaseId")
    def autonomous_container_database_id(self) -> _builtins.str:
        return pulumi.get(self, "autonomous_container_database_id")

    @_builtins.property
    @pulumi.getter(name="autonomousPatchType")
    def autonomous_patch_type(self) -> Optional[_builtins.str]:
        """
        Maintenance run type, either "QUARTERLY" or "TIMEZONE".
        """
        return pulumi.get(self, "autonomous_patch_type")

    @_builtins.property
    @pulumi.getter(name="autonomousPatches")
    def autonomous_patches(self) -> Sequence['outputs.GetAutonomousContainerPatchesAutonomousPatchResult']:
        """
        The list of autonomous_patches.
        """
        return pulumi.get(self, "autonomous_patches")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetAutonomousContainerPatchesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetAutonomousContainerPatchesResult(GetAutonomousContainerPatchesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAutonomousContainerPatchesResult(
            autonomous_container_database_id=self.autonomous_container_database_id,
            autonomous_patch_type=self.autonomous_patch_type,
            autonomous_patches=self.autonomous_patches,
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id)


def get_autonomous_container_patches(autonomous_container_database_id: Optional[_builtins.str] = None,
                                     autonomous_patch_type: Optional[_builtins.str] = None,
                                     compartment_id: Optional[_builtins.str] = None,
                                     filters: Optional[Sequence[Union['GetAutonomousContainerPatchesFilterArgs', 'GetAutonomousContainerPatchesFilterArgsDict']]] = None,
                                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAutonomousContainerPatchesResult:
    """
    This data source provides the list of Autonomous Container Patches in Oracle Cloud Infrastructure Database service.

    Lists the patches applicable to the requested container database.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_autonomous_container_patches = oci.Database.get_autonomous_container_patches(autonomous_container_database_id=test_autonomous_container_database["id"],
        compartment_id=compartment_id,
        autonomous_patch_type=autonomous_container_patch_autonomous_patch_type)
    ```


    :param _builtins.str autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param _builtins.str autonomous_patch_type: Autonomous patch type, either "QUARTERLY" or "TIMEZONE".
    :param _builtins.str compartment_id: The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['autonomousContainerDatabaseId'] = autonomous_container_database_id
    __args__['autonomousPatchType'] = autonomous_patch_type
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Database/getAutonomousContainerPatches:getAutonomousContainerPatches', __args__, opts=opts, typ=GetAutonomousContainerPatchesResult).value

    return AwaitableGetAutonomousContainerPatchesResult(
        autonomous_container_database_id=pulumi.get(__ret__, 'autonomous_container_database_id'),
        autonomous_patch_type=pulumi.get(__ret__, 'autonomous_patch_type'),
        autonomous_patches=pulumi.get(__ret__, 'autonomous_patches'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'))
def get_autonomous_container_patches_output(autonomous_container_database_id: Optional[pulumi.Input[_builtins.str]] = None,
                                            autonomous_patch_type: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                            compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                            filters: Optional[pulumi.Input[Optional[Sequence[Union['GetAutonomousContainerPatchesFilterArgs', 'GetAutonomousContainerPatchesFilterArgsDict']]]]] = None,
                                            opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetAutonomousContainerPatchesResult]:
    """
    This data source provides the list of Autonomous Container Patches in Oracle Cloud Infrastructure Database service.

    Lists the patches applicable to the requested container database.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_autonomous_container_patches = oci.Database.get_autonomous_container_patches(autonomous_container_database_id=test_autonomous_container_database["id"],
        compartment_id=compartment_id,
        autonomous_patch_type=autonomous_container_patch_autonomous_patch_type)
    ```


    :param _builtins.str autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param _builtins.str autonomous_patch_type: Autonomous patch type, either "QUARTERLY" or "TIMEZONE".
    :param _builtins.str compartment_id: The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['autonomousContainerDatabaseId'] = autonomous_container_database_id
    __args__['autonomousPatchType'] = autonomous_patch_type
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Database/getAutonomousContainerPatches:getAutonomousContainerPatches', __args__, opts=opts, typ=GetAutonomousContainerPatchesResult)
    return __ret__.apply(lambda __response__: GetAutonomousContainerPatchesResult(
        autonomous_container_database_id=pulumi.get(__response__, 'autonomous_container_database_id'),
        autonomous_patch_type=pulumi.get(__response__, 'autonomous_patch_type'),
        autonomous_patches=pulumi.get(__response__, 'autonomous_patches'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id')))
