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
    'GetBdsInstanceGetOsPatchResult',
    'AwaitableGetBdsInstanceGetOsPatchResult',
    'get_bds_instance_get_os_patch',
    'get_bds_instance_get_os_patch_output',
]

@pulumi.output_type
class GetBdsInstanceGetOsPatchResult:
    """
    A collection of values returned by getBdsInstanceGetOsPatch.
    """
    def __init__(__self__, bds_instance_id=None, filters=None, id=None, min_bds_version=None, min_compatible_odh_version_map=None, os_patch_version=None, patch_type=None, release_date=None, target_packages=None):
        if bds_instance_id and not isinstance(bds_instance_id, str):
            raise TypeError("Expected argument 'bds_instance_id' to be a str")
        pulumi.set(__self__, "bds_instance_id", bds_instance_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if min_bds_version and not isinstance(min_bds_version, str):
            raise TypeError("Expected argument 'min_bds_version' to be a str")
        pulumi.set(__self__, "min_bds_version", min_bds_version)
        if min_compatible_odh_version_map and not isinstance(min_compatible_odh_version_map, dict):
            raise TypeError("Expected argument 'min_compatible_odh_version_map' to be a dict")
        pulumi.set(__self__, "min_compatible_odh_version_map", min_compatible_odh_version_map)
        if os_patch_version and not isinstance(os_patch_version, str):
            raise TypeError("Expected argument 'os_patch_version' to be a str")
        pulumi.set(__self__, "os_patch_version", os_patch_version)
        if patch_type and not isinstance(patch_type, str):
            raise TypeError("Expected argument 'patch_type' to be a str")
        pulumi.set(__self__, "patch_type", patch_type)
        if release_date and not isinstance(release_date, str):
            raise TypeError("Expected argument 'release_date' to be a str")
        pulumi.set(__self__, "release_date", release_date)
        if target_packages and not isinstance(target_packages, list):
            raise TypeError("Expected argument 'target_packages' to be a list")
        pulumi.set(__self__, "target_packages", target_packages)

    @_builtins.property
    @pulumi.getter(name="bdsInstanceId")
    def bds_instance_id(self) -> _builtins.str:
        return pulumi.get(self, "bds_instance_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetBdsInstanceGetOsPatchFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="minBdsVersion")
    def min_bds_version(self) -> _builtins.str:
        """
        Minimum BDS version required to install current OS patch.
        """
        return pulumi.get(self, "min_bds_version")

    @_builtins.property
    @pulumi.getter(name="minCompatibleOdhVersionMap")
    def min_compatible_odh_version_map(self) -> Mapping[str, _builtins.str]:
        """
        Map of major ODH version to minimum ODH version required to install current OS patch. e.g. {ODH0.9: 0.9.1}
        """
        return pulumi.get(self, "min_compatible_odh_version_map")

    @_builtins.property
    @pulumi.getter(name="osPatchVersion")
    def os_patch_version(self) -> _builtins.str:
        """
        Version of the os patch.
        """
        return pulumi.get(self, "os_patch_version")

    @_builtins.property
    @pulumi.getter(name="patchType")
    def patch_type(self) -> _builtins.str:
        """
        Type of a specific os patch. REGULAR means standard released os patches. CUSTOM means os patches with some customizations. EMERGENT means os patches with some emergency fixes that should be prioritized.
        """
        return pulumi.get(self, "patch_type")

    @_builtins.property
    @pulumi.getter(name="releaseDate")
    def release_date(self) -> _builtins.str:
        """
        Released date of the OS patch.
        """
        return pulumi.get(self, "release_date")

    @_builtins.property
    @pulumi.getter(name="targetPackages")
    def target_packages(self) -> Sequence['outputs.GetBdsInstanceGetOsPatchTargetPackageResult']:
        """
        List of summaries of individual target packages.
        """
        return pulumi.get(self, "target_packages")


class AwaitableGetBdsInstanceGetOsPatchResult(GetBdsInstanceGetOsPatchResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetBdsInstanceGetOsPatchResult(
            bds_instance_id=self.bds_instance_id,
            filters=self.filters,
            id=self.id,
            min_bds_version=self.min_bds_version,
            min_compatible_odh_version_map=self.min_compatible_odh_version_map,
            os_patch_version=self.os_patch_version,
            patch_type=self.patch_type,
            release_date=self.release_date,
            target_packages=self.target_packages)


def get_bds_instance_get_os_patch(bds_instance_id: Optional[_builtins.str] = None,
                                  filters: Optional[Sequence[Union['GetBdsInstanceGetOsPatchFilterArgs', 'GetBdsInstanceGetOsPatchFilterArgsDict']]] = None,
                                  os_patch_version: Optional[_builtins.str] = None,
                                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetBdsInstanceGetOsPatchResult:
    """
    This data source provides the list of Bds Instance Get Os Patch in Oracle Cloud Infrastructure Big Data Service service.

    Get the details of an os patch

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_bds_instance_get_os_patch = oci.BigDataService.get_bds_instance_get_os_patch(bds_instance_id=test_bds_instance["id"],
        os_patch_version=bds_instance_get_os_patch_os_patch_version)
    ```


    :param _builtins.str bds_instance_id: The OCID of the cluster.
    :param _builtins.str os_patch_version: The version of the OS patch.
    """
    __args__ = dict()
    __args__['bdsInstanceId'] = bds_instance_id
    __args__['filters'] = filters
    __args__['osPatchVersion'] = os_patch_version
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:BigDataService/getBdsInstanceGetOsPatch:getBdsInstanceGetOsPatch', __args__, opts=opts, typ=GetBdsInstanceGetOsPatchResult).value

    return AwaitableGetBdsInstanceGetOsPatchResult(
        bds_instance_id=pulumi.get(__ret__, 'bds_instance_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        min_bds_version=pulumi.get(__ret__, 'min_bds_version'),
        min_compatible_odh_version_map=pulumi.get(__ret__, 'min_compatible_odh_version_map'),
        os_patch_version=pulumi.get(__ret__, 'os_patch_version'),
        patch_type=pulumi.get(__ret__, 'patch_type'),
        release_date=pulumi.get(__ret__, 'release_date'),
        target_packages=pulumi.get(__ret__, 'target_packages'))
def get_bds_instance_get_os_patch_output(bds_instance_id: Optional[pulumi.Input[_builtins.str]] = None,
                                         filters: Optional[pulumi.Input[Optional[Sequence[Union['GetBdsInstanceGetOsPatchFilterArgs', 'GetBdsInstanceGetOsPatchFilterArgsDict']]]]] = None,
                                         os_patch_version: Optional[pulumi.Input[_builtins.str]] = None,
                                         opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetBdsInstanceGetOsPatchResult]:
    """
    This data source provides the list of Bds Instance Get Os Patch in Oracle Cloud Infrastructure Big Data Service service.

    Get the details of an os patch

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_bds_instance_get_os_patch = oci.BigDataService.get_bds_instance_get_os_patch(bds_instance_id=test_bds_instance["id"],
        os_patch_version=bds_instance_get_os_patch_os_patch_version)
    ```


    :param _builtins.str bds_instance_id: The OCID of the cluster.
    :param _builtins.str os_patch_version: The version of the OS patch.
    """
    __args__ = dict()
    __args__['bdsInstanceId'] = bds_instance_id
    __args__['filters'] = filters
    __args__['osPatchVersion'] = os_patch_version
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:BigDataService/getBdsInstanceGetOsPatch:getBdsInstanceGetOsPatch', __args__, opts=opts, typ=GetBdsInstanceGetOsPatchResult)
    return __ret__.apply(lambda __response__: GetBdsInstanceGetOsPatchResult(
        bds_instance_id=pulumi.get(__response__, 'bds_instance_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        min_bds_version=pulumi.get(__response__, 'min_bds_version'),
        min_compatible_odh_version_map=pulumi.get(__response__, 'min_compatible_odh_version_map'),
        os_patch_version=pulumi.get(__response__, 'os_patch_version'),
        patch_type=pulumi.get(__response__, 'patch_type'),
        release_date=pulumi.get(__response__, 'release_date'),
        target_packages=pulumi.get(__response__, 'target_packages')))
