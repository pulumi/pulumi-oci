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
    'GetBdsInstanceSoftwareUpdatesResult',
    'AwaitableGetBdsInstanceSoftwareUpdatesResult',
    'get_bds_instance_software_updates',
    'get_bds_instance_software_updates_output',
]

@pulumi.output_type
class GetBdsInstanceSoftwareUpdatesResult:
    """
    A collection of values returned by getBdsInstanceSoftwareUpdates.
    """
    def __init__(__self__, bds_instance_id=None, filters=None, id=None, software_update_collections=None):
        if bds_instance_id and not isinstance(bds_instance_id, str):
            raise TypeError("Expected argument 'bds_instance_id' to be a str")
        pulumi.set(__self__, "bds_instance_id", bds_instance_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if software_update_collections and not isinstance(software_update_collections, list):
            raise TypeError("Expected argument 'software_update_collections' to be a list")
        pulumi.set(__self__, "software_update_collections", software_update_collections)

    @_builtins.property
    @pulumi.getter(name="bdsInstanceId")
    def bds_instance_id(self) -> _builtins.str:
        return pulumi.get(self, "bds_instance_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetBdsInstanceSoftwareUpdatesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="softwareUpdateCollections")
    def software_update_collections(self) -> Sequence['outputs.GetBdsInstanceSoftwareUpdatesSoftwareUpdateCollectionResult']:
        """
        The list of software_update_collection.
        """
        return pulumi.get(self, "software_update_collections")


class AwaitableGetBdsInstanceSoftwareUpdatesResult(GetBdsInstanceSoftwareUpdatesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetBdsInstanceSoftwareUpdatesResult(
            bds_instance_id=self.bds_instance_id,
            filters=self.filters,
            id=self.id,
            software_update_collections=self.software_update_collections)


def get_bds_instance_software_updates(bds_instance_id: Optional[_builtins.str] = None,
                                      filters: Optional[Sequence[Union['GetBdsInstanceSoftwareUpdatesFilterArgs', 'GetBdsInstanceSoftwareUpdatesFilterArgsDict']]] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetBdsInstanceSoftwareUpdatesResult:
    """
    This data source provides the list of Bds Instance Software Updates in Oracle Cloud Infrastructure Big Data Service service.

    List all the available software updates for current cluster.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_bds_instance_software_updates = oci.BigDataService.get_bds_instance_software_updates(bds_instance_id=test_bds_instance["id"])
    ```


    :param _builtins.str bds_instance_id: The OCID of the cluster.
    """
    __args__ = dict()
    __args__['bdsInstanceId'] = bds_instance_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:BigDataService/getBdsInstanceSoftwareUpdates:getBdsInstanceSoftwareUpdates', __args__, opts=opts, typ=GetBdsInstanceSoftwareUpdatesResult).value

    return AwaitableGetBdsInstanceSoftwareUpdatesResult(
        bds_instance_id=pulumi.get(__ret__, 'bds_instance_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        software_update_collections=pulumi.get(__ret__, 'software_update_collections'))
def get_bds_instance_software_updates_output(bds_instance_id: Optional[pulumi.Input[_builtins.str]] = None,
                                             filters: Optional[pulumi.Input[Optional[Sequence[Union['GetBdsInstanceSoftwareUpdatesFilterArgs', 'GetBdsInstanceSoftwareUpdatesFilterArgsDict']]]]] = None,
                                             opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetBdsInstanceSoftwareUpdatesResult]:
    """
    This data source provides the list of Bds Instance Software Updates in Oracle Cloud Infrastructure Big Data Service service.

    List all the available software updates for current cluster.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_bds_instance_software_updates = oci.BigDataService.get_bds_instance_software_updates(bds_instance_id=test_bds_instance["id"])
    ```


    :param _builtins.str bds_instance_id: The OCID of the cluster.
    """
    __args__ = dict()
    __args__['bdsInstanceId'] = bds_instance_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:BigDataService/getBdsInstanceSoftwareUpdates:getBdsInstanceSoftwareUpdates', __args__, opts=opts, typ=GetBdsInstanceSoftwareUpdatesResult)
    return __ret__.apply(lambda __response__: GetBdsInstanceSoftwareUpdatesResult(
        bds_instance_id=pulumi.get(__response__, 'bds_instance_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        software_update_collections=pulumi.get(__response__, 'software_update_collections')))
