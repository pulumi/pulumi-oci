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
    'GetDbHomePatchHistoryEntriesResult',
    'AwaitableGetDbHomePatchHistoryEntriesResult',
    'get_db_home_patch_history_entries',
    'get_db_home_patch_history_entries_output',
]

@pulumi.output_type
class GetDbHomePatchHistoryEntriesResult:
    """
    A collection of values returned by getDbHomePatchHistoryEntries.
    """
    def __init__(__self__, db_home_id=None, filters=None, id=None, patch_history_entries=None):
        if db_home_id and not isinstance(db_home_id, str):
            raise TypeError("Expected argument 'db_home_id' to be a str")
        pulumi.set(__self__, "db_home_id", db_home_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if patch_history_entries and not isinstance(patch_history_entries, list):
            raise TypeError("Expected argument 'patch_history_entries' to be a list")
        pulumi.set(__self__, "patch_history_entries", patch_history_entries)

    @property
    @pulumi.getter(name="dbHomeId")
    def db_home_id(self) -> str:
        return pulumi.get(self, "db_home_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDbHomePatchHistoryEntriesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="patchHistoryEntries")
    def patch_history_entries(self) -> Sequence['outputs.GetDbHomePatchHistoryEntriesPatchHistoryEntryResult']:
        """
        The list of patch_history_entries.
        """
        return pulumi.get(self, "patch_history_entries")


class AwaitableGetDbHomePatchHistoryEntriesResult(GetDbHomePatchHistoryEntriesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDbHomePatchHistoryEntriesResult(
            db_home_id=self.db_home_id,
            filters=self.filters,
            id=self.id,
            patch_history_entries=self.patch_history_entries)


def get_db_home_patch_history_entries(db_home_id: Optional[str] = None,
                                      filters: Optional[Sequence[pulumi.InputType['GetDbHomePatchHistoryEntriesFilterArgs']]] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDbHomePatchHistoryEntriesResult:
    """
    This data source provides the list of Db Home Patch History Entries in Oracle Cloud Infrastructure Database service.

    Lists the history of patch operations on the specified Database Home.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_db_home_patch_history_entries = oci.Database.get_db_home_patch_history_entries(db_home_id=oci_database_db_home["test_db_home"]["id"])
    ```


    :param str db_home_id: The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['dbHomeId'] = db_home_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Database/getDbHomePatchHistoryEntries:getDbHomePatchHistoryEntries', __args__, opts=opts, typ=GetDbHomePatchHistoryEntriesResult).value

    return AwaitableGetDbHomePatchHistoryEntriesResult(
        db_home_id=__ret__.db_home_id,
        filters=__ret__.filters,
        id=__ret__.id,
        patch_history_entries=__ret__.patch_history_entries)


@_utilities.lift_output_func(get_db_home_patch_history_entries)
def get_db_home_patch_history_entries_output(db_home_id: Optional[pulumi.Input[str]] = None,
                                             filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetDbHomePatchHistoryEntriesFilterArgs']]]]] = None,
                                             opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetDbHomePatchHistoryEntriesResult]:
    """
    This data source provides the list of Db Home Patch History Entries in Oracle Cloud Infrastructure Database service.

    Lists the history of patch operations on the specified Database Home.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_db_home_patch_history_entries = oci.Database.get_db_home_patch_history_entries(db_home_id=oci_database_db_home["test_db_home"]["id"])
    ```


    :param str db_home_id: The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    ...