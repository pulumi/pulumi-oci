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
    'GetManagedMySqlDatabaseSqlDataResult',
    'AwaitableGetManagedMySqlDatabaseSqlDataResult',
    'get_managed_my_sql_database_sql_data',
    'get_managed_my_sql_database_sql_data_output',
]

@pulumi.output_type
class GetManagedMySqlDatabaseSqlDataResult:
    """
    A collection of values returned by getManagedMySqlDatabaseSqlData.
    """
    def __init__(__self__, end_time=None, filter_column=None, filters=None, id=None, managed_my_sql_database_id=None, my_sql_data_collections=None, start_time=None):
        if end_time and not isinstance(end_time, str):
            raise TypeError("Expected argument 'end_time' to be a str")
        pulumi.set(__self__, "end_time", end_time)
        if filter_column and not isinstance(filter_column, str):
            raise TypeError("Expected argument 'filter_column' to be a str")
        pulumi.set(__self__, "filter_column", filter_column)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if managed_my_sql_database_id and not isinstance(managed_my_sql_database_id, str):
            raise TypeError("Expected argument 'managed_my_sql_database_id' to be a str")
        pulumi.set(__self__, "managed_my_sql_database_id", managed_my_sql_database_id)
        if my_sql_data_collections and not isinstance(my_sql_data_collections, list):
            raise TypeError("Expected argument 'my_sql_data_collections' to be a list")
        pulumi.set(__self__, "my_sql_data_collections", my_sql_data_collections)
        if start_time and not isinstance(start_time, str):
            raise TypeError("Expected argument 'start_time' to be a str")
        pulumi.set(__self__, "start_time", start_time)

    @_builtins.property
    @pulumi.getter(name="endTime")
    def end_time(self) -> _builtins.str:
        return pulumi.get(self, "end_time")

    @_builtins.property
    @pulumi.getter(name="filterColumn")
    def filter_column(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "filter_column")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetManagedMySqlDatabaseSqlDataFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="managedMySqlDatabaseId")
    def managed_my_sql_database_id(self) -> _builtins.str:
        return pulumi.get(self, "managed_my_sql_database_id")

    @_builtins.property
    @pulumi.getter(name="mySqlDataCollections")
    def my_sql_data_collections(self) -> Sequence['outputs.GetManagedMySqlDatabaseSqlDataMySqlDataCollectionResult']:
        """
        The list of my_sql_data_collection.
        """
        return pulumi.get(self, "my_sql_data_collections")

    @_builtins.property
    @pulumi.getter(name="startTime")
    def start_time(self) -> _builtins.str:
        return pulumi.get(self, "start_time")


class AwaitableGetManagedMySqlDatabaseSqlDataResult(GetManagedMySqlDatabaseSqlDataResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagedMySqlDatabaseSqlDataResult(
            end_time=self.end_time,
            filter_column=self.filter_column,
            filters=self.filters,
            id=self.id,
            managed_my_sql_database_id=self.managed_my_sql_database_id,
            my_sql_data_collections=self.my_sql_data_collections,
            start_time=self.start_time)


def get_managed_my_sql_database_sql_data(end_time: Optional[_builtins.str] = None,
                                         filter_column: Optional[_builtins.str] = None,
                                         filters: Optional[Sequence[Union['GetManagedMySqlDatabaseSqlDataFilterArgs', 'GetManagedMySqlDatabaseSqlDataFilterArgsDict']]] = None,
                                         managed_my_sql_database_id: Optional[_builtins.str] = None,
                                         start_time: Optional[_builtins.str] = None,
                                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagedMySqlDatabaseSqlDataResult:
    """
    This data source provides the list of Managed My Sql Database Sql Data in Oracle Cloud Infrastructure Database Management service.

    Retrieves SQL performance data for given MySQL Instance.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_my_sql_database_sql_data = oci.DatabaseManagement.get_managed_my_sql_database_sql_data(end_time=managed_my_sql_database_sql_data_end_time,
        managed_my_sql_database_id=test_managed_my_sql_database["id"],
        start_time=managed_my_sql_database_sql_data_start_time,
        filter_column=managed_my_sql_database_sql_data_filter_column)
    ```


    :param _builtins.str end_time: The end time of the time range to retrieve the health metrics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
    :param _builtins.str filter_column: The parameter to filter results by key criteria which include :
           * AVG_TIMER_WAIT
           * SUM_TIMER_WAIT
           * COUNT_STAR
           * SUM_ERRORS
           * SUM_ROWS_AFFECTED
           * SUM_ROWS_SENT
           * SUM_ROWS_EXAMINED
           * SUM_CREATED_TMP_TABLES
           * SUM_NO_INDEX_USED
           * SUM_NO_GOOD_INDEX_USED
           * FIRST_SEEN
           * LAST_SEEN
           * HEATWAVE_OFFLOADED
           * HEATWAVE_OUT_OF_MEMORY
    :param _builtins.str managed_my_sql_database_id: The OCID of the Managed MySQL Database.
    :param _builtins.str start_time: The start time of the time range to retrieve the health metrics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
    """
    __args__ = dict()
    __args__['endTime'] = end_time
    __args__['filterColumn'] = filter_column
    __args__['filters'] = filters
    __args__['managedMySqlDatabaseId'] = managed_my_sql_database_id
    __args__['startTime'] = start_time
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DatabaseManagement/getManagedMySqlDatabaseSqlData:getManagedMySqlDatabaseSqlData', __args__, opts=opts, typ=GetManagedMySqlDatabaseSqlDataResult).value

    return AwaitableGetManagedMySqlDatabaseSqlDataResult(
        end_time=pulumi.get(__ret__, 'end_time'),
        filter_column=pulumi.get(__ret__, 'filter_column'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        managed_my_sql_database_id=pulumi.get(__ret__, 'managed_my_sql_database_id'),
        my_sql_data_collections=pulumi.get(__ret__, 'my_sql_data_collections'),
        start_time=pulumi.get(__ret__, 'start_time'))
def get_managed_my_sql_database_sql_data_output(end_time: Optional[pulumi.Input[_builtins.str]] = None,
                                                filter_column: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                filters: Optional[pulumi.Input[Optional[Sequence[Union['GetManagedMySqlDatabaseSqlDataFilterArgs', 'GetManagedMySqlDatabaseSqlDataFilterArgsDict']]]]] = None,
                                                managed_my_sql_database_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                start_time: Optional[pulumi.Input[_builtins.str]] = None,
                                                opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetManagedMySqlDatabaseSqlDataResult]:
    """
    This data source provides the list of Managed My Sql Database Sql Data in Oracle Cloud Infrastructure Database Management service.

    Retrieves SQL performance data for given MySQL Instance.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_my_sql_database_sql_data = oci.DatabaseManagement.get_managed_my_sql_database_sql_data(end_time=managed_my_sql_database_sql_data_end_time,
        managed_my_sql_database_id=test_managed_my_sql_database["id"],
        start_time=managed_my_sql_database_sql_data_start_time,
        filter_column=managed_my_sql_database_sql_data_filter_column)
    ```


    :param _builtins.str end_time: The end time of the time range to retrieve the health metrics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
    :param _builtins.str filter_column: The parameter to filter results by key criteria which include :
           * AVG_TIMER_WAIT
           * SUM_TIMER_WAIT
           * COUNT_STAR
           * SUM_ERRORS
           * SUM_ROWS_AFFECTED
           * SUM_ROWS_SENT
           * SUM_ROWS_EXAMINED
           * SUM_CREATED_TMP_TABLES
           * SUM_NO_INDEX_USED
           * SUM_NO_GOOD_INDEX_USED
           * FIRST_SEEN
           * LAST_SEEN
           * HEATWAVE_OFFLOADED
           * HEATWAVE_OUT_OF_MEMORY
    :param _builtins.str managed_my_sql_database_id: The OCID of the Managed MySQL Database.
    :param _builtins.str start_time: The start time of the time range to retrieve the health metrics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
    """
    __args__ = dict()
    __args__['endTime'] = end_time
    __args__['filterColumn'] = filter_column
    __args__['filters'] = filters
    __args__['managedMySqlDatabaseId'] = managed_my_sql_database_id
    __args__['startTime'] = start_time
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DatabaseManagement/getManagedMySqlDatabaseSqlData:getManagedMySqlDatabaseSqlData', __args__, opts=opts, typ=GetManagedMySqlDatabaseSqlDataResult)
    return __ret__.apply(lambda __response__: GetManagedMySqlDatabaseSqlDataResult(
        end_time=pulumi.get(__response__, 'end_time'),
        filter_column=pulumi.get(__response__, 'filter_column'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        managed_my_sql_database_id=pulumi.get(__response__, 'managed_my_sql_database_id'),
        my_sql_data_collections=pulumi.get(__response__, 'my_sql_data_collections'),
        start_time=pulumi.get(__response__, 'start_time')))
