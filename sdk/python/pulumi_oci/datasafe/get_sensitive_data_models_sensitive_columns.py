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
    'GetSensitiveDataModelsSensitiveColumnsResult',
    'AwaitableGetSensitiveDataModelsSensitiveColumnsResult',
    'get_sensitive_data_models_sensitive_columns',
    'get_sensitive_data_models_sensitive_columns_output',
]

@pulumi.output_type
class GetSensitiveDataModelsSensitiveColumnsResult:
    """
    A collection of values returned by getSensitiveDataModelsSensitiveColumns.
    """
    def __init__(__self__, column_group=None, column_names=None, data_types=None, filters=None, id=None, is_case_in_sensitive=None, object_types=None, objects=None, parent_column_keys=None, relation_types=None, schema_names=None, sensitive_column_collections=None, sensitive_column_lifecycle_state=None, sensitive_data_model_id=None, sensitive_type_ids=None, statuses=None, time_created_greater_than_or_equal_to=None, time_created_less_than=None, time_updated_greater_than_or_equal_to=None, time_updated_less_than=None):
        if column_group and not isinstance(column_group, str):
            raise TypeError("Expected argument 'column_group' to be a str")
        pulumi.set(__self__, "column_group", column_group)
        if column_names and not isinstance(column_names, list):
            raise TypeError("Expected argument 'column_names' to be a list")
        pulumi.set(__self__, "column_names", column_names)
        if data_types and not isinstance(data_types, list):
            raise TypeError("Expected argument 'data_types' to be a list")
        pulumi.set(__self__, "data_types", data_types)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_case_in_sensitive and not isinstance(is_case_in_sensitive, bool):
            raise TypeError("Expected argument 'is_case_in_sensitive' to be a bool")
        pulumi.set(__self__, "is_case_in_sensitive", is_case_in_sensitive)
        if object_types and not isinstance(object_types, list):
            raise TypeError("Expected argument 'object_types' to be a list")
        pulumi.set(__self__, "object_types", object_types)
        if objects and not isinstance(objects, list):
            raise TypeError("Expected argument 'objects' to be a list")
        pulumi.set(__self__, "objects", objects)
        if parent_column_keys and not isinstance(parent_column_keys, list):
            raise TypeError("Expected argument 'parent_column_keys' to be a list")
        pulumi.set(__self__, "parent_column_keys", parent_column_keys)
        if relation_types and not isinstance(relation_types, list):
            raise TypeError("Expected argument 'relation_types' to be a list")
        pulumi.set(__self__, "relation_types", relation_types)
        if schema_names and not isinstance(schema_names, list):
            raise TypeError("Expected argument 'schema_names' to be a list")
        pulumi.set(__self__, "schema_names", schema_names)
        if sensitive_column_collections and not isinstance(sensitive_column_collections, list):
            raise TypeError("Expected argument 'sensitive_column_collections' to be a list")
        pulumi.set(__self__, "sensitive_column_collections", sensitive_column_collections)
        if sensitive_column_lifecycle_state and not isinstance(sensitive_column_lifecycle_state, str):
            raise TypeError("Expected argument 'sensitive_column_lifecycle_state' to be a str")
        pulumi.set(__self__, "sensitive_column_lifecycle_state", sensitive_column_lifecycle_state)
        if sensitive_data_model_id and not isinstance(sensitive_data_model_id, str):
            raise TypeError("Expected argument 'sensitive_data_model_id' to be a str")
        pulumi.set(__self__, "sensitive_data_model_id", sensitive_data_model_id)
        if sensitive_type_ids and not isinstance(sensitive_type_ids, list):
            raise TypeError("Expected argument 'sensitive_type_ids' to be a list")
        pulumi.set(__self__, "sensitive_type_ids", sensitive_type_ids)
        if statuses and not isinstance(statuses, list):
            raise TypeError("Expected argument 'statuses' to be a list")
        pulumi.set(__self__, "statuses", statuses)
        if time_created_greater_than_or_equal_to and not isinstance(time_created_greater_than_or_equal_to, str):
            raise TypeError("Expected argument 'time_created_greater_than_or_equal_to' to be a str")
        pulumi.set(__self__, "time_created_greater_than_or_equal_to", time_created_greater_than_or_equal_to)
        if time_created_less_than and not isinstance(time_created_less_than, str):
            raise TypeError("Expected argument 'time_created_less_than' to be a str")
        pulumi.set(__self__, "time_created_less_than", time_created_less_than)
        if time_updated_greater_than_or_equal_to and not isinstance(time_updated_greater_than_or_equal_to, str):
            raise TypeError("Expected argument 'time_updated_greater_than_or_equal_to' to be a str")
        pulumi.set(__self__, "time_updated_greater_than_or_equal_to", time_updated_greater_than_or_equal_to)
        if time_updated_less_than and not isinstance(time_updated_less_than, str):
            raise TypeError("Expected argument 'time_updated_less_than' to be a str")
        pulumi.set(__self__, "time_updated_less_than", time_updated_less_than)

    @_builtins.property
    @pulumi.getter(name="columnGroup")
    def column_group(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "column_group")

    @_builtins.property
    @pulumi.getter(name="columnNames")
    def column_names(self) -> Optional[Sequence[_builtins.str]]:
        """
        The name of the sensitive column.
        """
        return pulumi.get(self, "column_names")

    @_builtins.property
    @pulumi.getter(name="dataTypes")
    def data_types(self) -> Optional[Sequence[_builtins.str]]:
        """
        The data type of the sensitive column.
        """
        return pulumi.get(self, "data_types")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSensitiveDataModelsSensitiveColumnsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isCaseInSensitive")
    def is_case_in_sensitive(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "is_case_in_sensitive")

    @_builtins.property
    @pulumi.getter(name="objectTypes")
    def object_types(self) -> Optional[Sequence[_builtins.str]]:
        """
        The type of the database object that contains the sensitive column.
        """
        return pulumi.get(self, "object_types")

    @_builtins.property
    @pulumi.getter
    def objects(self) -> Optional[Sequence[_builtins.str]]:
        """
        The database object that contains the sensitive column.
        """
        return pulumi.get(self, "objects")

    @_builtins.property
    @pulumi.getter(name="parentColumnKeys")
    def parent_column_keys(self) -> Optional[Sequence[_builtins.str]]:
        return pulumi.get(self, "parent_column_keys")

    @_builtins.property
    @pulumi.getter(name="relationTypes")
    def relation_types(self) -> Optional[Sequence[_builtins.str]]:
        """
        The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
        """
        return pulumi.get(self, "relation_types")

    @_builtins.property
    @pulumi.getter(name="schemaNames")
    def schema_names(self) -> Optional[Sequence[_builtins.str]]:
        """
        The database schema that contains the sensitive column.
        """
        return pulumi.get(self, "schema_names")

    @_builtins.property
    @pulumi.getter(name="sensitiveColumnCollections")
    def sensitive_column_collections(self) -> Sequence['outputs.GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollectionResult']:
        """
        The list of sensitive_column_collection.
        """
        return pulumi.get(self, "sensitive_column_collections")

    @_builtins.property
    @pulumi.getter(name="sensitiveColumnLifecycleState")
    def sensitive_column_lifecycle_state(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "sensitive_column_lifecycle_state")

    @_builtins.property
    @pulumi.getter(name="sensitiveDataModelId")
    def sensitive_data_model_id(self) -> _builtins.str:
        """
        The OCID of the sensitive data model that contains the sensitive column.
        """
        return pulumi.get(self, "sensitive_data_model_id")

    @_builtins.property
    @pulumi.getter(name="sensitiveTypeIds")
    def sensitive_type_ids(self) -> Optional[Sequence[_builtins.str]]:
        """
        The OCID of the sensitive type associated with the sensitive column.
        """
        return pulumi.get(self, "sensitive_type_ids")

    @_builtins.property
    @pulumi.getter
    def statuses(self) -> Optional[Sequence[_builtins.str]]:
        """
        The status of the sensitive column. VALID means the column is considered sensitive. INVALID means the column is not considered sensitive. Tracking invalid columns in a sensitive data model helps ensure that an incremental data discovery job does not identify these columns as sensitive again.
        """
        return pulumi.get(self, "statuses")

    @_builtins.property
    @pulumi.getter(name="timeCreatedGreaterThanOrEqualTo")
    def time_created_greater_than_or_equal_to(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "time_created_greater_than_or_equal_to")

    @_builtins.property
    @pulumi.getter(name="timeCreatedLessThan")
    def time_created_less_than(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "time_created_less_than")

    @_builtins.property
    @pulumi.getter(name="timeUpdatedGreaterThanOrEqualTo")
    def time_updated_greater_than_or_equal_to(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "time_updated_greater_than_or_equal_to")

    @_builtins.property
    @pulumi.getter(name="timeUpdatedLessThan")
    def time_updated_less_than(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "time_updated_less_than")


class AwaitableGetSensitiveDataModelsSensitiveColumnsResult(GetSensitiveDataModelsSensitiveColumnsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSensitiveDataModelsSensitiveColumnsResult(
            column_group=self.column_group,
            column_names=self.column_names,
            data_types=self.data_types,
            filters=self.filters,
            id=self.id,
            is_case_in_sensitive=self.is_case_in_sensitive,
            object_types=self.object_types,
            objects=self.objects,
            parent_column_keys=self.parent_column_keys,
            relation_types=self.relation_types,
            schema_names=self.schema_names,
            sensitive_column_collections=self.sensitive_column_collections,
            sensitive_column_lifecycle_state=self.sensitive_column_lifecycle_state,
            sensitive_data_model_id=self.sensitive_data_model_id,
            sensitive_type_ids=self.sensitive_type_ids,
            statuses=self.statuses,
            time_created_greater_than_or_equal_to=self.time_created_greater_than_or_equal_to,
            time_created_less_than=self.time_created_less_than,
            time_updated_greater_than_or_equal_to=self.time_updated_greater_than_or_equal_to,
            time_updated_less_than=self.time_updated_less_than)


def get_sensitive_data_models_sensitive_columns(column_group: Optional[_builtins.str] = None,
                                                column_names: Optional[Sequence[_builtins.str]] = None,
                                                data_types: Optional[Sequence[_builtins.str]] = None,
                                                filters: Optional[Sequence[Union['GetSensitiveDataModelsSensitiveColumnsFilterArgs', 'GetSensitiveDataModelsSensitiveColumnsFilterArgsDict']]] = None,
                                                is_case_in_sensitive: Optional[_builtins.bool] = None,
                                                object_types: Optional[Sequence[_builtins.str]] = None,
                                                objects: Optional[Sequence[_builtins.str]] = None,
                                                parent_column_keys: Optional[Sequence[_builtins.str]] = None,
                                                relation_types: Optional[Sequence[_builtins.str]] = None,
                                                schema_names: Optional[Sequence[_builtins.str]] = None,
                                                sensitive_column_lifecycle_state: Optional[_builtins.str] = None,
                                                sensitive_data_model_id: Optional[_builtins.str] = None,
                                                sensitive_type_ids: Optional[Sequence[_builtins.str]] = None,
                                                statuses: Optional[Sequence[_builtins.str]] = None,
                                                time_created_greater_than_or_equal_to: Optional[_builtins.str] = None,
                                                time_created_less_than: Optional[_builtins.str] = None,
                                                time_updated_greater_than_or_equal_to: Optional[_builtins.str] = None,
                                                time_updated_less_than: Optional[_builtins.str] = None,
                                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSensitiveDataModelsSensitiveColumnsResult:
    """
    This data source provides the list of Sensitive Data Models Sensitive Columns in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of sensitive columns present in the specified sensitive data model based on the specified query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_sensitive_data_models_sensitive_columns = oci.DataSafe.get_sensitive_data_models_sensitive_columns(sensitive_data_model_id=test_sensitive_data_model["id"],
        column_group=sensitive_data_models_sensitive_column_column_group,
        column_names=sensitive_data_models_sensitive_column_column_name,
        data_types=sensitive_data_models_sensitive_column_data_type,
        is_case_in_sensitive=sensitive_data_models_sensitive_column_is_case_in_sensitive,
        objects=sensitive_data_models_sensitive_column_object,
        object_types=sensitive_data_models_sensitive_column_object_type,
        parent_column_keys=sensitive_data_models_sensitive_column_parent_column_key,
        relation_types=sensitive_data_models_sensitive_column_relation_type,
        schema_names=sensitive_data_models_sensitive_column_schema_name,
        sensitive_column_lifecycle_state=sensitive_data_models_sensitive_column_sensitive_column_lifecycle_state,
        sensitive_type_ids=test_sensitive_type["id"],
        statuses=sensitive_data_models_sensitive_column_status,
        time_created_greater_than_or_equal_to=sensitive_data_models_sensitive_column_time_created_greater_than_or_equal_to,
        time_created_less_than=sensitive_data_models_sensitive_column_time_created_less_than,
        time_updated_greater_than_or_equal_to=sensitive_data_models_sensitive_column_time_updated_greater_than_or_equal_to,
        time_updated_less_than=sensitive_data_models_sensitive_column_time_updated_less_than)
    ```


    :param _builtins.str column_group: A filter to return only the sensitive columns that belong to the specified column group.
    :param Sequence[_builtins.str] column_names: A filter to return only a specific column based on column name.
    :param Sequence[_builtins.str] data_types: A filter to return only the resources that match the specified data types.
    :param _builtins.bool is_case_in_sensitive: A boolean flag indicating whether the search should be case-insensitive. The search is case-sensitive by default. Set this parameter to true to do case-insensitive search.
    :param Sequence[_builtins.str] object_types: A filter to return only items related to a specific object type.
    :param Sequence[_builtins.str] objects: A filter to return only items related to a specific object name.
    :param Sequence[_builtins.str] parent_column_keys: A filter to return only the sensitive columns that are children of one of the columns identified by the specified keys.
    :param Sequence[_builtins.str] relation_types: A filter to return sensitive columns based on their relationship with their parent columns. If set to NONE, it returns the sensitive columns that do not have any parent. The response includes the parent columns as well as the independent columns that are not in any relationship. If set to APP_DEFINED, it returns all the child columns that have application-level (non-dictionary) relationship with their parents. If set to DB_DEFINED, it returns all the child columns that have database-level (dictionary-defined) relationship with their parents.
    :param Sequence[_builtins.str] schema_names: A filter to return only items related to specific schema name.
    :param _builtins.str sensitive_column_lifecycle_state: Filters the sensitive column resources with the given lifecycle state values.
    :param _builtins.str sensitive_data_model_id: The OCID of the sensitive data model.
    :param Sequence[_builtins.str] sensitive_type_ids: A filter to return only the sensitive columns that are associated with one of the sensitive types identified by the specified OCIDs.
    :param Sequence[_builtins.str] statuses: A filter to return only the sensitive columns that match the specified status.
    :param _builtins.str time_created_greater_than_or_equal_to: A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
           
           **Example:** 2016-12-19T16:39:57.600Z
    :param _builtins.str time_created_less_than: Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
           
           **Example:** 2016-12-19T16:39:57.600Z
    :param _builtins.str time_updated_greater_than_or_equal_to: Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
    :param _builtins.str time_updated_less_than: Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
    """
    __args__ = dict()
    __args__['columnGroup'] = column_group
    __args__['columnNames'] = column_names
    __args__['dataTypes'] = data_types
    __args__['filters'] = filters
    __args__['isCaseInSensitive'] = is_case_in_sensitive
    __args__['objectTypes'] = object_types
    __args__['objects'] = objects
    __args__['parentColumnKeys'] = parent_column_keys
    __args__['relationTypes'] = relation_types
    __args__['schemaNames'] = schema_names
    __args__['sensitiveColumnLifecycleState'] = sensitive_column_lifecycle_state
    __args__['sensitiveDataModelId'] = sensitive_data_model_id
    __args__['sensitiveTypeIds'] = sensitive_type_ids
    __args__['statuses'] = statuses
    __args__['timeCreatedGreaterThanOrEqualTo'] = time_created_greater_than_or_equal_to
    __args__['timeCreatedLessThan'] = time_created_less_than
    __args__['timeUpdatedGreaterThanOrEqualTo'] = time_updated_greater_than_or_equal_to
    __args__['timeUpdatedLessThan'] = time_updated_less_than
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getSensitiveDataModelsSensitiveColumns:getSensitiveDataModelsSensitiveColumns', __args__, opts=opts, typ=GetSensitiveDataModelsSensitiveColumnsResult).value

    return AwaitableGetSensitiveDataModelsSensitiveColumnsResult(
        column_group=pulumi.get(__ret__, 'column_group'),
        column_names=pulumi.get(__ret__, 'column_names'),
        data_types=pulumi.get(__ret__, 'data_types'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        is_case_in_sensitive=pulumi.get(__ret__, 'is_case_in_sensitive'),
        object_types=pulumi.get(__ret__, 'object_types'),
        objects=pulumi.get(__ret__, 'objects'),
        parent_column_keys=pulumi.get(__ret__, 'parent_column_keys'),
        relation_types=pulumi.get(__ret__, 'relation_types'),
        schema_names=pulumi.get(__ret__, 'schema_names'),
        sensitive_column_collections=pulumi.get(__ret__, 'sensitive_column_collections'),
        sensitive_column_lifecycle_state=pulumi.get(__ret__, 'sensitive_column_lifecycle_state'),
        sensitive_data_model_id=pulumi.get(__ret__, 'sensitive_data_model_id'),
        sensitive_type_ids=pulumi.get(__ret__, 'sensitive_type_ids'),
        statuses=pulumi.get(__ret__, 'statuses'),
        time_created_greater_than_or_equal_to=pulumi.get(__ret__, 'time_created_greater_than_or_equal_to'),
        time_created_less_than=pulumi.get(__ret__, 'time_created_less_than'),
        time_updated_greater_than_or_equal_to=pulumi.get(__ret__, 'time_updated_greater_than_or_equal_to'),
        time_updated_less_than=pulumi.get(__ret__, 'time_updated_less_than'))
def get_sensitive_data_models_sensitive_columns_output(column_group: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                       column_names: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                       data_types: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                       filters: Optional[pulumi.Input[Optional[Sequence[Union['GetSensitiveDataModelsSensitiveColumnsFilterArgs', 'GetSensitiveDataModelsSensitiveColumnsFilterArgsDict']]]]] = None,
                                                       is_case_in_sensitive: Optional[pulumi.Input[Optional[_builtins.bool]]] = None,
                                                       object_types: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                       objects: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                       parent_column_keys: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                       relation_types: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                       schema_names: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                       sensitive_column_lifecycle_state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                       sensitive_data_model_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                       sensitive_type_ids: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                       statuses: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                       time_created_greater_than_or_equal_to: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                       time_created_less_than: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                       time_updated_greater_than_or_equal_to: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                       time_updated_less_than: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                       opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetSensitiveDataModelsSensitiveColumnsResult]:
    """
    This data source provides the list of Sensitive Data Models Sensitive Columns in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of sensitive columns present in the specified sensitive data model based on the specified query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_sensitive_data_models_sensitive_columns = oci.DataSafe.get_sensitive_data_models_sensitive_columns(sensitive_data_model_id=test_sensitive_data_model["id"],
        column_group=sensitive_data_models_sensitive_column_column_group,
        column_names=sensitive_data_models_sensitive_column_column_name,
        data_types=sensitive_data_models_sensitive_column_data_type,
        is_case_in_sensitive=sensitive_data_models_sensitive_column_is_case_in_sensitive,
        objects=sensitive_data_models_sensitive_column_object,
        object_types=sensitive_data_models_sensitive_column_object_type,
        parent_column_keys=sensitive_data_models_sensitive_column_parent_column_key,
        relation_types=sensitive_data_models_sensitive_column_relation_type,
        schema_names=sensitive_data_models_sensitive_column_schema_name,
        sensitive_column_lifecycle_state=sensitive_data_models_sensitive_column_sensitive_column_lifecycle_state,
        sensitive_type_ids=test_sensitive_type["id"],
        statuses=sensitive_data_models_sensitive_column_status,
        time_created_greater_than_or_equal_to=sensitive_data_models_sensitive_column_time_created_greater_than_or_equal_to,
        time_created_less_than=sensitive_data_models_sensitive_column_time_created_less_than,
        time_updated_greater_than_or_equal_to=sensitive_data_models_sensitive_column_time_updated_greater_than_or_equal_to,
        time_updated_less_than=sensitive_data_models_sensitive_column_time_updated_less_than)
    ```


    :param _builtins.str column_group: A filter to return only the sensitive columns that belong to the specified column group.
    :param Sequence[_builtins.str] column_names: A filter to return only a specific column based on column name.
    :param Sequence[_builtins.str] data_types: A filter to return only the resources that match the specified data types.
    :param _builtins.bool is_case_in_sensitive: A boolean flag indicating whether the search should be case-insensitive. The search is case-sensitive by default. Set this parameter to true to do case-insensitive search.
    :param Sequence[_builtins.str] object_types: A filter to return only items related to a specific object type.
    :param Sequence[_builtins.str] objects: A filter to return only items related to a specific object name.
    :param Sequence[_builtins.str] parent_column_keys: A filter to return only the sensitive columns that are children of one of the columns identified by the specified keys.
    :param Sequence[_builtins.str] relation_types: A filter to return sensitive columns based on their relationship with their parent columns. If set to NONE, it returns the sensitive columns that do not have any parent. The response includes the parent columns as well as the independent columns that are not in any relationship. If set to APP_DEFINED, it returns all the child columns that have application-level (non-dictionary) relationship with their parents. If set to DB_DEFINED, it returns all the child columns that have database-level (dictionary-defined) relationship with their parents.
    :param Sequence[_builtins.str] schema_names: A filter to return only items related to specific schema name.
    :param _builtins.str sensitive_column_lifecycle_state: Filters the sensitive column resources with the given lifecycle state values.
    :param _builtins.str sensitive_data_model_id: The OCID of the sensitive data model.
    :param Sequence[_builtins.str] sensitive_type_ids: A filter to return only the sensitive columns that are associated with one of the sensitive types identified by the specified OCIDs.
    :param Sequence[_builtins.str] statuses: A filter to return only the sensitive columns that match the specified status.
    :param _builtins.str time_created_greater_than_or_equal_to: A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
           
           **Example:** 2016-12-19T16:39:57.600Z
    :param _builtins.str time_created_less_than: Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
           
           **Example:** 2016-12-19T16:39:57.600Z
    :param _builtins.str time_updated_greater_than_or_equal_to: Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
    :param _builtins.str time_updated_less_than: Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
    """
    __args__ = dict()
    __args__['columnGroup'] = column_group
    __args__['columnNames'] = column_names
    __args__['dataTypes'] = data_types
    __args__['filters'] = filters
    __args__['isCaseInSensitive'] = is_case_in_sensitive
    __args__['objectTypes'] = object_types
    __args__['objects'] = objects
    __args__['parentColumnKeys'] = parent_column_keys
    __args__['relationTypes'] = relation_types
    __args__['schemaNames'] = schema_names
    __args__['sensitiveColumnLifecycleState'] = sensitive_column_lifecycle_state
    __args__['sensitiveDataModelId'] = sensitive_data_model_id
    __args__['sensitiveTypeIds'] = sensitive_type_ids
    __args__['statuses'] = statuses
    __args__['timeCreatedGreaterThanOrEqualTo'] = time_created_greater_than_or_equal_to
    __args__['timeCreatedLessThan'] = time_created_less_than
    __args__['timeUpdatedGreaterThanOrEqualTo'] = time_updated_greater_than_or_equal_to
    __args__['timeUpdatedLessThan'] = time_updated_less_than
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataSafe/getSensitiveDataModelsSensitiveColumns:getSensitiveDataModelsSensitiveColumns', __args__, opts=opts, typ=GetSensitiveDataModelsSensitiveColumnsResult)
    return __ret__.apply(lambda __response__: GetSensitiveDataModelsSensitiveColumnsResult(
        column_group=pulumi.get(__response__, 'column_group'),
        column_names=pulumi.get(__response__, 'column_names'),
        data_types=pulumi.get(__response__, 'data_types'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        is_case_in_sensitive=pulumi.get(__response__, 'is_case_in_sensitive'),
        object_types=pulumi.get(__response__, 'object_types'),
        objects=pulumi.get(__response__, 'objects'),
        parent_column_keys=pulumi.get(__response__, 'parent_column_keys'),
        relation_types=pulumi.get(__response__, 'relation_types'),
        schema_names=pulumi.get(__response__, 'schema_names'),
        sensitive_column_collections=pulumi.get(__response__, 'sensitive_column_collections'),
        sensitive_column_lifecycle_state=pulumi.get(__response__, 'sensitive_column_lifecycle_state'),
        sensitive_data_model_id=pulumi.get(__response__, 'sensitive_data_model_id'),
        sensitive_type_ids=pulumi.get(__response__, 'sensitive_type_ids'),
        statuses=pulumi.get(__response__, 'statuses'),
        time_created_greater_than_or_equal_to=pulumi.get(__response__, 'time_created_greater_than_or_equal_to'),
        time_created_less_than=pulumi.get(__response__, 'time_created_less_than'),
        time_updated_greater_than_or_equal_to=pulumi.get(__response__, 'time_updated_greater_than_or_equal_to'),
        time_updated_less_than=pulumi.get(__response__, 'time_updated_less_than')))
