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
    'GetSdmMaskingPolicyDifferenceDifferenceColumnsResult',
    'AwaitableGetSdmMaskingPolicyDifferenceDifferenceColumnsResult',
    'get_sdm_masking_policy_difference_difference_columns',
    'get_sdm_masking_policy_difference_difference_columns_output',
]

@pulumi.output_type
class GetSdmMaskingPolicyDifferenceDifferenceColumnsResult:
    """
    A collection of values returned by getSdmMaskingPolicyDifferenceDifferenceColumns.
    """
    def __init__(__self__, column_names=None, difference_type=None, filters=None, id=None, objects=None, planned_action=None, schema_names=None, sdm_masking_policy_difference_column_collections=None, sdm_masking_policy_difference_id=None, sync_status=None):
        if column_names and not isinstance(column_names, list):
            raise TypeError("Expected argument 'column_names' to be a list")
        pulumi.set(__self__, "column_names", column_names)
        if difference_type and not isinstance(difference_type, str):
            raise TypeError("Expected argument 'difference_type' to be a str")
        pulumi.set(__self__, "difference_type", difference_type)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if objects and not isinstance(objects, list):
            raise TypeError("Expected argument 'objects' to be a list")
        pulumi.set(__self__, "objects", objects)
        if planned_action and not isinstance(planned_action, str):
            raise TypeError("Expected argument 'planned_action' to be a str")
        pulumi.set(__self__, "planned_action", planned_action)
        if schema_names and not isinstance(schema_names, list):
            raise TypeError("Expected argument 'schema_names' to be a list")
        pulumi.set(__self__, "schema_names", schema_names)
        if sdm_masking_policy_difference_column_collections and not isinstance(sdm_masking_policy_difference_column_collections, list):
            raise TypeError("Expected argument 'sdm_masking_policy_difference_column_collections' to be a list")
        pulumi.set(__self__, "sdm_masking_policy_difference_column_collections", sdm_masking_policy_difference_column_collections)
        if sdm_masking_policy_difference_id and not isinstance(sdm_masking_policy_difference_id, str):
            raise TypeError("Expected argument 'sdm_masking_policy_difference_id' to be a str")
        pulumi.set(__self__, "sdm_masking_policy_difference_id", sdm_masking_policy_difference_id)
        if sync_status and not isinstance(sync_status, str):
            raise TypeError("Expected argument 'sync_status' to be a str")
        pulumi.set(__self__, "sync_status", sync_status)

    @property
    @pulumi.getter(name="columnNames")
    def column_names(self) -> Optional[Sequence[str]]:
        """
        The name of the difference column.
        """
        return pulumi.get(self, "column_names")

    @property
    @pulumi.getter(name="differenceType")
    def difference_type(self) -> Optional[str]:
        """
        The type of the SDM masking policy difference column. It can be one of the following three types: NEW: A new sensitive column in the sensitive data model that is not in the masking policy. DELETED: A column that is present in the masking policy but has been deleted from the sensitive data model. MODIFIED: A column that is present in the masking policy as well as the sensitive data model but some of its attributes have been modified.
        """
        return pulumi.get(self, "difference_type")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSdmMaskingPolicyDifferenceDifferenceColumnsFilterResult']]:
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
    def objects(self) -> Optional[Sequence[str]]:
        """
        The database object that contains the difference column.
        """
        return pulumi.get(self, "objects")

    @property
    @pulumi.getter(name="plannedAction")
    def planned_action(self) -> Optional[str]:
        """
        Specifies how to process the difference column. It's set to SYNC by default. Use the PatchSdmMaskingPolicyDifferenceColumns operation to update this attribute. You can choose one of the following options: SYNC: To sync the difference column and update the masking policy to reflect the changes. NO_SYNC: To not sync the difference column so that it doesn't change the masking policy. After specifying the planned action, you can use the ApplySdmMaskingPolicyDifference operation to automatically process the difference columns.
        """
        return pulumi.get(self, "planned_action")

    @property
    @pulumi.getter(name="schemaNames")
    def schema_names(self) -> Optional[Sequence[str]]:
        """
        The database schema that contains the difference column.
        """
        return pulumi.get(self, "schema_names")

    @property
    @pulumi.getter(name="sdmMaskingPolicyDifferenceColumnCollections")
    def sdm_masking_policy_difference_column_collections(self) -> Sequence['outputs.GetSdmMaskingPolicyDifferenceDifferenceColumnsSdmMaskingPolicyDifferenceColumnCollectionResult']:
        """
        The list of sdm_masking_policy_difference_column_collection.
        """
        return pulumi.get(self, "sdm_masking_policy_difference_column_collections")

    @property
    @pulumi.getter(name="sdmMaskingPolicyDifferenceId")
    def sdm_masking_policy_difference_id(self) -> str:
        return pulumi.get(self, "sdm_masking_policy_difference_id")

    @property
    @pulumi.getter(name="syncStatus")
    def sync_status(self) -> Optional[str]:
        """
        Indicates if the difference column has been processed. Use GetDifferenceColumn operation to  track whether the difference column has already been processed and applied to the masking policy.
        """
        return pulumi.get(self, "sync_status")


class AwaitableGetSdmMaskingPolicyDifferenceDifferenceColumnsResult(GetSdmMaskingPolicyDifferenceDifferenceColumnsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSdmMaskingPolicyDifferenceDifferenceColumnsResult(
            column_names=self.column_names,
            difference_type=self.difference_type,
            filters=self.filters,
            id=self.id,
            objects=self.objects,
            planned_action=self.planned_action,
            schema_names=self.schema_names,
            sdm_masking_policy_difference_column_collections=self.sdm_masking_policy_difference_column_collections,
            sdm_masking_policy_difference_id=self.sdm_masking_policy_difference_id,
            sync_status=self.sync_status)


def get_sdm_masking_policy_difference_difference_columns(column_names: Optional[Sequence[str]] = None,
                                                         difference_type: Optional[str] = None,
                                                         filters: Optional[Sequence[pulumi.InputType['GetSdmMaskingPolicyDifferenceDifferenceColumnsFilterArgs']]] = None,
                                                         objects: Optional[Sequence[str]] = None,
                                                         planned_action: Optional[str] = None,
                                                         schema_names: Optional[Sequence[str]] = None,
                                                         sdm_masking_policy_difference_id: Optional[str] = None,
                                                         sync_status: Optional[str] = None,
                                                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSdmMaskingPolicyDifferenceDifferenceColumnsResult:
    """
    This data source provides the list of Sdm Masking Policy Difference Difference Columns in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of columns of a SDM masking policy difference resource based on the specified query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_sdm_masking_policy_difference_difference_columns = oci.DataSafe.get_sdm_masking_policy_difference_difference_columns(sdm_masking_policy_difference_id=oci_data_safe_sdm_masking_policy_difference["test_sdm_masking_policy_difference"]["id"],
        column_names=var["sdm_masking_policy_difference_difference_column_column_name"],
        difference_type=var["sdm_masking_policy_difference_difference_column_difference_type"],
        objects=var["sdm_masking_policy_difference_difference_column_object"],
        planned_action=var["sdm_masking_policy_difference_difference_column_planned_action"],
        schema_names=var["sdm_masking_policy_difference_difference_column_schema_name"],
        sync_status=var["sdm_masking_policy_difference_difference_column_sync_status"])
    ```


    :param Sequence[str] column_names: A filter to return only a specific column based on column name.
    :param str difference_type: A filter to return only the SDM masking policy difference columns that match the specified difference type
    :param Sequence[str] objects: A filter to return only items related to a specific object name.
    :param str planned_action: A filter to return only the SDM masking policy difference columns that match the specified planned action.
    :param Sequence[str] schema_names: A filter to return only items related to specific schema name.
    :param str sdm_masking_policy_difference_id: The OCID of the SDM masking policy difference.
    :param str sync_status: A filter to return the SDM masking policy difference columns based on the value of their syncStatus attribute.
    """
    __args__ = dict()
    __args__['columnNames'] = column_names
    __args__['differenceType'] = difference_type
    __args__['filters'] = filters
    __args__['objects'] = objects
    __args__['plannedAction'] = planned_action
    __args__['schemaNames'] = schema_names
    __args__['sdmMaskingPolicyDifferenceId'] = sdm_masking_policy_difference_id
    __args__['syncStatus'] = sync_status
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getSdmMaskingPolicyDifferenceDifferenceColumns:getSdmMaskingPolicyDifferenceDifferenceColumns', __args__, opts=opts, typ=GetSdmMaskingPolicyDifferenceDifferenceColumnsResult).value

    return AwaitableGetSdmMaskingPolicyDifferenceDifferenceColumnsResult(
        column_names=__ret__.column_names,
        difference_type=__ret__.difference_type,
        filters=__ret__.filters,
        id=__ret__.id,
        objects=__ret__.objects,
        planned_action=__ret__.planned_action,
        schema_names=__ret__.schema_names,
        sdm_masking_policy_difference_column_collections=__ret__.sdm_masking_policy_difference_column_collections,
        sdm_masking_policy_difference_id=__ret__.sdm_masking_policy_difference_id,
        sync_status=__ret__.sync_status)


@_utilities.lift_output_func(get_sdm_masking_policy_difference_difference_columns)
def get_sdm_masking_policy_difference_difference_columns_output(column_names: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                                                                difference_type: Optional[pulumi.Input[Optional[str]]] = None,
                                                                filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetSdmMaskingPolicyDifferenceDifferenceColumnsFilterArgs']]]]] = None,
                                                                objects: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                                                                planned_action: Optional[pulumi.Input[Optional[str]]] = None,
                                                                schema_names: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                                                                sdm_masking_policy_difference_id: Optional[pulumi.Input[str]] = None,
                                                                sync_status: Optional[pulumi.Input[Optional[str]]] = None,
                                                                opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetSdmMaskingPolicyDifferenceDifferenceColumnsResult]:
    """
    This data source provides the list of Sdm Masking Policy Difference Difference Columns in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of columns of a SDM masking policy difference resource based on the specified query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_sdm_masking_policy_difference_difference_columns = oci.DataSafe.get_sdm_masking_policy_difference_difference_columns(sdm_masking_policy_difference_id=oci_data_safe_sdm_masking_policy_difference["test_sdm_masking_policy_difference"]["id"],
        column_names=var["sdm_masking_policy_difference_difference_column_column_name"],
        difference_type=var["sdm_masking_policy_difference_difference_column_difference_type"],
        objects=var["sdm_masking_policy_difference_difference_column_object"],
        planned_action=var["sdm_masking_policy_difference_difference_column_planned_action"],
        schema_names=var["sdm_masking_policy_difference_difference_column_schema_name"],
        sync_status=var["sdm_masking_policy_difference_difference_column_sync_status"])
    ```


    :param Sequence[str] column_names: A filter to return only a specific column based on column name.
    :param str difference_type: A filter to return only the SDM masking policy difference columns that match the specified difference type
    :param Sequence[str] objects: A filter to return only items related to a specific object name.
    :param str planned_action: A filter to return only the SDM masking policy difference columns that match the specified planned action.
    :param Sequence[str] schema_names: A filter to return only items related to specific schema name.
    :param str sdm_masking_policy_difference_id: The OCID of the SDM masking policy difference.
    :param str sync_status: A filter to return the SDM masking policy difference columns based on the value of their syncStatus attribute.
    """
    ...