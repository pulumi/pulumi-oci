# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetRegistryDataAssetsResult',
    'AwaitableGetRegistryDataAssetsResult',
    'get_registry_data_assets',
    'get_registry_data_assets_output',
]

@pulumi.output_type
class GetRegistryDataAssetsResult:
    """
    A collection of values returned by getRegistryDataAssets.
    """
    def __init__(__self__, data_asset_summary_collections=None, endpoint_ids=None, exclude_endpoint_ids=None, exclude_types=None, favorites_query_param=None, fields=None, filters=None, folder_id=None, id=None, include_types=None, name=None, registry_id=None, type=None):
        if data_asset_summary_collections and not isinstance(data_asset_summary_collections, list):
            raise TypeError("Expected argument 'data_asset_summary_collections' to be a list")
        pulumi.set(__self__, "data_asset_summary_collections", data_asset_summary_collections)
        if endpoint_ids and not isinstance(endpoint_ids, list):
            raise TypeError("Expected argument 'endpoint_ids' to be a list")
        pulumi.set(__self__, "endpoint_ids", endpoint_ids)
        if exclude_endpoint_ids and not isinstance(exclude_endpoint_ids, list):
            raise TypeError("Expected argument 'exclude_endpoint_ids' to be a list")
        pulumi.set(__self__, "exclude_endpoint_ids", exclude_endpoint_ids)
        if exclude_types and not isinstance(exclude_types, list):
            raise TypeError("Expected argument 'exclude_types' to be a list")
        pulumi.set(__self__, "exclude_types", exclude_types)
        if favorites_query_param and not isinstance(favorites_query_param, str):
            raise TypeError("Expected argument 'favorites_query_param' to be a str")
        pulumi.set(__self__, "favorites_query_param", favorites_query_param)
        if fields and not isinstance(fields, list):
            raise TypeError("Expected argument 'fields' to be a list")
        pulumi.set(__self__, "fields", fields)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if folder_id and not isinstance(folder_id, str):
            raise TypeError("Expected argument 'folder_id' to be a str")
        pulumi.set(__self__, "folder_id", folder_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if include_types and not isinstance(include_types, list):
            raise TypeError("Expected argument 'include_types' to be a list")
        pulumi.set(__self__, "include_types", include_types)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if registry_id and not isinstance(registry_id, str):
            raise TypeError("Expected argument 'registry_id' to be a str")
        pulumi.set(__self__, "registry_id", registry_id)
        if type and not isinstance(type, str):
            raise TypeError("Expected argument 'type' to be a str")
        pulumi.set(__self__, "type", type)

    @property
    @pulumi.getter(name="dataAssetSummaryCollections")
    def data_asset_summary_collections(self) -> Sequence['outputs.GetRegistryDataAssetsDataAssetSummaryCollectionResult']:
        """
        The list of data_asset_summary_collection.
        """
        return pulumi.get(self, "data_asset_summary_collections")

    @property
    @pulumi.getter(name="endpointIds")
    def endpoint_ids(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "endpoint_ids")

    @property
    @pulumi.getter(name="excludeEndpointIds")
    def exclude_endpoint_ids(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "exclude_endpoint_ids")

    @property
    @pulumi.getter(name="excludeTypes")
    def exclude_types(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "exclude_types")

    @property
    @pulumi.getter(name="favoritesQueryParam")
    def favorites_query_param(self) -> Optional[str]:
        return pulumi.get(self, "favorites_query_param")

    @property
    @pulumi.getter
    def fields(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "fields")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetRegistryDataAssetsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter(name="folderId")
    def folder_id(self) -> Optional[str]:
        return pulumi.get(self, "folder_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="includeTypes")
    def include_types(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "include_types")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="registryId")
    def registry_id(self) -> str:
        return pulumi.get(self, "registry_id")

    @property
    @pulumi.getter
    def type(self) -> Optional[str]:
        """
        Specific DataAsset Type
        """
        return pulumi.get(self, "type")


class AwaitableGetRegistryDataAssetsResult(GetRegistryDataAssetsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetRegistryDataAssetsResult(
            data_asset_summary_collections=self.data_asset_summary_collections,
            endpoint_ids=self.endpoint_ids,
            exclude_endpoint_ids=self.exclude_endpoint_ids,
            exclude_types=self.exclude_types,
            favorites_query_param=self.favorites_query_param,
            fields=self.fields,
            filters=self.filters,
            folder_id=self.folder_id,
            id=self.id,
            include_types=self.include_types,
            name=self.name,
            registry_id=self.registry_id,
            type=self.type)


def get_registry_data_assets(endpoint_ids: Optional[Sequence[str]] = None,
                             exclude_endpoint_ids: Optional[Sequence[str]] = None,
                             exclude_types: Optional[Sequence[str]] = None,
                             favorites_query_param: Optional[str] = None,
                             fields: Optional[Sequence[str]] = None,
                             filters: Optional[Sequence[pulumi.InputType['GetRegistryDataAssetsFilterArgs']]] = None,
                             folder_id: Optional[str] = None,
                             include_types: Optional[Sequence[str]] = None,
                             name: Optional[str] = None,
                             registry_id: Optional[str] = None,
                             type: Optional[str] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetRegistryDataAssetsResult:
    """
    This data source provides the list of Registry Data Assets in Oracle Cloud Infrastructure Data Connectivity service.

    Retrieves a list of all data asset summaries.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_registry_data_assets = oci.DataConnectivity.get_registry_data_assets(registry_id=oci_data_connectivity_registry["test_registry"]["id"],
        endpoint_ids=var["registry_data_asset_endpoint_ids"],
        exclude_endpoint_ids=var["registry_data_asset_exclude_endpoint_ids"],
        exclude_types=var["registry_data_asset_exclude_types"],
        favorites_query_param=var["registry_data_asset_favorites_query_param"],
        fields=var["registry_data_asset_fields"],
        folder_id=oci_data_connectivity_folder["test_folder"]["id"],
        include_types=var["registry_data_asset_include_types"],
        name=var["registry_data_asset_name"])
    ```


    :param Sequence[str] endpoint_ids: Endpoint Ids used for data-plane APIs to filter or prefer specific endpoint.
    :param Sequence[str] exclude_endpoint_ids: Endpoints which will be excluded while listing dataAssets
    :param Sequence[str] exclude_types: Types which wont be listed while listing dataAsset/Connection
    :param str favorites_query_param: If value is FAVORITES_ONLY, then only objects marked as favorite by the requesting user will be included in result. If value is NON_FAVORITES_ONLY, then objects marked as favorites by the requesting user will be skipped. If value is ALL or if not specified, all objects, irrespective of favorites or not will be returned. Default is ALL.
    :param Sequence[str] fields: Specifies the fields to get for an object.
    :param str folder_id: Unique key of the folder.
    :param Sequence[str] include_types: DataAsset type which needs to be listed while listing dataAssets
    :param str name: Used to filter by the name of the object.
    :param str registry_id: The registry Ocid.
    :param str type: Specific DataAsset Type
    """
    __args__ = dict()
    __args__['endpointIds'] = endpoint_ids
    __args__['excludeEndpointIds'] = exclude_endpoint_ids
    __args__['excludeTypes'] = exclude_types
    __args__['favoritesQueryParam'] = favorites_query_param
    __args__['fields'] = fields
    __args__['filters'] = filters
    __args__['folderId'] = folder_id
    __args__['includeTypes'] = include_types
    __args__['name'] = name
    __args__['registryId'] = registry_id
    __args__['type'] = type
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:DataConnectivity/getRegistryDataAssets:getRegistryDataAssets', __args__, opts=opts, typ=GetRegistryDataAssetsResult).value

    return AwaitableGetRegistryDataAssetsResult(
        data_asset_summary_collections=__ret__.data_asset_summary_collections,
        endpoint_ids=__ret__.endpoint_ids,
        exclude_endpoint_ids=__ret__.exclude_endpoint_ids,
        exclude_types=__ret__.exclude_types,
        favorites_query_param=__ret__.favorites_query_param,
        fields=__ret__.fields,
        filters=__ret__.filters,
        folder_id=__ret__.folder_id,
        id=__ret__.id,
        include_types=__ret__.include_types,
        name=__ret__.name,
        registry_id=__ret__.registry_id,
        type=__ret__.type)


@_utilities.lift_output_func(get_registry_data_assets)
def get_registry_data_assets_output(endpoint_ids: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                                    exclude_endpoint_ids: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                                    exclude_types: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                                    favorites_query_param: Optional[pulumi.Input[Optional[str]]] = None,
                                    fields: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                                    filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetRegistryDataAssetsFilterArgs']]]]] = None,
                                    folder_id: Optional[pulumi.Input[Optional[str]]] = None,
                                    include_types: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                                    name: Optional[pulumi.Input[Optional[str]]] = None,
                                    registry_id: Optional[pulumi.Input[str]] = None,
                                    type: Optional[pulumi.Input[Optional[str]]] = None,
                                    opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetRegistryDataAssetsResult]:
    """
    This data source provides the list of Registry Data Assets in Oracle Cloud Infrastructure Data Connectivity service.

    Retrieves a list of all data asset summaries.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_registry_data_assets = oci.DataConnectivity.get_registry_data_assets(registry_id=oci_data_connectivity_registry["test_registry"]["id"],
        endpoint_ids=var["registry_data_asset_endpoint_ids"],
        exclude_endpoint_ids=var["registry_data_asset_exclude_endpoint_ids"],
        exclude_types=var["registry_data_asset_exclude_types"],
        favorites_query_param=var["registry_data_asset_favorites_query_param"],
        fields=var["registry_data_asset_fields"],
        folder_id=oci_data_connectivity_folder["test_folder"]["id"],
        include_types=var["registry_data_asset_include_types"],
        name=var["registry_data_asset_name"])
    ```


    :param Sequence[str] endpoint_ids: Endpoint Ids used for data-plane APIs to filter or prefer specific endpoint.
    :param Sequence[str] exclude_endpoint_ids: Endpoints which will be excluded while listing dataAssets
    :param Sequence[str] exclude_types: Types which wont be listed while listing dataAsset/Connection
    :param str favorites_query_param: If value is FAVORITES_ONLY, then only objects marked as favorite by the requesting user will be included in result. If value is NON_FAVORITES_ONLY, then objects marked as favorites by the requesting user will be skipped. If value is ALL or if not specified, all objects, irrespective of favorites or not will be returned. Default is ALL.
    :param Sequence[str] fields: Specifies the fields to get for an object.
    :param str folder_id: Unique key of the folder.
    :param Sequence[str] include_types: DataAsset type which needs to be listed while listing dataAssets
    :param str name: Used to filter by the name of the object.
    :param str registry_id: The registry Ocid.
    :param str type: Specific DataAsset Type
    """
    ...
