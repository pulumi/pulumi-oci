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
    'GetAssetsResult',
    'AwaitableGetAssetsResult',
    'get_assets',
    'get_assets_output',
]

@pulumi.output_type
class GetAssetsResult:
    """
    A collection of values returned by getAssets.
    """
    def __init__(__self__, asset_collections=None, asset_id=None, asset_type=None, compartment_id=None, display_name=None, external_asset_key=None, filters=None, id=None, inventory_id=None, source_key=None, state=None):
        if asset_collections and not isinstance(asset_collections, list):
            raise TypeError("Expected argument 'asset_collections' to be a list")
        pulumi.set(__self__, "asset_collections", asset_collections)
        if asset_id and not isinstance(asset_id, str):
            raise TypeError("Expected argument 'asset_id' to be a str")
        pulumi.set(__self__, "asset_id", asset_id)
        if asset_type and not isinstance(asset_type, str):
            raise TypeError("Expected argument 'asset_type' to be a str")
        pulumi.set(__self__, "asset_type", asset_type)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if external_asset_key and not isinstance(external_asset_key, str):
            raise TypeError("Expected argument 'external_asset_key' to be a str")
        pulumi.set(__self__, "external_asset_key", external_asset_key)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if inventory_id and not isinstance(inventory_id, str):
            raise TypeError("Expected argument 'inventory_id' to be a str")
        pulumi.set(__self__, "inventory_id", inventory_id)
        if source_key and not isinstance(source_key, str):
            raise TypeError("Expected argument 'source_key' to be a str")
        pulumi.set(__self__, "source_key", source_key)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="assetCollections")
    def asset_collections(self) -> Sequence['outputs.GetAssetsAssetCollectionResult']:
        """
        The list of asset_collection.
        """
        return pulumi.get(self, "asset_collections")

    @_builtins.property
    @pulumi.getter(name="assetId")
    def asset_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "asset_id")

    @_builtins.property
    @pulumi.getter(name="assetType")
    def asset_type(self) -> Optional[_builtins.str]:
        """
        The type of asset.
        """
        return pulumi.get(self, "asset_type")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment to which an asset belongs to.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        Asset display name.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="externalAssetKey")
    def external_asset_key(self) -> Optional[_builtins.str]:
        """
        The key of the asset from the external environment.
        """
        return pulumi.get(self, "external_asset_key")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetAssetsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="inventoryId")
    def inventory_id(self) -> Optional[_builtins.str]:
        """
        Inventory ID to which an asset belongs to.
        """
        return pulumi.get(self, "inventory_id")

    @_builtins.property
    @pulumi.getter(name="sourceKey")
    def source_key(self) -> Optional[_builtins.str]:
        """
        The source key that the asset belongs to.
        """
        return pulumi.get(self, "source_key")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the asset.
        """
        return pulumi.get(self, "state")


class AwaitableGetAssetsResult(GetAssetsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAssetsResult(
            asset_collections=self.asset_collections,
            asset_id=self.asset_id,
            asset_type=self.asset_type,
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            external_asset_key=self.external_asset_key,
            filters=self.filters,
            id=self.id,
            inventory_id=self.inventory_id,
            source_key=self.source_key,
            state=self.state)


def get_assets(asset_id: Optional[_builtins.str] = None,
               asset_type: Optional[_builtins.str] = None,
               compartment_id: Optional[_builtins.str] = None,
               display_name: Optional[_builtins.str] = None,
               external_asset_key: Optional[_builtins.str] = None,
               filters: Optional[Sequence[Union['GetAssetsFilterArgs', 'GetAssetsFilterArgsDict']]] = None,
               inventory_id: Optional[_builtins.str] = None,
               source_key: Optional[_builtins.str] = None,
               state: Optional[_builtins.str] = None,
               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAssetsResult:
    """
    This data source provides the list of Assets in Oracle Cloud Infrastructure Cloud Bridge service.

    Returns a list of assets.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_assets = oci.CloudBridge.get_assets(compartment_id=compartment_id,
        asset_id=test_asset["id"],
        asset_type=asset_asset_type,
        display_name=asset_display_name,
        external_asset_key=asset_external_asset_key,
        inventory_id=test_inventory["id"],
        source_key=asset_source_key,
        state=asset_state)
    ```


    :param _builtins.str asset_id: Unique asset identifier.
    :param _builtins.str asset_type: The type of asset.
    :param _builtins.str compartment_id: The ID of the compartment in which to list resources.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str external_asset_key: External asset key.
    :param _builtins.str inventory_id: Unique Inventory identifier.
    :param _builtins.str source_key: Source key from where the assets originate.
    :param _builtins.str state: A filter to return only assets whose lifecycleState matches the given lifecycleState.
    """
    __args__ = dict()
    __args__['assetId'] = asset_id
    __args__['assetType'] = asset_type
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['externalAssetKey'] = external_asset_key
    __args__['filters'] = filters
    __args__['inventoryId'] = inventory_id
    __args__['sourceKey'] = source_key
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:CloudBridge/getAssets:getAssets', __args__, opts=opts, typ=GetAssetsResult).value

    return AwaitableGetAssetsResult(
        asset_collections=pulumi.get(__ret__, 'asset_collections'),
        asset_id=pulumi.get(__ret__, 'asset_id'),
        asset_type=pulumi.get(__ret__, 'asset_type'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        external_asset_key=pulumi.get(__ret__, 'external_asset_key'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        inventory_id=pulumi.get(__ret__, 'inventory_id'),
        source_key=pulumi.get(__ret__, 'source_key'),
        state=pulumi.get(__ret__, 'state'))
def get_assets_output(asset_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                      asset_type: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                      compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                      display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                      external_asset_key: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                      filters: Optional[pulumi.Input[Optional[Sequence[Union['GetAssetsFilterArgs', 'GetAssetsFilterArgsDict']]]]] = None,
                      inventory_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                      source_key: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                      state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                      opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetAssetsResult]:
    """
    This data source provides the list of Assets in Oracle Cloud Infrastructure Cloud Bridge service.

    Returns a list of assets.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_assets = oci.CloudBridge.get_assets(compartment_id=compartment_id,
        asset_id=test_asset["id"],
        asset_type=asset_asset_type,
        display_name=asset_display_name,
        external_asset_key=asset_external_asset_key,
        inventory_id=test_inventory["id"],
        source_key=asset_source_key,
        state=asset_state)
    ```


    :param _builtins.str asset_id: Unique asset identifier.
    :param _builtins.str asset_type: The type of asset.
    :param _builtins.str compartment_id: The ID of the compartment in which to list resources.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str external_asset_key: External asset key.
    :param _builtins.str inventory_id: Unique Inventory identifier.
    :param _builtins.str source_key: Source key from where the assets originate.
    :param _builtins.str state: A filter to return only assets whose lifecycleState matches the given lifecycleState.
    """
    __args__ = dict()
    __args__['assetId'] = asset_id
    __args__['assetType'] = asset_type
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['externalAssetKey'] = external_asset_key
    __args__['filters'] = filters
    __args__['inventoryId'] = inventory_id
    __args__['sourceKey'] = source_key
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:CloudBridge/getAssets:getAssets', __args__, opts=opts, typ=GetAssetsResult)
    return __ret__.apply(lambda __response__: GetAssetsResult(
        asset_collections=pulumi.get(__response__, 'asset_collections'),
        asset_id=pulumi.get(__response__, 'asset_id'),
        asset_type=pulumi.get(__response__, 'asset_type'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        external_asset_key=pulumi.get(__response__, 'external_asset_key'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        inventory_id=pulumi.get(__response__, 'inventory_id'),
        source_key=pulumi.get(__response__, 'source_key'),
        state=pulumi.get(__response__, 'state')))
