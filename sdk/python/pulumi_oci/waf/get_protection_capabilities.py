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
    'GetProtectionCapabilitiesResult',
    'AwaitableGetProtectionCapabilitiesResult',
    'get_protection_capabilities',
    'get_protection_capabilities_output',
]

@pulumi.output_type
class GetProtectionCapabilitiesResult:
    """
    A collection of values returned by getProtectionCapabilities.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, group_tags=None, id=None, is_latest_versions=None, key=None, protection_capability_collections=None, type=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if group_tags and not isinstance(group_tags, list):
            raise TypeError("Expected argument 'group_tags' to be a list")
        pulumi.set(__self__, "group_tags", group_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_latest_versions and not isinstance(is_latest_versions, list):
            raise TypeError("Expected argument 'is_latest_versions' to be a list")
        pulumi.set(__self__, "is_latest_versions", is_latest_versions)
        if key and not isinstance(key, str):
            raise TypeError("Expected argument 'key' to be a str")
        pulumi.set(__self__, "key", key)
        if protection_capability_collections and not isinstance(protection_capability_collections, list):
            raise TypeError("Expected argument 'protection_capability_collections' to be a list")
        pulumi.set(__self__, "protection_capability_collections", protection_capability_collections)
        if type and not isinstance(type, str):
            raise TypeError("Expected argument 'type' to be a str")
        pulumi.set(__self__, "type", type)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        The display name of protection capability.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetProtectionCapabilitiesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter(name="groupTags")
    def group_tags(self) -> Optional[Sequence[_builtins.str]]:
        return pulumi.get(self, "group_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isLatestVersions")
    def is_latest_versions(self) -> Optional[Sequence[_builtins.bool]]:
        """
        The field that shows if this is the latest version of protection capability.
        """
        return pulumi.get(self, "is_latest_versions")

    @_builtins.property
    @pulumi.getter
    def key(self) -> Optional[_builtins.str]:
        """
        Unique key of protection capability.
        """
        return pulumi.get(self, "key")

    @_builtins.property
    @pulumi.getter(name="protectionCapabilityCollections")
    def protection_capability_collections(self) -> Sequence['outputs.GetProtectionCapabilitiesProtectionCapabilityCollectionResult']:
        """
        The list of protection_capability_collection.
        """
        return pulumi.get(self, "protection_capability_collections")

    @_builtins.property
    @pulumi.getter
    def type(self) -> Optional[_builtins.str]:
        """
        The type of protection capability.
        * **REQUEST_PROTECTION_CAPABILITY** can only be used in `requestProtection` module of WebAppFirewallPolicy.
        * **RESPONSE_PROTECTION_CAPABILITY** can only be used in `responseProtection` module of WebAppFirewallPolicy.
        """
        return pulumi.get(self, "type")


class AwaitableGetProtectionCapabilitiesResult(GetProtectionCapabilitiesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetProtectionCapabilitiesResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            group_tags=self.group_tags,
            id=self.id,
            is_latest_versions=self.is_latest_versions,
            key=self.key,
            protection_capability_collections=self.protection_capability_collections,
            type=self.type)


def get_protection_capabilities(compartment_id: Optional[_builtins.str] = None,
                                display_name: Optional[_builtins.str] = None,
                                filters: Optional[Sequence[Union['GetProtectionCapabilitiesFilterArgs', 'GetProtectionCapabilitiesFilterArgsDict']]] = None,
                                group_tags: Optional[Sequence[_builtins.str]] = None,
                                is_latest_versions: Optional[Sequence[_builtins.bool]] = None,
                                key: Optional[_builtins.str] = None,
                                type: Optional[_builtins.str] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetProtectionCapabilitiesResult:
    """
    This data source provides the list of Protection Capabilities in Oracle Cloud Infrastructure Waf service.

    Lists of protection capabilities filtered by query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_protection_capabilities = oci.Waf.get_protection_capabilities(compartment_id=compartment_id,
        display_name=protection_capability_display_name,
        group_tags=protection_capability_group_tag,
        is_latest_versions=protection_capability_is_latest_version,
        key=protection_capability_key,
        type=protection_capability_type)
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param Sequence[_builtins.str] group_tags: A filter to return only resources that are accociated given group tag.
    :param Sequence[_builtins.bool] is_latest_versions: A filter to return only resources that matches given isLatestVersion.
    :param _builtins.str key: The unique key of protection capability to filter by.
    :param _builtins.str type: A filter to return only resources that matches given type.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['groupTags'] = group_tags
    __args__['isLatestVersions'] = is_latest_versions
    __args__['key'] = key
    __args__['type'] = type
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Waf/getProtectionCapabilities:getProtectionCapabilities', __args__, opts=opts, typ=GetProtectionCapabilitiesResult).value

    return AwaitableGetProtectionCapabilitiesResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        group_tags=pulumi.get(__ret__, 'group_tags'),
        id=pulumi.get(__ret__, 'id'),
        is_latest_versions=pulumi.get(__ret__, 'is_latest_versions'),
        key=pulumi.get(__ret__, 'key'),
        protection_capability_collections=pulumi.get(__ret__, 'protection_capability_collections'),
        type=pulumi.get(__ret__, 'type'))
def get_protection_capabilities_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                       display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                       filters: Optional[pulumi.Input[Optional[Sequence[Union['GetProtectionCapabilitiesFilterArgs', 'GetProtectionCapabilitiesFilterArgsDict']]]]] = None,
                                       group_tags: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                       is_latest_versions: Optional[pulumi.Input[Optional[Sequence[_builtins.bool]]]] = None,
                                       key: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                       type: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                       opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetProtectionCapabilitiesResult]:
    """
    This data source provides the list of Protection Capabilities in Oracle Cloud Infrastructure Waf service.

    Lists of protection capabilities filtered by query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_protection_capabilities = oci.Waf.get_protection_capabilities(compartment_id=compartment_id,
        display_name=protection_capability_display_name,
        group_tags=protection_capability_group_tag,
        is_latest_versions=protection_capability_is_latest_version,
        key=protection_capability_key,
        type=protection_capability_type)
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param Sequence[_builtins.str] group_tags: A filter to return only resources that are accociated given group tag.
    :param Sequence[_builtins.bool] is_latest_versions: A filter to return only resources that matches given isLatestVersion.
    :param _builtins.str key: The unique key of protection capability to filter by.
    :param _builtins.str type: A filter to return only resources that matches given type.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['groupTags'] = group_tags
    __args__['isLatestVersions'] = is_latest_versions
    __args__['key'] = key
    __args__['type'] = type
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Waf/getProtectionCapabilities:getProtectionCapabilities', __args__, opts=opts, typ=GetProtectionCapabilitiesResult)
    return __ret__.apply(lambda __response__: GetProtectionCapabilitiesResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        group_tags=pulumi.get(__response__, 'group_tags'),
        id=pulumi.get(__response__, 'id'),
        is_latest_versions=pulumi.get(__response__, 'is_latest_versions'),
        key=pulumi.get(__response__, 'key'),
        protection_capability_collections=pulumi.get(__response__, 'protection_capability_collections'),
        type=pulumi.get(__response__, 'type')))
