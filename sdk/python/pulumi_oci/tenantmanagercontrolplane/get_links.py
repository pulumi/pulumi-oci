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
    'GetLinksResult',
    'AwaitableGetLinksResult',
    'get_links',
    'get_links_output',
]

@pulumi.output_type
class GetLinksResult:
    """
    A collection of values returned by getLinks.
    """
    def __init__(__self__, child_tenancy_id=None, filters=None, id=None, link_collections=None, parent_tenancy_id=None, state=None):
        if child_tenancy_id and not isinstance(child_tenancy_id, str):
            raise TypeError("Expected argument 'child_tenancy_id' to be a str")
        pulumi.set(__self__, "child_tenancy_id", child_tenancy_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if link_collections and not isinstance(link_collections, list):
            raise TypeError("Expected argument 'link_collections' to be a list")
        pulumi.set(__self__, "link_collections", link_collections)
        if parent_tenancy_id and not isinstance(parent_tenancy_id, str):
            raise TypeError("Expected argument 'parent_tenancy_id' to be a str")
        pulumi.set(__self__, "parent_tenancy_id", parent_tenancy_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="childTenancyId")
    def child_tenancy_id(self) -> Optional[_builtins.str]:
        """
        OCID of the child tenancy.
        """
        return pulumi.get(self, "child_tenancy_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetLinksFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="linkCollections")
    def link_collections(self) -> Sequence['outputs.GetLinksLinkCollectionResult']:
        """
        The list of link_collection.
        """
        return pulumi.get(self, "link_collections")

    @_builtins.property
    @pulumi.getter(name="parentTenancyId")
    def parent_tenancy_id(self) -> Optional[_builtins.str]:
        """
        OCID of the parent tenancy.
        """
        return pulumi.get(self, "parent_tenancy_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        Lifecycle state of the link.
        """
        return pulumi.get(self, "state")


class AwaitableGetLinksResult(GetLinksResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetLinksResult(
            child_tenancy_id=self.child_tenancy_id,
            filters=self.filters,
            id=self.id,
            link_collections=self.link_collections,
            parent_tenancy_id=self.parent_tenancy_id,
            state=self.state)


def get_links(child_tenancy_id: Optional[_builtins.str] = None,
              filters: Optional[Sequence[Union['GetLinksFilterArgs', 'GetLinksFilterArgsDict']]] = None,
              parent_tenancy_id: Optional[_builtins.str] = None,
              state: Optional[_builtins.str] = None,
              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetLinksResult:
    """
    This data source provides the list of Links in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.

    Return a (paginated) list of links.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_links = oci.Tenantmanagercontrolplane.get_links(child_tenancy_id=test_tenancy["id"],
        parent_tenancy_id=test_tenancy["id"],
        state=link_state)
    ```


    :param _builtins.str child_tenancy_id: The ID of the child tenancy this link is associated with.
    :param _builtins.str parent_tenancy_id: The ID of the parent tenancy this link is associated with.
    :param _builtins.str state: The lifecycle state of the resource.
    """
    __args__ = dict()
    __args__['childTenancyId'] = child_tenancy_id
    __args__['filters'] = filters
    __args__['parentTenancyId'] = parent_tenancy_id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Tenantmanagercontrolplane/getLinks:getLinks', __args__, opts=opts, typ=GetLinksResult).value

    return AwaitableGetLinksResult(
        child_tenancy_id=pulumi.get(__ret__, 'child_tenancy_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        link_collections=pulumi.get(__ret__, 'link_collections'),
        parent_tenancy_id=pulumi.get(__ret__, 'parent_tenancy_id'),
        state=pulumi.get(__ret__, 'state'))
def get_links_output(child_tenancy_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                     filters: Optional[pulumi.Input[Optional[Sequence[Union['GetLinksFilterArgs', 'GetLinksFilterArgsDict']]]]] = None,
                     parent_tenancy_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                     state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                     opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetLinksResult]:
    """
    This data source provides the list of Links in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.

    Return a (paginated) list of links.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_links = oci.Tenantmanagercontrolplane.get_links(child_tenancy_id=test_tenancy["id"],
        parent_tenancy_id=test_tenancy["id"],
        state=link_state)
    ```


    :param _builtins.str child_tenancy_id: The ID of the child tenancy this link is associated with.
    :param _builtins.str parent_tenancy_id: The ID of the parent tenancy this link is associated with.
    :param _builtins.str state: The lifecycle state of the resource.
    """
    __args__ = dict()
    __args__['childTenancyId'] = child_tenancy_id
    __args__['filters'] = filters
    __args__['parentTenancyId'] = parent_tenancy_id
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Tenantmanagercontrolplane/getLinks:getLinks', __args__, opts=opts, typ=GetLinksResult)
    return __ret__.apply(lambda __response__: GetLinksResult(
        child_tenancy_id=pulumi.get(__response__, 'child_tenancy_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        link_collections=pulumi.get(__response__, 'link_collections'),
        parent_tenancy_id=pulumi.get(__response__, 'parent_tenancy_id'),
        state=pulumi.get(__response__, 'state')))
