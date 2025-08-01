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
    'GetWlmsWlsDomainServersResult',
    'AwaitableGetWlmsWlsDomainServersResult',
    'get_wlms_wls_domain_servers',
    'get_wlms_wls_domain_servers_output',
]

@pulumi.output_type
class GetWlmsWlsDomainServersResult:
    """
    A collection of values returned by getWlmsWlsDomainServers.
    """
    def __init__(__self__, filters=None, id=None, name=None, server_collections=None, wls_domain_id=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if server_collections and not isinstance(server_collections, list):
            raise TypeError("Expected argument 'server_collections' to be a list")
        pulumi.set(__self__, "server_collections", server_collections)
        if wls_domain_id and not isinstance(wls_domain_id, str):
            raise TypeError("Expected argument 'wls_domain_id' to be a str")
        pulumi.set(__self__, "wls_domain_id", wls_domain_id)

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetWlmsWlsDomainServersFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[_builtins.str]:
        """
        The name of the server.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="serverCollections")
    def server_collections(self) -> Sequence['outputs.GetWlmsWlsDomainServersServerCollectionResult']:
        """
        The list of server_collection.
        """
        return pulumi.get(self, "server_collections")

    @_builtins.property
    @pulumi.getter(name="wlsDomainId")
    def wls_domain_id(self) -> _builtins.str:
        """
        The ID of the WebLogic domain to which the server belongs.
        """
        return pulumi.get(self, "wls_domain_id")


class AwaitableGetWlmsWlsDomainServersResult(GetWlmsWlsDomainServersResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetWlmsWlsDomainServersResult(
            filters=self.filters,
            id=self.id,
            name=self.name,
            server_collections=self.server_collections,
            wls_domain_id=self.wls_domain_id)


def get_wlms_wls_domain_servers(filters: Optional[Sequence[Union['GetWlmsWlsDomainServersFilterArgs', 'GetWlmsWlsDomainServersFilterArgsDict']]] = None,
                                name: Optional[_builtins.str] = None,
                                wls_domain_id: Optional[_builtins.str] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetWlmsWlsDomainServersResult:
    """
    This data source provides the list of Wls Domain Servers in Oracle Cloud Infrastructure Wlms service.

    Gets list of servers in a specific WebLogic domain.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_wls_domain_servers = oci.oci.get_wlms_wls_domain_servers(wls_domain_id=test_wls_domain["id"],
        name=wls_domain_server_name)
    ```


    :param _builtins.str name: The name of the resource.
    :param _builtins.str wls_domain_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['wlsDomainId'] = wls_domain_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:oci/getWlmsWlsDomainServers:getWlmsWlsDomainServers', __args__, opts=opts, typ=GetWlmsWlsDomainServersResult).value

    return AwaitableGetWlmsWlsDomainServersResult(
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        name=pulumi.get(__ret__, 'name'),
        server_collections=pulumi.get(__ret__, 'server_collections'),
        wls_domain_id=pulumi.get(__ret__, 'wls_domain_id'))
def get_wlms_wls_domain_servers_output(filters: Optional[pulumi.Input[Optional[Sequence[Union['GetWlmsWlsDomainServersFilterArgs', 'GetWlmsWlsDomainServersFilterArgsDict']]]]] = None,
                                       name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                       wls_domain_id: Optional[pulumi.Input[_builtins.str]] = None,
                                       opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetWlmsWlsDomainServersResult]:
    """
    This data source provides the list of Wls Domain Servers in Oracle Cloud Infrastructure Wlms service.

    Gets list of servers in a specific WebLogic domain.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_wls_domain_servers = oci.oci.get_wlms_wls_domain_servers(wls_domain_id=test_wls_domain["id"],
        name=wls_domain_server_name)
    ```


    :param _builtins.str name: The name of the resource.
    :param _builtins.str wls_domain_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['wlsDomainId'] = wls_domain_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:oci/getWlmsWlsDomainServers:getWlmsWlsDomainServers', __args__, opts=opts, typ=GetWlmsWlsDomainServersResult)
    return __ret__.apply(lambda __response__: GetWlmsWlsDomainServersResult(
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        name=pulumi.get(__response__, 'name'),
        server_collections=pulumi.get(__response__, 'server_collections'),
        wls_domain_id=pulumi.get(__response__, 'wls_domain_id')))
