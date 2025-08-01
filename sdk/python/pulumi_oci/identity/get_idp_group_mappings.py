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
    'GetIdpGroupMappingsResult',
    'AwaitableGetIdpGroupMappingsResult',
    'get_idp_group_mappings',
    'get_idp_group_mappings_output',
]

@pulumi.output_type
class GetIdpGroupMappingsResult:
    """
    A collection of values returned by getIdpGroupMappings.
    """
    def __init__(__self__, filters=None, id=None, identity_provider_id=None, idp_group_mappings=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if identity_provider_id and not isinstance(identity_provider_id, str):
            raise TypeError("Expected argument 'identity_provider_id' to be a str")
        pulumi.set(__self__, "identity_provider_id", identity_provider_id)
        if idp_group_mappings and not isinstance(idp_group_mappings, list):
            raise TypeError("Expected argument 'idp_group_mappings' to be a list")
        pulumi.set(__self__, "idp_group_mappings", idp_group_mappings)

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetIdpGroupMappingsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="identityProviderId")
    def identity_provider_id(self) -> _builtins.str:
        """
        The OCID of the `IdentityProvider` this mapping belongs to.
        """
        return pulumi.get(self, "identity_provider_id")

    @_builtins.property
    @pulumi.getter(name="idpGroupMappings")
    def idp_group_mappings(self) -> Sequence['outputs.GetIdpGroupMappingsIdpGroupMappingResult']:
        """
        The list of idp_group_mappings.
        """
        return pulumi.get(self, "idp_group_mappings")


class AwaitableGetIdpGroupMappingsResult(GetIdpGroupMappingsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetIdpGroupMappingsResult(
            filters=self.filters,
            id=self.id,
            identity_provider_id=self.identity_provider_id,
            idp_group_mappings=self.idp_group_mappings)


def get_idp_group_mappings(filters: Optional[Sequence[Union['GetIdpGroupMappingsFilterArgs', 'GetIdpGroupMappingsFilterArgsDict']]] = None,
                           identity_provider_id: Optional[_builtins.str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetIdpGroupMappingsResult:
    """
    This data source provides the list of Idp Group Mappings in Oracle Cloud Infrastructure Identity service.

    **Deprecated.** For more information, see [Deprecated IAM Service APIs](https://docs.cloud.oracle.com/iaas/Content/Identity/Reference/deprecatediamapis.htm).

    Lists the group mappings for the specified identity provider.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_idp_group_mappings = oci.Identity.get_idp_group_mappings(identity_provider_id=test_identity_provider["id"])
    ```


    :param _builtins.str identity_provider_id: The OCID of the identity provider.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['identityProviderId'] = identity_provider_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Identity/getIdpGroupMappings:getIdpGroupMappings', __args__, opts=opts, typ=GetIdpGroupMappingsResult).value

    return AwaitableGetIdpGroupMappingsResult(
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        identity_provider_id=pulumi.get(__ret__, 'identity_provider_id'),
        idp_group_mappings=pulumi.get(__ret__, 'idp_group_mappings'))
def get_idp_group_mappings_output(filters: Optional[pulumi.Input[Optional[Sequence[Union['GetIdpGroupMappingsFilterArgs', 'GetIdpGroupMappingsFilterArgsDict']]]]] = None,
                                  identity_provider_id: Optional[pulumi.Input[_builtins.str]] = None,
                                  opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetIdpGroupMappingsResult]:
    """
    This data source provides the list of Idp Group Mappings in Oracle Cloud Infrastructure Identity service.

    **Deprecated.** For more information, see [Deprecated IAM Service APIs](https://docs.cloud.oracle.com/iaas/Content/Identity/Reference/deprecatediamapis.htm).

    Lists the group mappings for the specified identity provider.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_idp_group_mappings = oci.Identity.get_idp_group_mappings(identity_provider_id=test_identity_provider["id"])
    ```


    :param _builtins.str identity_provider_id: The OCID of the identity provider.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['identityProviderId'] = identity_provider_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Identity/getIdpGroupMappings:getIdpGroupMappings', __args__, opts=opts, typ=GetIdpGroupMappingsResult)
    return __ret__.apply(lambda __response__: GetIdpGroupMappingsResult(
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        identity_provider_id=pulumi.get(__response__, 'identity_provider_id'),
        idp_group_mappings=pulumi.get(__response__, 'idp_group_mappings')))
