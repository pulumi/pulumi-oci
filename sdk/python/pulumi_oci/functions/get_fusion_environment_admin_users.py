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
    'GetFusionEnvironmentAdminUsersResult',
    'AwaitableGetFusionEnvironmentAdminUsersResult',
    'get_fusion_environment_admin_users',
    'get_fusion_environment_admin_users_output',
]

@pulumi.output_type
class GetFusionEnvironmentAdminUsersResult:
    """
    A collection of values returned by getFusionEnvironmentAdminUsers.
    """
    def __init__(__self__, admin_user_collections=None, filters=None, fusion_environment_id=None, id=None):
        if admin_user_collections and not isinstance(admin_user_collections, list):
            raise TypeError("Expected argument 'admin_user_collections' to be a list")
        pulumi.set(__self__, "admin_user_collections", admin_user_collections)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if fusion_environment_id and not isinstance(fusion_environment_id, str):
            raise TypeError("Expected argument 'fusion_environment_id' to be a str")
        pulumi.set(__self__, "fusion_environment_id", fusion_environment_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @_builtins.property
    @pulumi.getter(name="adminUserCollections")
    def admin_user_collections(self) -> Sequence['outputs.GetFusionEnvironmentAdminUsersAdminUserCollectionResult']:
        """
        The list of admin_user_collection.
        """
        return pulumi.get(self, "admin_user_collections")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetFusionEnvironmentAdminUsersFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter(name="fusionEnvironmentId")
    def fusion_environment_id(self) -> _builtins.str:
        return pulumi.get(self, "fusion_environment_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetFusionEnvironmentAdminUsersResult(GetFusionEnvironmentAdminUsersResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetFusionEnvironmentAdminUsersResult(
            admin_user_collections=self.admin_user_collections,
            filters=self.filters,
            fusion_environment_id=self.fusion_environment_id,
            id=self.id)


def get_fusion_environment_admin_users(filters: Optional[Sequence[Union['GetFusionEnvironmentAdminUsersFilterArgs', 'GetFusionEnvironmentAdminUsersFilterArgsDict']]] = None,
                                       fusion_environment_id: Optional[_builtins.str] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetFusionEnvironmentAdminUsersResult:
    """
    This data source provides the list of Fusion Environment Admin Users in Oracle Cloud Infrastructure Fusion Apps service.

    List all FusionEnvironment admin users

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fusion_environment_admin_users = oci.Functions.get_fusion_environment_admin_users(fusion_environment_id=test_fusion_environment["id"])
    ```


    :param _builtins.str fusion_environment_id: unique FusionEnvironment identifier
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['fusionEnvironmentId'] = fusion_environment_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Functions/getFusionEnvironmentAdminUsers:getFusionEnvironmentAdminUsers', __args__, opts=opts, typ=GetFusionEnvironmentAdminUsersResult).value

    return AwaitableGetFusionEnvironmentAdminUsersResult(
        admin_user_collections=pulumi.get(__ret__, 'admin_user_collections'),
        filters=pulumi.get(__ret__, 'filters'),
        fusion_environment_id=pulumi.get(__ret__, 'fusion_environment_id'),
        id=pulumi.get(__ret__, 'id'))
def get_fusion_environment_admin_users_output(filters: Optional[pulumi.Input[Optional[Sequence[Union['GetFusionEnvironmentAdminUsersFilterArgs', 'GetFusionEnvironmentAdminUsersFilterArgsDict']]]]] = None,
                                              fusion_environment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                              opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetFusionEnvironmentAdminUsersResult]:
    """
    This data source provides the list of Fusion Environment Admin Users in Oracle Cloud Infrastructure Fusion Apps service.

    List all FusionEnvironment admin users

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fusion_environment_admin_users = oci.Functions.get_fusion_environment_admin_users(fusion_environment_id=test_fusion_environment["id"])
    ```


    :param _builtins.str fusion_environment_id: unique FusionEnvironment identifier
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['fusionEnvironmentId'] = fusion_environment_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Functions/getFusionEnvironmentAdminUsers:getFusionEnvironmentAdminUsers', __args__, opts=opts, typ=GetFusionEnvironmentAdminUsersResult)
    return __ret__.apply(lambda __response__: GetFusionEnvironmentAdminUsersResult(
        admin_user_collections=pulumi.get(__response__, 'admin_user_collections'),
        filters=pulumi.get(__response__, 'filters'),
        fusion_environment_id=pulumi.get(__response__, 'fusion_environment_id'),
        id=pulumi.get(__response__, 'id')))
