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

__all__ = [
    'GetManagedDatabaseUserProxiedForUserResult',
    'AwaitableGetManagedDatabaseUserProxiedForUserResult',
    'get_managed_database_user_proxied_for_user',
    'get_managed_database_user_proxied_for_user_output',
]

@pulumi.output_type
class GetManagedDatabaseUserProxiedForUserResult:
    """
    A collection of values returned by getManagedDatabaseUserProxiedForUser.
    """
    def __init__(__self__, id=None, items=None, managed_database_id=None, name=None, user_name=None):
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if items and not isinstance(items, list):
            raise TypeError("Expected argument 'items' to be a list")
        pulumi.set(__self__, "items", items)
        if managed_database_id and not isinstance(managed_database_id, str):
            raise TypeError("Expected argument 'managed_database_id' to be a str")
        pulumi.set(__self__, "managed_database_id", managed_database_id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if user_name and not isinstance(user_name, str):
            raise TypeError("Expected argument 'user_name' to be a str")
        pulumi.set(__self__, "user_name", user_name)

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetManagedDatabaseUserProxiedForUserItemResult']:
        """
        An array of user resources.
        """
        return pulumi.get(self, "items")

    @property
    @pulumi.getter(name="managedDatabaseId")
    def managed_database_id(self) -> str:
        return pulumi.get(self, "managed_database_id")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        The name of a proxy user or the name of the client user.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="userName")
    def user_name(self) -> str:
        return pulumi.get(self, "user_name")


class AwaitableGetManagedDatabaseUserProxiedForUserResult(GetManagedDatabaseUserProxiedForUserResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagedDatabaseUserProxiedForUserResult(
            id=self.id,
            items=self.items,
            managed_database_id=self.managed_database_id,
            name=self.name,
            user_name=self.user_name)


def get_managed_database_user_proxied_for_user(managed_database_id: Optional[str] = None,
                                               name: Optional[str] = None,
                                               user_name: Optional[str] = None,
                                               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagedDatabaseUserProxiedForUserResult:
    """
    This data source provides details about a specific Managed Database User Proxied For User resource in Oracle Cloud Infrastructure Database Management service.

    Gets the list of users on whose behalf the current user acts as proxy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database_user_proxied_for_user = oci.DatabaseManagement.get_managed_database_user_proxied_for_user(managed_database_id=oci_database_management_managed_database["test_managed_database"]["id"],
        user_name=oci_identity_user["test_user"]["name"],
        name=var["managed_database_user_proxied_for_user_name"])
    ```


    :param str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    :param str name: A filter to return only resources that match the entire name.
    :param str user_name: The name of the user whose details are to be viewed.
    """
    __args__ = dict()
    __args__['managedDatabaseId'] = managed_database_id
    __args__['name'] = name
    __args__['userName'] = user_name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DatabaseManagement/getManagedDatabaseUserProxiedForUser:getManagedDatabaseUserProxiedForUser', __args__, opts=opts, typ=GetManagedDatabaseUserProxiedForUserResult).value

    return AwaitableGetManagedDatabaseUserProxiedForUserResult(
        id=__ret__.id,
        items=__ret__.items,
        managed_database_id=__ret__.managed_database_id,
        name=__ret__.name,
        user_name=__ret__.user_name)


@_utilities.lift_output_func(get_managed_database_user_proxied_for_user)
def get_managed_database_user_proxied_for_user_output(managed_database_id: Optional[pulumi.Input[str]] = None,
                                                      name: Optional[pulumi.Input[Optional[str]]] = None,
                                                      user_name: Optional[pulumi.Input[str]] = None,
                                                      opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetManagedDatabaseUserProxiedForUserResult]:
    """
    This data source provides details about a specific Managed Database User Proxied For User resource in Oracle Cloud Infrastructure Database Management service.

    Gets the list of users on whose behalf the current user acts as proxy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database_user_proxied_for_user = oci.DatabaseManagement.get_managed_database_user_proxied_for_user(managed_database_id=oci_database_management_managed_database["test_managed_database"]["id"],
        user_name=oci_identity_user["test_user"]["name"],
        name=var["managed_database_user_proxied_for_user_name"])
    ```


    :param str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    :param str name: A filter to return only resources that match the entire name.
    :param str user_name: The name of the user whose details are to be viewed.
    """
    ...