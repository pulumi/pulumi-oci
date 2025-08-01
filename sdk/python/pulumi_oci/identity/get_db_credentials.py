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
    'GetDbCredentialsResult',
    'AwaitableGetDbCredentialsResult',
    'get_db_credentials',
    'get_db_credentials_output',
]

@pulumi.output_type
class GetDbCredentialsResult:
    """
    A collection of values returned by getDbCredentials.
    """
    def __init__(__self__, db_credentials=None, filters=None, id=None, name=None, state=None, user_id=None):
        if db_credentials and not isinstance(db_credentials, list):
            raise TypeError("Expected argument 'db_credentials' to be a list")
        pulumi.set(__self__, "db_credentials", db_credentials)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if user_id and not isinstance(user_id, str):
            raise TypeError("Expected argument 'user_id' to be a str")
        pulumi.set(__self__, "user_id", user_id)

    @_builtins.property
    @pulumi.getter(name="dbCredentials")
    def db_credentials(self) -> Sequence['outputs.GetDbCredentialsDbCredentialResult']:
        """
        The list of db_credentials.
        """
        return pulumi.get(self, "db_credentials")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDbCredentialsFilterResult']]:
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
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The credential's current state. After creating a DB credential, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="userId")
    def user_id(self) -> _builtins.str:
        """
        The OCID of the user the DB credential belongs to.
        """
        return pulumi.get(self, "user_id")


class AwaitableGetDbCredentialsResult(GetDbCredentialsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDbCredentialsResult(
            db_credentials=self.db_credentials,
            filters=self.filters,
            id=self.id,
            name=self.name,
            state=self.state,
            user_id=self.user_id)


def get_db_credentials(filters: Optional[Sequence[Union['GetDbCredentialsFilterArgs', 'GetDbCredentialsFilterArgsDict']]] = None,
                       name: Optional[_builtins.str] = None,
                       state: Optional[_builtins.str] = None,
                       user_id: Optional[_builtins.str] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDbCredentialsResult:
    """
    This data source provides the list of Db Credentials in Oracle Cloud Infrastructure Identity service.

    Lists the DB credentials for the specified user. The returned object contains the credential's OCID

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_db_credentials = oci.Identity.get_db_credentials(user_id=test_user["id"],
        name=db_credential_name,
        state=db_credential_state)
    ```


    :param _builtins.str name: A filter to only return resources that match the given name exactly.
    :param _builtins.str state: A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
    :param _builtins.str user_id: The OCID of the user.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['state'] = state
    __args__['userId'] = user_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Identity/getDbCredentials:getDbCredentials', __args__, opts=opts, typ=GetDbCredentialsResult).value

    return AwaitableGetDbCredentialsResult(
        db_credentials=pulumi.get(__ret__, 'db_credentials'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        name=pulumi.get(__ret__, 'name'),
        state=pulumi.get(__ret__, 'state'),
        user_id=pulumi.get(__ret__, 'user_id'))
def get_db_credentials_output(filters: Optional[pulumi.Input[Optional[Sequence[Union['GetDbCredentialsFilterArgs', 'GetDbCredentialsFilterArgsDict']]]]] = None,
                              name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                              state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                              user_id: Optional[pulumi.Input[_builtins.str]] = None,
                              opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDbCredentialsResult]:
    """
    This data source provides the list of Db Credentials in Oracle Cloud Infrastructure Identity service.

    Lists the DB credentials for the specified user. The returned object contains the credential's OCID

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_db_credentials = oci.Identity.get_db_credentials(user_id=test_user["id"],
        name=db_credential_name,
        state=db_credential_state)
    ```


    :param _builtins.str name: A filter to only return resources that match the given name exactly.
    :param _builtins.str state: A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
    :param _builtins.str user_id: The OCID of the user.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['state'] = state
    __args__['userId'] = user_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Identity/getDbCredentials:getDbCredentials', __args__, opts=opts, typ=GetDbCredentialsResult)
    return __ret__.apply(lambda __response__: GetDbCredentialsResult(
        db_credentials=pulumi.get(__response__, 'db_credentials'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        name=pulumi.get(__response__, 'name'),
        state=pulumi.get(__response__, 'state'),
        user_id=pulumi.get(__response__, 'user_id')))
