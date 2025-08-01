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

__all__ = [
    'GetUiPasswordResult',
    'AwaitableGetUiPasswordResult',
    'get_ui_password',
    'get_ui_password_output',
]

@pulumi.output_type
class GetUiPasswordResult:
    """
    A collection of values returned by getUiPassword.
    """
    def __init__(__self__, id=None, inactive_status=None, password=None, state=None, time_created=None, user_id=None):
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if inactive_status and not isinstance(inactive_status, str):
            raise TypeError("Expected argument 'inactive_status' to be a str")
        pulumi.set(__self__, "inactive_status", inactive_status)
        if password and not isinstance(password, str):
            raise TypeError("Expected argument 'password' to be a str")
        pulumi.set(__self__, "password", password)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if user_id and not isinstance(user_id, str):
            raise TypeError("Expected argument 'user_id' to be a str")
        pulumi.set(__self__, "user_id", user_id)

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="inactiveStatus")
    def inactive_status(self) -> _builtins.str:
        return pulumi.get(self, "inactive_status")

    @_builtins.property
    @pulumi.getter
    def password(self) -> _builtins.str:
        return pulumi.get(self, "password")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The password's current state.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        Date and time the password was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="userId")
    def user_id(self) -> _builtins.str:
        """
        The OCID of the user.
        """
        return pulumi.get(self, "user_id")


class AwaitableGetUiPasswordResult(GetUiPasswordResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetUiPasswordResult(
            id=self.id,
            inactive_status=self.inactive_status,
            password=self.password,
            state=self.state,
            time_created=self.time_created,
            user_id=self.user_id)


def get_ui_password(user_id: Optional[_builtins.str] = None,
                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetUiPasswordResult:
    """
    This data source provides details about a specific Ui Password resource in Oracle Cloud Infrastructure Identity service.

    Gets the specified user's console password information. The returned object contains the user's OCID,
    but not the password itself. The actual password is returned only when created or reset.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_ui_password = oci.Identity.get_ui_password(user_id=test_user["id"])
    ```


    :param _builtins.str user_id: The OCID of the user.
    """
    __args__ = dict()
    __args__['userId'] = user_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Identity/getUiPassword:getUiPassword', __args__, opts=opts, typ=GetUiPasswordResult).value

    return AwaitableGetUiPasswordResult(
        id=pulumi.get(__ret__, 'id'),
        inactive_status=pulumi.get(__ret__, 'inactive_status'),
        password=pulumi.get(__ret__, 'password'),
        state=pulumi.get(__ret__, 'state'),
        time_created=pulumi.get(__ret__, 'time_created'),
        user_id=pulumi.get(__ret__, 'user_id'))
def get_ui_password_output(user_id: Optional[pulumi.Input[_builtins.str]] = None,
                           opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetUiPasswordResult]:
    """
    This data source provides details about a specific Ui Password resource in Oracle Cloud Infrastructure Identity service.

    Gets the specified user's console password information. The returned object contains the user's OCID,
    but not the password itself. The actual password is returned only when created or reset.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_ui_password = oci.Identity.get_ui_password(user_id=test_user["id"])
    ```


    :param _builtins.str user_id: The OCID of the user.
    """
    __args__ = dict()
    __args__['userId'] = user_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Identity/getUiPassword:getUiPassword', __args__, opts=opts, typ=GetUiPasswordResult)
    return __ret__.apply(lambda __response__: GetUiPasswordResult(
        id=pulumi.get(__response__, 'id'),
        inactive_status=pulumi.get(__response__, 'inactive_status'),
        password=pulumi.get(__response__, 'password'),
        state=pulumi.get(__response__, 'state'),
        time_created=pulumi.get(__response__, 'time_created'),
        user_id=pulumi.get(__response__, 'user_id')))
