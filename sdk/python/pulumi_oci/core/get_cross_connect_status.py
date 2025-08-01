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
    'GetCrossConnectStatusResult',
    'AwaitableGetCrossConnectStatusResult',
    'get_cross_connect_status',
    'get_cross_connect_status_output',
]

@pulumi.output_type
class GetCrossConnectStatusResult:
    """
    A collection of values returned by getCrossConnectStatus.
    """
    def __init__(__self__, cross_connect_id=None, encryption_status=None, id=None, interface_state=None, light_level_ind_bm=None, light_level_indicator=None):
        if cross_connect_id and not isinstance(cross_connect_id, str):
            raise TypeError("Expected argument 'cross_connect_id' to be a str")
        pulumi.set(__self__, "cross_connect_id", cross_connect_id)
        if encryption_status and not isinstance(encryption_status, str):
            raise TypeError("Expected argument 'encryption_status' to be a str")
        pulumi.set(__self__, "encryption_status", encryption_status)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if interface_state and not isinstance(interface_state, str):
            raise TypeError("Expected argument 'interface_state' to be a str")
        pulumi.set(__self__, "interface_state", interface_state)
        if light_level_ind_bm and not isinstance(light_level_ind_bm, float):
            raise TypeError("Expected argument 'light_level_ind_bm' to be a float")
        pulumi.set(__self__, "light_level_ind_bm", light_level_ind_bm)
        if light_level_indicator and not isinstance(light_level_indicator, str):
            raise TypeError("Expected argument 'light_level_indicator' to be a str")
        pulumi.set(__self__, "light_level_indicator", light_level_indicator)

    @_builtins.property
    @pulumi.getter(name="crossConnectId")
    def cross_connect_id(self) -> _builtins.str:
        """
        The OCID of the cross-connect.
        """
        return pulumi.get(self, "cross_connect_id")

    @_builtins.property
    @pulumi.getter(name="encryptionStatus")
    def encryption_status(self) -> _builtins.str:
        """
        Encryption status of the CrossConnect
        """
        return pulumi.get(self, "encryption_status")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="interfaceState")
    def interface_state(self) -> _builtins.str:
        """
        Whether Oracle's side of the interface is up or down.
        """
        return pulumi.get(self, "interface_state")

    @_builtins.property
    @pulumi.getter(name="lightLevelIndBm")
    def light_level_ind_bm(self) -> _builtins.float:
        """
        The light level of the cross-connect (in dBm).  Example: `14.0`
        """
        return pulumi.get(self, "light_level_ind_bm")

    @_builtins.property
    @pulumi.getter(name="lightLevelIndicator")
    def light_level_indicator(self) -> _builtins.str:
        """
        Status indicator corresponding to the light level.
        * **NO_LIGHT:** No measurable light
        * **LOW_WARN:** There's measurable light but it's too low
        * **HIGH_WARN:** Light level is too high
        * **BAD:** There's measurable light but the signal-to-noise ratio is bad
        * **GOOD:** Good light level
        """
        return pulumi.get(self, "light_level_indicator")


class AwaitableGetCrossConnectStatusResult(GetCrossConnectStatusResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetCrossConnectStatusResult(
            cross_connect_id=self.cross_connect_id,
            encryption_status=self.encryption_status,
            id=self.id,
            interface_state=self.interface_state,
            light_level_ind_bm=self.light_level_ind_bm,
            light_level_indicator=self.light_level_indicator)


def get_cross_connect_status(cross_connect_id: Optional[_builtins.str] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetCrossConnectStatusResult:
    """
    This data source provides details about a specific Cross Connect Status resource in Oracle Cloud Infrastructure Core service.

    Gets the status of the specified cross-connect.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_cross_connect_status = oci.Core.get_cross_connect_status(cross_connect_id=test_cross_connect["id"])
    ```


    :param _builtins.str cross_connect_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cross-connect.
    """
    __args__ = dict()
    __args__['crossConnectId'] = cross_connect_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getCrossConnectStatus:getCrossConnectStatus', __args__, opts=opts, typ=GetCrossConnectStatusResult).value

    return AwaitableGetCrossConnectStatusResult(
        cross_connect_id=pulumi.get(__ret__, 'cross_connect_id'),
        encryption_status=pulumi.get(__ret__, 'encryption_status'),
        id=pulumi.get(__ret__, 'id'),
        interface_state=pulumi.get(__ret__, 'interface_state'),
        light_level_ind_bm=pulumi.get(__ret__, 'light_level_ind_bm'),
        light_level_indicator=pulumi.get(__ret__, 'light_level_indicator'))
def get_cross_connect_status_output(cross_connect_id: Optional[pulumi.Input[_builtins.str]] = None,
                                    opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetCrossConnectStatusResult]:
    """
    This data source provides details about a specific Cross Connect Status resource in Oracle Cloud Infrastructure Core service.

    Gets the status of the specified cross-connect.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_cross_connect_status = oci.Core.get_cross_connect_status(cross_connect_id=test_cross_connect["id"])
    ```


    :param _builtins.str cross_connect_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cross-connect.
    """
    __args__ = dict()
    __args__['crossConnectId'] = cross_connect_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getCrossConnectStatus:getCrossConnectStatus', __args__, opts=opts, typ=GetCrossConnectStatusResult)
    return __ret__.apply(lambda __response__: GetCrossConnectStatusResult(
        cross_connect_id=pulumi.get(__response__, 'cross_connect_id'),
        encryption_status=pulumi.get(__response__, 'encryption_status'),
        id=pulumi.get(__response__, 'id'),
        interface_state=pulumi.get(__response__, 'interface_state'),
        light_level_ind_bm=pulumi.get(__response__, 'light_level_ind_bm'),
        light_level_indicator=pulumi.get(__response__, 'light_level_indicator')))
