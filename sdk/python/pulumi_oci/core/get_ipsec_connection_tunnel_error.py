# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetIpsecConnectionTunnelErrorResult',
    'AwaitableGetIpsecConnectionTunnelErrorResult',
    'get_ipsec_connection_tunnel_error',
    'get_ipsec_connection_tunnel_error_output',
]

@pulumi.output_type
class GetIpsecConnectionTunnelErrorResult:
    """
    A collection of values returned by getIpsecConnectionTunnelError.
    """
    def __init__(__self__, error_code=None, error_description=None, id=None, ipsec_id=None, oci_resources_link=None, solution=None, timestamp=None, tunnel_id=None):
        if error_code and not isinstance(error_code, str):
            raise TypeError("Expected argument 'error_code' to be a str")
        pulumi.set(__self__, "error_code", error_code)
        if error_description and not isinstance(error_description, str):
            raise TypeError("Expected argument 'error_description' to be a str")
        pulumi.set(__self__, "error_description", error_description)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if ipsec_id and not isinstance(ipsec_id, str):
            raise TypeError("Expected argument 'ipsec_id' to be a str")
        pulumi.set(__self__, "ipsec_id", ipsec_id)
        if oci_resources_link and not isinstance(oci_resources_link, str):
            raise TypeError("Expected argument 'oci_resources_link' to be a str")
        pulumi.set(__self__, "oci_resources_link", oci_resources_link)
        if solution and not isinstance(solution, str):
            raise TypeError("Expected argument 'solution' to be a str")
        pulumi.set(__self__, "solution", solution)
        if timestamp and not isinstance(timestamp, str):
            raise TypeError("Expected argument 'timestamp' to be a str")
        pulumi.set(__self__, "timestamp", timestamp)
        if tunnel_id and not isinstance(tunnel_id, str):
            raise TypeError("Expected argument 'tunnel_id' to be a str")
        pulumi.set(__self__, "tunnel_id", tunnel_id)

    @property
    @pulumi.getter(name="errorCode")
    def error_code(self) -> str:
        """
        Unique code describes the error type.
        """
        return pulumi.get(self, "error_code")

    @property
    @pulumi.getter(name="errorDescription")
    def error_description(self) -> str:
        """
        A detailed description of the error.
        """
        return pulumi.get(self, "error_description")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="ipsecId")
    def ipsec_id(self) -> str:
        return pulumi.get(self, "ipsec_id")

    @property
    @pulumi.getter(name="ociResourcesLink")
    def oci_resources_link(self) -> str:
        """
        Link to more Oracle resources or relevant documentation.
        """
        return pulumi.get(self, "oci_resources_link")

    @property
    @pulumi.getter
    def solution(self) -> str:
        """
        Resolution for the error.
        """
        return pulumi.get(self, "solution")

    @property
    @pulumi.getter
    def timestamp(self) -> str:
        """
        Timestamp when the error occurred.
        """
        return pulumi.get(self, "timestamp")

    @property
    @pulumi.getter(name="tunnelId")
    def tunnel_id(self) -> str:
        return pulumi.get(self, "tunnel_id")


class AwaitableGetIpsecConnectionTunnelErrorResult(GetIpsecConnectionTunnelErrorResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetIpsecConnectionTunnelErrorResult(
            error_code=self.error_code,
            error_description=self.error_description,
            id=self.id,
            ipsec_id=self.ipsec_id,
            oci_resources_link=self.oci_resources_link,
            solution=self.solution,
            timestamp=self.timestamp,
            tunnel_id=self.tunnel_id)


def get_ipsec_connection_tunnel_error(ipsec_id: Optional[str] = None,
                                      tunnel_id: Optional[str] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetIpsecConnectionTunnelErrorResult:
    """
    This data source provides details about a specific Ipsec Connection Tunnel Error resource in Oracle Cloud Infrastructure Core service.

    Gets the identified error for the specified IPSec tunnel ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_ipsec_connection_tunnel_error = oci.Core.get_ipsec_connection_tunnel_error(ipsec_id=oci_core_ipsec["test_ipsec"]["id"],
        tunnel_id=oci_core_tunnel["test_tunnel"]["id"])
    ```


    :param str ipsec_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the IPSec connection.
    :param str tunnel_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tunnel.
    """
    __args__ = dict()
    __args__['ipsecId'] = ipsec_id
    __args__['tunnelId'] = tunnel_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getIpsecConnectionTunnelError:getIpsecConnectionTunnelError', __args__, opts=opts, typ=GetIpsecConnectionTunnelErrorResult).value

    return AwaitableGetIpsecConnectionTunnelErrorResult(
        error_code=__ret__.error_code,
        error_description=__ret__.error_description,
        id=__ret__.id,
        ipsec_id=__ret__.ipsec_id,
        oci_resources_link=__ret__.oci_resources_link,
        solution=__ret__.solution,
        timestamp=__ret__.timestamp,
        tunnel_id=__ret__.tunnel_id)


@_utilities.lift_output_func(get_ipsec_connection_tunnel_error)
def get_ipsec_connection_tunnel_error_output(ipsec_id: Optional[pulumi.Input[str]] = None,
                                             tunnel_id: Optional[pulumi.Input[str]] = None,
                                             opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetIpsecConnectionTunnelErrorResult]:
    """
    This data source provides details about a specific Ipsec Connection Tunnel Error resource in Oracle Cloud Infrastructure Core service.

    Gets the identified error for the specified IPSec tunnel ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_ipsec_connection_tunnel_error = oci.Core.get_ipsec_connection_tunnel_error(ipsec_id=oci_core_ipsec["test_ipsec"]["id"],
        tunnel_id=oci_core_tunnel["test_tunnel"]["id"])
    ```


    :param str ipsec_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the IPSec connection.
    :param str tunnel_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tunnel.
    """
    ...