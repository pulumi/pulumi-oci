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
    'GetIpv6sResult',
    'AwaitableGetIpv6sResult',
    'get_ipv6s',
    'get_ipv6s_output',
]

@pulumi.output_type
class GetIpv6sResult:
    """
    A collection of values returned by getIpv6s.
    """
    def __init__(__self__, filters=None, id=None, ip_address=None, ipv6s=None, subnet_id=None, vnic_id=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if ip_address and not isinstance(ip_address, str):
            raise TypeError("Expected argument 'ip_address' to be a str")
        pulumi.set(__self__, "ip_address", ip_address)
        if ipv6s and not isinstance(ipv6s, list):
            raise TypeError("Expected argument 'ipv6s' to be a list")
        pulumi.set(__self__, "ipv6s", ipv6s)
        if subnet_id and not isinstance(subnet_id, str):
            raise TypeError("Expected argument 'subnet_id' to be a str")
        pulumi.set(__self__, "subnet_id", subnet_id)
        if vnic_id and not isinstance(vnic_id, str):
            raise TypeError("Expected argument 'vnic_id' to be a str")
        pulumi.set(__self__, "vnic_id", vnic_id)

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetIpv6sFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="ipAddress")
    def ip_address(self) -> Optional[_builtins.str]:
        """
        The IPv6 address of the `IPv6` object. The address is within the IPv6 CIDR block of the VNIC's subnet (see the `ipv6CidrBlock` attribute for the [Subnet](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Subnet/) object.  Example: `2001:0db8:0123:1111:abcd:ef01:2345:6789`
        """
        return pulumi.get(self, "ip_address")

    @_builtins.property
    @pulumi.getter
    def ipv6s(self) -> Sequence['outputs.GetIpv6sIpv6Result']:
        """
        The list of ipv6s.
        """
        return pulumi.get(self, "ipv6s")

    @_builtins.property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the VNIC is in.
        """
        return pulumi.get(self, "subnet_id")

    @_builtins.property
    @pulumi.getter(name="vnicId")
    def vnic_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC the IPv6 is assigned to. The VNIC and IPv6 must be in the same subnet.
        """
        return pulumi.get(self, "vnic_id")


class AwaitableGetIpv6sResult(GetIpv6sResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetIpv6sResult(
            filters=self.filters,
            id=self.id,
            ip_address=self.ip_address,
            ipv6s=self.ipv6s,
            subnet_id=self.subnet_id,
            vnic_id=self.vnic_id)


def get_ipv6s(filters: Optional[Sequence[Union['GetIpv6sFilterArgs', 'GetIpv6sFilterArgsDict']]] = None,
              ip_address: Optional[_builtins.str] = None,
              subnet_id: Optional[_builtins.str] = None,
              vnic_id: Optional[_builtins.str] = None,
              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetIpv6sResult:
    """
    This data source provides the list of Ipv6s in Oracle Cloud Infrastructure Core service.

    Lists the [IPv6](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Ipv6/) objects based
    on one of these filters:

      * Subnet OCID.
      * VNIC OCID.
      * Both IPv6 address and subnet OCID: This lets you get an `Ipv6` object based on its private
          IPv6 address (for example, 2001:0db8:0123:1111:abcd:ef01:2345:6789) and not its OCID. For comparison,
          [GetIpv6](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Ipv6/GetIpv6) requires the OCID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_ipv6s = oci.Core.get_ipv6s(ip_address=ipv6_ip_address,
        subnet_id=test_subnet["id"],
        vnic_id=test_vnic_attachment["id"])
    ```


    :param _builtins.str ip_address: An IP address. This could be either IPv4 or IPv6, depending on the resource. Example: `10.0.3.3`
    :param _builtins.str subnet_id: The OCID of the subnet.
    :param _builtins.str vnic_id: The OCID of the VNIC.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['ipAddress'] = ip_address
    __args__['subnetId'] = subnet_id
    __args__['vnicId'] = vnic_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getIpv6s:getIpv6s', __args__, opts=opts, typ=GetIpv6sResult).value

    return AwaitableGetIpv6sResult(
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        ip_address=pulumi.get(__ret__, 'ip_address'),
        ipv6s=pulumi.get(__ret__, 'ipv6s'),
        subnet_id=pulumi.get(__ret__, 'subnet_id'),
        vnic_id=pulumi.get(__ret__, 'vnic_id'))
def get_ipv6s_output(filters: Optional[pulumi.Input[Optional[Sequence[Union['GetIpv6sFilterArgs', 'GetIpv6sFilterArgsDict']]]]] = None,
                     ip_address: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                     subnet_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                     vnic_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                     opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetIpv6sResult]:
    """
    This data source provides the list of Ipv6s in Oracle Cloud Infrastructure Core service.

    Lists the [IPv6](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Ipv6/) objects based
    on one of these filters:

      * Subnet OCID.
      * VNIC OCID.
      * Both IPv6 address and subnet OCID: This lets you get an `Ipv6` object based on its private
          IPv6 address (for example, 2001:0db8:0123:1111:abcd:ef01:2345:6789) and not its OCID. For comparison,
          [GetIpv6](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Ipv6/GetIpv6) requires the OCID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_ipv6s = oci.Core.get_ipv6s(ip_address=ipv6_ip_address,
        subnet_id=test_subnet["id"],
        vnic_id=test_vnic_attachment["id"])
    ```


    :param _builtins.str ip_address: An IP address. This could be either IPv4 or IPv6, depending on the resource. Example: `10.0.3.3`
    :param _builtins.str subnet_id: The OCID of the subnet.
    :param _builtins.str vnic_id: The OCID of the VNIC.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['ipAddress'] = ip_address
    __args__['subnetId'] = subnet_id
    __args__['vnicId'] = vnic_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getIpv6s:getIpv6s', __args__, opts=opts, typ=GetIpv6sResult)
    return __ret__.apply(lambda __response__: GetIpv6sResult(
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        ip_address=pulumi.get(__response__, 'ip_address'),
        ipv6s=pulumi.get(__response__, 'ipv6s'),
        subnet_id=pulumi.get(__response__, 'subnet_id'),
        vnic_id=pulumi.get(__response__, 'vnic_id')))
