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
    'GetNatGatewayResult',
    'AwaitableGetNatGatewayResult',
    'get_nat_gateway',
    'get_nat_gateway_output',
]

@pulumi.output_type
class GetNatGatewayResult:
    """
    A collection of values returned by getNatGateway.
    """
    def __init__(__self__, block_traffic=None, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, nat_gateway_id=None, nat_ip=None, public_ip_id=None, route_table_id=None, state=None, time_created=None, vcn_id=None):
        if block_traffic and not isinstance(block_traffic, bool):
            raise TypeError("Expected argument 'block_traffic' to be a bool")
        pulumi.set(__self__, "block_traffic", block_traffic)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if nat_gateway_id and not isinstance(nat_gateway_id, str):
            raise TypeError("Expected argument 'nat_gateway_id' to be a str")
        pulumi.set(__self__, "nat_gateway_id", nat_gateway_id)
        if nat_ip and not isinstance(nat_ip, str):
            raise TypeError("Expected argument 'nat_ip' to be a str")
        pulumi.set(__self__, "nat_ip", nat_ip)
        if public_ip_id and not isinstance(public_ip_id, str):
            raise TypeError("Expected argument 'public_ip_id' to be a str")
        pulumi.set(__self__, "public_ip_id", public_ip_id)
        if route_table_id and not isinstance(route_table_id, str):
            raise TypeError("Expected argument 'route_table_id' to be a str")
        pulumi.set(__self__, "route_table_id", route_table_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if vcn_id and not isinstance(vcn_id, str):
            raise TypeError("Expected argument 'vcn_id' to be a str")
        pulumi.set(__self__, "vcn_id", vcn_id)

    @_builtins.property
    @pulumi.getter(name="blockTraffic")
    def block_traffic(self) -> _builtins.bool:
        """
        Whether the NAT gateway blocks traffic through it. The default is `false`.  Example: `true`
        """
        return pulumi.get(self, "block_traffic")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the NAT gateway.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the NAT gateway.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="natGatewayId")
    def nat_gateway_id(self) -> _builtins.str:
        return pulumi.get(self, "nat_gateway_id")

    @_builtins.property
    @pulumi.getter(name="natIp")
    def nat_ip(self) -> _builtins.str:
        """
        The IP address associated with the NAT gateway.
        """
        return pulumi.get(self, "nat_ip")

    @_builtins.property
    @pulumi.getter(name="publicIpId")
    def public_ip_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the public IP address associated with the NAT gateway.
        """
        return pulumi.get(self, "public_ip_id")

    @_builtins.property
    @pulumi.getter(name="routeTableId")
    def route_table_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table used by the NAT gateway.
        """
        return pulumi.get(self, "route_table_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The NAT gateway's current state.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the NAT gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="vcnId")
    def vcn_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the NAT gateway belongs to.
        """
        return pulumi.get(self, "vcn_id")


class AwaitableGetNatGatewayResult(GetNatGatewayResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNatGatewayResult(
            block_traffic=self.block_traffic,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            nat_gateway_id=self.nat_gateway_id,
            nat_ip=self.nat_ip,
            public_ip_id=self.public_ip_id,
            route_table_id=self.route_table_id,
            state=self.state,
            time_created=self.time_created,
            vcn_id=self.vcn_id)


def get_nat_gateway(nat_gateway_id: Optional[_builtins.str] = None,
                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNatGatewayResult:
    """
    This data source provides details about a specific Nat Gateway resource in Oracle Cloud Infrastructure Core service.

    Gets the specified NAT gateway's information.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_nat_gateway = oci.Core.get_nat_gateway(nat_gateway_id=test_nat_gateway_oci_core_nat_gateway["id"])
    ```


    :param _builtins.str nat_gateway_id: The NAT gateway's [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['natGatewayId'] = nat_gateway_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getNatGateway:getNatGateway', __args__, opts=opts, typ=GetNatGatewayResult).value

    return AwaitableGetNatGatewayResult(
        block_traffic=pulumi.get(__ret__, 'block_traffic'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        nat_gateway_id=pulumi.get(__ret__, 'nat_gateway_id'),
        nat_ip=pulumi.get(__ret__, 'nat_ip'),
        public_ip_id=pulumi.get(__ret__, 'public_ip_id'),
        route_table_id=pulumi.get(__ret__, 'route_table_id'),
        state=pulumi.get(__ret__, 'state'),
        time_created=pulumi.get(__ret__, 'time_created'),
        vcn_id=pulumi.get(__ret__, 'vcn_id'))
def get_nat_gateway_output(nat_gateway_id: Optional[pulumi.Input[_builtins.str]] = None,
                           opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetNatGatewayResult]:
    """
    This data source provides details about a specific Nat Gateway resource in Oracle Cloud Infrastructure Core service.

    Gets the specified NAT gateway's information.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_nat_gateway = oci.Core.get_nat_gateway(nat_gateway_id=test_nat_gateway_oci_core_nat_gateway["id"])
    ```


    :param _builtins.str nat_gateway_id: The NAT gateway's [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['natGatewayId'] = nat_gateway_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getNatGateway:getNatGateway', __args__, opts=opts, typ=GetNatGatewayResult)
    return __ret__.apply(lambda __response__: GetNatGatewayResult(
        block_traffic=pulumi.get(__response__, 'block_traffic'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        nat_gateway_id=pulumi.get(__response__, 'nat_gateway_id'),
        nat_ip=pulumi.get(__response__, 'nat_ip'),
        public_ip_id=pulumi.get(__response__, 'public_ip_id'),
        route_table_id=pulumi.get(__response__, 'route_table_id'),
        state=pulumi.get(__response__, 'state'),
        time_created=pulumi.get(__response__, 'time_created'),
        vcn_id=pulumi.get(__response__, 'vcn_id')))
