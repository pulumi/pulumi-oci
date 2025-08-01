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
    'GetVnicResult',
    'AwaitableGetVnicResult',
    'get_vnic',
    'get_vnic_output',
]

@pulumi.output_type
class GetVnicResult:
    """
    A collection of values returned by getVnic.
    """
    def __init__(__self__, availability_domain=None, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, hostname_label=None, id=None, ipv6addresses=None, is_primary=None, mac_address=None, nsg_ids=None, private_ip_address=None, public_ip_address=None, route_table_id=None, security_attributes=None, skip_source_dest_check=None, state=None, subnet_id=None, time_created=None, vlan_id=None, vnic_id=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
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
        if hostname_label and not isinstance(hostname_label, str):
            raise TypeError("Expected argument 'hostname_label' to be a str")
        pulumi.set(__self__, "hostname_label", hostname_label)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if ipv6addresses and not isinstance(ipv6addresses, list):
            raise TypeError("Expected argument 'ipv6addresses' to be a list")
        pulumi.set(__self__, "ipv6addresses", ipv6addresses)
        if is_primary and not isinstance(is_primary, bool):
            raise TypeError("Expected argument 'is_primary' to be a bool")
        pulumi.set(__self__, "is_primary", is_primary)
        if mac_address and not isinstance(mac_address, str):
            raise TypeError("Expected argument 'mac_address' to be a str")
        pulumi.set(__self__, "mac_address", mac_address)
        if nsg_ids and not isinstance(nsg_ids, list):
            raise TypeError("Expected argument 'nsg_ids' to be a list")
        pulumi.set(__self__, "nsg_ids", nsg_ids)
        if private_ip_address and not isinstance(private_ip_address, str):
            raise TypeError("Expected argument 'private_ip_address' to be a str")
        pulumi.set(__self__, "private_ip_address", private_ip_address)
        if public_ip_address and not isinstance(public_ip_address, str):
            raise TypeError("Expected argument 'public_ip_address' to be a str")
        pulumi.set(__self__, "public_ip_address", public_ip_address)
        if route_table_id and not isinstance(route_table_id, str):
            raise TypeError("Expected argument 'route_table_id' to be a str")
        pulumi.set(__self__, "route_table_id", route_table_id)
        if security_attributes and not isinstance(security_attributes, dict):
            raise TypeError("Expected argument 'security_attributes' to be a dict")
        pulumi.set(__self__, "security_attributes", security_attributes)
        if skip_source_dest_check and not isinstance(skip_source_dest_check, bool):
            raise TypeError("Expected argument 'skip_source_dest_check' to be a bool")
        pulumi.set(__self__, "skip_source_dest_check", skip_source_dest_check)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if subnet_id and not isinstance(subnet_id, str):
            raise TypeError("Expected argument 'subnet_id' to be a str")
        pulumi.set(__self__, "subnet_id", subnet_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if vlan_id and not isinstance(vlan_id, str):
            raise TypeError("Expected argument 'vlan_id' to be a str")
        pulumi.set(__self__, "vlan_id", vlan_id)
        if vnic_id and not isinstance(vnic_id, str):
            raise TypeError("Expected argument 'vnic_id' to be a str")
        pulumi.set(__self__, "vnic_id", vnic_id)

    @_builtins.property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> _builtins.str:
        """
        The VNIC's availability domain.  Example: `Uocm:PHX-AD-1`
        """
        return pulumi.get(self, "availability_domain")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the VNIC.
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
    @pulumi.getter(name="hostnameLabel")
    def hostname_label(self) -> _builtins.str:
        """
        The hostname for the VNIC's primary private IP. Used for DNS. The value is the hostname portion of the primary private IP's fully qualified domain name (FQDN) (for example, `bminstance1` in FQDN `bminstance1.subnet123.vcn1.oraclevcn.com`). Must be unique across all VNICs in the subnet and comply with [RFC 952](https://tools.ietf.org/html/rfc952) and [RFC 1123](https://tools.ietf.org/html/rfc1123).
        """
        return pulumi.get(self, "hostname_label")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def ipv6addresses(self) -> Sequence[_builtins.str]:
        """
        List of IPv6 addresses assigned to the VNIC.  Example: `2001:DB8::`
        """
        return pulumi.get(self, "ipv6addresses")

    @_builtins.property
    @pulumi.getter(name="isPrimary")
    def is_primary(self) -> _builtins.bool:
        """
        Whether the VNIC is the primary VNIC (the VNIC that is automatically created and attached during instance launch).
        """
        return pulumi.get(self, "is_primary")

    @_builtins.property
    @pulumi.getter(name="macAddress")
    def mac_address(self) -> _builtins.str:
        """
        The MAC address of the VNIC.
        """
        return pulumi.get(self, "mac_address")

    @_builtins.property
    @pulumi.getter(name="nsgIds")
    def nsg_ids(self) -> Sequence[_builtins.str]:
        """
        A list of the OCIDs of the network security groups that the VNIC belongs to.
        """
        return pulumi.get(self, "nsg_ids")

    @_builtins.property
    @pulumi.getter(name="privateIpAddress")
    def private_ip_address(self) -> _builtins.str:
        """
        The private IP address of the primary `privateIp` object on the VNIC. The address is within the CIDR of the VNIC's subnet.  Example: `10.0.3.3`
        """
        return pulumi.get(self, "private_ip_address")

    @_builtins.property
    @pulumi.getter(name="publicIpAddress")
    def public_ip_address(self) -> _builtins.str:
        """
        The public IP address of the VNIC, if one is assigned.
        """
        return pulumi.get(self, "public_ip_address")

    @_builtins.property
    @pulumi.getter(name="routeTableId")
    def route_table_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the IP address or VNIC will use. For more information, see [Source Based Routing](https://docs.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm#Overview_of_Routing_for_Your_VCN__source_routing).
        """
        return pulumi.get(self, "route_table_id")

    @_builtins.property
    @pulumi.getter(name="securityAttributes")
    def security_attributes(self) -> Mapping[str, _builtins.str]:
        """
        [Security attributes](https://docs.cloud.oracle.com/iaas/Content/zero-trust-packet-routing/zpr-artifacts.htm#security-attributes) are labels for a resource that can be referenced in a [Zero Trust Packet Routing](https://docs.cloud.oracle.com/iaas/Content/zero-trust-packet-routing/overview.htm) (ZPR) policy to control access to ZPR-supported resources.  Example: `{"Oracle-DataSecurity-ZPR": {"MaxEgressCount": {"value":"42","mode":"audit"}}}`
        """
        return pulumi.get(self, "security_attributes")

    @_builtins.property
    @pulumi.getter(name="skipSourceDestCheck")
    def skip_source_dest_check(self) -> _builtins.bool:
        """
        Whether the source/destination check is disabled on the VNIC. Defaults to `false`, which means the check is performed. For information about why you would skip the source/destination check, see [Using a Private IP as a Route Target](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm#privateip).
        """
        return pulumi.get(self, "skip_source_dest_check")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the VNIC.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the VNIC is in.
        """
        return pulumi.get(self, "subnet_id")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the VNIC was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="vlanId")
    def vlan_id(self) -> _builtins.str:
        """
        If the VNIC belongs to a VLAN as part of the Oracle Cloud VMware Solution (instead of belonging to a subnet), the `vlanId` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN the VNIC is in. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan). If the VNIC is instead in a subnet, `subnetId` has a value.
        """
        return pulumi.get(self, "vlan_id")

    @_builtins.property
    @pulumi.getter(name="vnicId")
    def vnic_id(self) -> _builtins.str:
        return pulumi.get(self, "vnic_id")


class AwaitableGetVnicResult(GetVnicResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetVnicResult(
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            hostname_label=self.hostname_label,
            id=self.id,
            ipv6addresses=self.ipv6addresses,
            is_primary=self.is_primary,
            mac_address=self.mac_address,
            nsg_ids=self.nsg_ids,
            private_ip_address=self.private_ip_address,
            public_ip_address=self.public_ip_address,
            route_table_id=self.route_table_id,
            security_attributes=self.security_attributes,
            skip_source_dest_check=self.skip_source_dest_check,
            state=self.state,
            subnet_id=self.subnet_id,
            time_created=self.time_created,
            vlan_id=self.vlan_id,
            vnic_id=self.vnic_id)


def get_vnic(vnic_id: Optional[_builtins.str] = None,
             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetVnicResult:
    """
    This data source provides details about a specific Vnic resource in Oracle Cloud Infrastructure Core service.

    Gets the information for the specified virtual network interface card (VNIC).
    You can get the VNIC [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) from the
    [ListVnicAttachments](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/VnicAttachment/ListVnicAttachments)
    operation.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_vnic = oci.Core.get_vnic(vnic_id=test_vnic_oci_core_vnic["id"])
    ```


    :param _builtins.str vnic_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC.
    """
    __args__ = dict()
    __args__['vnicId'] = vnic_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getVnic:getVnic', __args__, opts=opts, typ=GetVnicResult).value

    return AwaitableGetVnicResult(
        availability_domain=pulumi.get(__ret__, 'availability_domain'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        hostname_label=pulumi.get(__ret__, 'hostname_label'),
        id=pulumi.get(__ret__, 'id'),
        ipv6addresses=pulumi.get(__ret__, 'ipv6addresses'),
        is_primary=pulumi.get(__ret__, 'is_primary'),
        mac_address=pulumi.get(__ret__, 'mac_address'),
        nsg_ids=pulumi.get(__ret__, 'nsg_ids'),
        private_ip_address=pulumi.get(__ret__, 'private_ip_address'),
        public_ip_address=pulumi.get(__ret__, 'public_ip_address'),
        route_table_id=pulumi.get(__ret__, 'route_table_id'),
        security_attributes=pulumi.get(__ret__, 'security_attributes'),
        skip_source_dest_check=pulumi.get(__ret__, 'skip_source_dest_check'),
        state=pulumi.get(__ret__, 'state'),
        subnet_id=pulumi.get(__ret__, 'subnet_id'),
        time_created=pulumi.get(__ret__, 'time_created'),
        vlan_id=pulumi.get(__ret__, 'vlan_id'),
        vnic_id=pulumi.get(__ret__, 'vnic_id'))
def get_vnic_output(vnic_id: Optional[pulumi.Input[_builtins.str]] = None,
                    opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetVnicResult]:
    """
    This data source provides details about a specific Vnic resource in Oracle Cloud Infrastructure Core service.

    Gets the information for the specified virtual network interface card (VNIC).
    You can get the VNIC [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) from the
    [ListVnicAttachments](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/VnicAttachment/ListVnicAttachments)
    operation.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_vnic = oci.Core.get_vnic(vnic_id=test_vnic_oci_core_vnic["id"])
    ```


    :param _builtins.str vnic_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC.
    """
    __args__ = dict()
    __args__['vnicId'] = vnic_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getVnic:getVnic', __args__, opts=opts, typ=GetVnicResult)
    return __ret__.apply(lambda __response__: GetVnicResult(
        availability_domain=pulumi.get(__response__, 'availability_domain'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        hostname_label=pulumi.get(__response__, 'hostname_label'),
        id=pulumi.get(__response__, 'id'),
        ipv6addresses=pulumi.get(__response__, 'ipv6addresses'),
        is_primary=pulumi.get(__response__, 'is_primary'),
        mac_address=pulumi.get(__response__, 'mac_address'),
        nsg_ids=pulumi.get(__response__, 'nsg_ids'),
        private_ip_address=pulumi.get(__response__, 'private_ip_address'),
        public_ip_address=pulumi.get(__response__, 'public_ip_address'),
        route_table_id=pulumi.get(__response__, 'route_table_id'),
        security_attributes=pulumi.get(__response__, 'security_attributes'),
        skip_source_dest_check=pulumi.get(__response__, 'skip_source_dest_check'),
        state=pulumi.get(__response__, 'state'),
        subnet_id=pulumi.get(__response__, 'subnet_id'),
        time_created=pulumi.get(__response__, 'time_created'),
        vlan_id=pulumi.get(__response__, 'vlan_id'),
        vnic_id=pulumi.get(__response__, 'vnic_id')))
