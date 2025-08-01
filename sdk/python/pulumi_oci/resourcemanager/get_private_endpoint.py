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
    'GetPrivateEndpointResult',
    'AwaitableGetPrivateEndpointResult',
    'get_private_endpoint',
    'get_private_endpoint_output',
]

@pulumi.output_type
class GetPrivateEndpointResult:
    """
    A collection of values returned by getPrivateEndpoint.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, description=None, display_name=None, dns_zones=None, freeform_tags=None, id=None, is_used_with_configuration_source_provider=None, nsg_id_lists=None, private_endpoint_id=None, source_ips=None, state=None, subnet_id=None, time_created=None, vcn_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if dns_zones and not isinstance(dns_zones, list):
            raise TypeError("Expected argument 'dns_zones' to be a list")
        pulumi.set(__self__, "dns_zones", dns_zones)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_used_with_configuration_source_provider and not isinstance(is_used_with_configuration_source_provider, bool):
            raise TypeError("Expected argument 'is_used_with_configuration_source_provider' to be a bool")
        pulumi.set(__self__, "is_used_with_configuration_source_provider", is_used_with_configuration_source_provider)
        if nsg_id_lists and not isinstance(nsg_id_lists, list):
            raise TypeError("Expected argument 'nsg_id_lists' to be a list")
        pulumi.set(__self__, "nsg_id_lists", nsg_id_lists)
        if private_endpoint_id and not isinstance(private_endpoint_id, str):
            raise TypeError("Expected argument 'private_endpoint_id' to be a str")
        pulumi.set(__self__, "private_endpoint_id", private_endpoint_id)
        if source_ips and not isinstance(source_ips, list):
            raise TypeError("Expected argument 'source_ips' to be a list")
        pulumi.set(__self__, "source_ips", source_ips)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if subnet_id and not isinstance(subnet_id, str):
            raise TypeError("Expected argument 'subnet_id' to be a str")
        pulumi.set(__self__, "subnet_id", subnet_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if vcn_id and not isinstance(vcn_id, str):
            raise TypeError("Expected argument 'vcn_id' to be a str")
        pulumi.set(__self__, "vcn_id", vcn_id)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing this private endpoint details.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        Description of the private endpoint. Avoid entering confidential information.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="dnsZones")
    def dns_zones(self) -> Sequence[_builtins.str]:
        """
        DNS Proxy forwards any DNS FQDN queries over into the consumer DNS resolver if the DNS FQDN is included in the dns zones list otherwise it goes to service provider VCN resolver.
        """
        return pulumi.get(self, "dns_zones")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags associated with the resource. Each tag is a key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        Unique identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the private endpoint details.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isUsedWithConfigurationSourceProvider")
    def is_used_with_configuration_source_provider(self) -> _builtins.bool:
        """
        When `true`, allows the private endpoint to be used with a configuration source provider.
        """
        return pulumi.get(self, "is_used_with_configuration_source_provider")

    @_builtins.property
    @pulumi.getter(name="nsgIdLists")
    def nsg_id_lists(self) -> Sequence[_builtins.str]:
        """
        An array of network security groups (NSG) that the customer can optionally provide.
        """
        return pulumi.get(self, "nsg_id_lists")

    @_builtins.property
    @pulumi.getter(name="privateEndpointId")
    def private_endpoint_id(self) -> _builtins.str:
        return pulumi.get(self, "private_endpoint_id")

    @_builtins.property
    @pulumi.getter(name="sourceIps")
    def source_ips(self) -> Sequence[_builtins.str]:
        """
        The source IPs which resource manager service will use to connect to customer's network. Automatically assigned by Resource Manager Service.
        """
        return pulumi.get(self, "source_ips")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current lifecycle state of the private endpoint.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet within the VCN for the private endpoint.
        """
        return pulumi.get(self, "subnet_id")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time at which the private endpoint was created. Format is defined by RFC3339. Example: `2020-11-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="vcnId")
    def vcn_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN for the private endpoint.
        """
        return pulumi.get(self, "vcn_id")


class AwaitableGetPrivateEndpointResult(GetPrivateEndpointResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetPrivateEndpointResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            dns_zones=self.dns_zones,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_used_with_configuration_source_provider=self.is_used_with_configuration_source_provider,
            nsg_id_lists=self.nsg_id_lists,
            private_endpoint_id=self.private_endpoint_id,
            source_ips=self.source_ips,
            state=self.state,
            subnet_id=self.subnet_id,
            time_created=self.time_created,
            vcn_id=self.vcn_id)


def get_private_endpoint(private_endpoint_id: Optional[_builtins.str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetPrivateEndpointResult:
    """
    This data source provides details about a specific Private Endpoint resource in Oracle Cloud Infrastructure Resource Manager service.

    Gets the specified private endpoint.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_private_endpoint = oci.ResourceManager.get_private_endpoint(private_endpoint_id=test_private_endpoint_oci_resourcemanager_private_endpoint["id"])
    ```


    :param _builtins.str private_endpoint_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint.
    """
    __args__ = dict()
    __args__['privateEndpointId'] = private_endpoint_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ResourceManager/getPrivateEndpoint:getPrivateEndpoint', __args__, opts=opts, typ=GetPrivateEndpointResult).value

    return AwaitableGetPrivateEndpointResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        dns_zones=pulumi.get(__ret__, 'dns_zones'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        is_used_with_configuration_source_provider=pulumi.get(__ret__, 'is_used_with_configuration_source_provider'),
        nsg_id_lists=pulumi.get(__ret__, 'nsg_id_lists'),
        private_endpoint_id=pulumi.get(__ret__, 'private_endpoint_id'),
        source_ips=pulumi.get(__ret__, 'source_ips'),
        state=pulumi.get(__ret__, 'state'),
        subnet_id=pulumi.get(__ret__, 'subnet_id'),
        time_created=pulumi.get(__ret__, 'time_created'),
        vcn_id=pulumi.get(__ret__, 'vcn_id'))
def get_private_endpoint_output(private_endpoint_id: Optional[pulumi.Input[_builtins.str]] = None,
                                opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetPrivateEndpointResult]:
    """
    This data source provides details about a specific Private Endpoint resource in Oracle Cloud Infrastructure Resource Manager service.

    Gets the specified private endpoint.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_private_endpoint = oci.ResourceManager.get_private_endpoint(private_endpoint_id=test_private_endpoint_oci_resourcemanager_private_endpoint["id"])
    ```


    :param _builtins.str private_endpoint_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint.
    """
    __args__ = dict()
    __args__['privateEndpointId'] = private_endpoint_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:ResourceManager/getPrivateEndpoint:getPrivateEndpoint', __args__, opts=opts, typ=GetPrivateEndpointResult)
    return __ret__.apply(lambda __response__: GetPrivateEndpointResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        dns_zones=pulumi.get(__response__, 'dns_zones'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        is_used_with_configuration_source_provider=pulumi.get(__response__, 'is_used_with_configuration_source_provider'),
        nsg_id_lists=pulumi.get(__response__, 'nsg_id_lists'),
        private_endpoint_id=pulumi.get(__response__, 'private_endpoint_id'),
        source_ips=pulumi.get(__response__, 'source_ips'),
        state=pulumi.get(__response__, 'state'),
        subnet_id=pulumi.get(__response__, 'subnet_id'),
        time_created=pulumi.get(__response__, 'time_created'),
        vcn_id=pulumi.get(__response__, 'vcn_id')))
