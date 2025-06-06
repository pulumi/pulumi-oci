# coding=utf-8
# *** WARNING: this file was generated by pulumi-language-python. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import builtins
import copy
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
    'GetOutboundConnectorsResult',
    'AwaitableGetOutboundConnectorsResult',
    'get_outbound_connectors',
    'get_outbound_connectors_output',
]

@pulumi.output_type
class GetOutboundConnectorsResult:
    """
    A collection of values returned by getOutboundConnectors.
    """
    def __init__(__self__, availability_domain=None, compartment_id=None, display_name=None, filters=None, id=None, outbound_connectors=None, state=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if outbound_connectors and not isinstance(outbound_connectors, list):
            raise TypeError("Expected argument 'outbound_connectors' to be a list")
        pulumi.set(__self__, "outbound_connectors", outbound_connectors)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> builtins.str:
        """
        The availability domain the outbound connector is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
        """
        return pulumi.get(self, "availability_domain")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the outbound connector.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[builtins.str]:
        """
        A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My outbound connector`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetOutboundConnectorsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> Optional[builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the outbound connector.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="outboundConnectors")
    def outbound_connectors(self) -> Sequence['outputs.GetOutboundConnectorsOutboundConnectorResult']:
        """
        The list of outbound_connectors.
        """
        return pulumi.get(self, "outbound_connectors")

    @property
    @pulumi.getter
    def state(self) -> Optional[builtins.str]:
        """
        The current state of this outbound connector.
        """
        return pulumi.get(self, "state")


class AwaitableGetOutboundConnectorsResult(GetOutboundConnectorsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetOutboundConnectorsResult(
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            outbound_connectors=self.outbound_connectors,
            state=self.state)


def get_outbound_connectors(availability_domain: Optional[builtins.str] = None,
                            compartment_id: Optional[builtins.str] = None,
                            display_name: Optional[builtins.str] = None,
                            filters: Optional[Sequence[Union['GetOutboundConnectorsFilterArgs', 'GetOutboundConnectorsFilterArgsDict']]] = None,
                            id: Optional[builtins.str] = None,
                            state: Optional[builtins.str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetOutboundConnectorsResult:
    """
    This data source provides the list of Outbound Connectors in Oracle Cloud Infrastructure File Storage service.

    Lists the outbound connector resources in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_outbound_connectors = oci.FileStorage.get_outbound_connectors(availability_domain=outbound_connector_availability_domain,
        compartment_id=compartment_id,
        display_name=outbound_connector_display_name,
        id=outbound_connector_id,
        state=outbound_connector_state)
    ```


    :param builtins.str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param builtins.str display_name: A user-friendly name. It does not have to be unique, and it is changeable.  Example: `My resource`
    :param builtins.str id: Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
    :param builtins.str state: Filter results by the specified lifecycle state. Must be a valid state for the resource type.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:FileStorage/getOutboundConnectors:getOutboundConnectors', __args__, opts=opts, typ=GetOutboundConnectorsResult).value

    return AwaitableGetOutboundConnectorsResult(
        availability_domain=pulumi.get(__ret__, 'availability_domain'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        outbound_connectors=pulumi.get(__ret__, 'outbound_connectors'),
        state=pulumi.get(__ret__, 'state'))
def get_outbound_connectors_output(availability_domain: Optional[pulumi.Input[builtins.str]] = None,
                                   compartment_id: Optional[pulumi.Input[builtins.str]] = None,
                                   display_name: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                   filters: Optional[pulumi.Input[Optional[Sequence[Union['GetOutboundConnectorsFilterArgs', 'GetOutboundConnectorsFilterArgsDict']]]]] = None,
                                   id: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                   state: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                   opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetOutboundConnectorsResult]:
    """
    This data source provides the list of Outbound Connectors in Oracle Cloud Infrastructure File Storage service.

    Lists the outbound connector resources in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_outbound_connectors = oci.FileStorage.get_outbound_connectors(availability_domain=outbound_connector_availability_domain,
        compartment_id=compartment_id,
        display_name=outbound_connector_display_name,
        id=outbound_connector_id,
        state=outbound_connector_state)
    ```


    :param builtins.str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param builtins.str display_name: A user-friendly name. It does not have to be unique, and it is changeable.  Example: `My resource`
    :param builtins.str id: Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
    :param builtins.str state: Filter results by the specified lifecycle state. Must be a valid state for the resource type.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:FileStorage/getOutboundConnectors:getOutboundConnectors', __args__, opts=opts, typ=GetOutboundConnectorsResult)
    return __ret__.apply(lambda __response__: GetOutboundConnectorsResult(
        availability_domain=pulumi.get(__response__, 'availability_domain'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        outbound_connectors=pulumi.get(__response__, 'outbound_connectors'),
        state=pulumi.get(__response__, 'state')))
