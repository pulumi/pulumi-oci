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
    'GetComputeCapacityReservationsResult',
    'AwaitableGetComputeCapacityReservationsResult',
    'get_compute_capacity_reservations',
    'get_compute_capacity_reservations_output',
]

@pulumi.output_type
class GetComputeCapacityReservationsResult:
    """
    A collection of values returned by getComputeCapacityReservations.
    """
    def __init__(__self__, availability_domain=None, compartment_id=None, compute_capacity_reservations=None, display_name=None, filters=None, id=None, state=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compute_capacity_reservations and not isinstance(compute_capacity_reservations, list):
            raise TypeError("Expected argument 'compute_capacity_reservations' to be a list")
        pulumi.set(__self__, "compute_capacity_reservations", compute_capacity_reservations)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> Optional[builtins.str]:
        """
        The availability domain of the compute capacity reservation.  Example: `Uocm:PHX-AD-1`
        """
        return pulumi.get(self, "availability_domain")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the compute capacity reservation.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="computeCapacityReservations")
    def compute_capacity_reservations(self) -> Sequence['outputs.GetComputeCapacityReservationsComputeCapacityReservationResult']:
        """
        The list of compute_capacity_reservations.
        """
        return pulumi.get(self, "compute_capacity_reservations")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[builtins.str]:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetComputeCapacityReservationsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def state(self) -> Optional[builtins.str]:
        """
        The current state of the compute capacity reservation.
        """
        return pulumi.get(self, "state")


class AwaitableGetComputeCapacityReservationsResult(GetComputeCapacityReservationsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetComputeCapacityReservationsResult(
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            compute_capacity_reservations=self.compute_capacity_reservations,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            state=self.state)


def get_compute_capacity_reservations(availability_domain: Optional[builtins.str] = None,
                                      compartment_id: Optional[builtins.str] = None,
                                      display_name: Optional[builtins.str] = None,
                                      filters: Optional[Sequence[Union['GetComputeCapacityReservationsFilterArgs', 'GetComputeCapacityReservationsFilterArgsDict']]] = None,
                                      state: Optional[builtins.str] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetComputeCapacityReservationsResult:
    """
    This data source provides the list of Compute Capacity Reservations in Oracle Cloud Infrastructure Core service.

    Lists the compute capacity reservations that match the specified criteria and compartment.

    You can limit the list by specifying a compute capacity reservation display name
    (the list will include all the identically-named compute capacity reservations in the compartment).

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_capacity_reservations = oci.Core.get_compute_capacity_reservations(compartment_id=compartment_id,
        availability_domain=compute_capacity_reservation_availability_domain,
        display_name=compute_capacity_reservation_display_name,
        state=compute_capacity_reservation_state)
    ```


    :param builtins.str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param builtins.str display_name: A filter to return only resources that match the given display name exactly.
    :param builtins.str state: A filter to only return resources that match the given lifecycle state.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getComputeCapacityReservations:getComputeCapacityReservations', __args__, opts=opts, typ=GetComputeCapacityReservationsResult).value

    return AwaitableGetComputeCapacityReservationsResult(
        availability_domain=pulumi.get(__ret__, 'availability_domain'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compute_capacity_reservations=pulumi.get(__ret__, 'compute_capacity_reservations'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        state=pulumi.get(__ret__, 'state'))
def get_compute_capacity_reservations_output(availability_domain: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                             compartment_id: Optional[pulumi.Input[builtins.str]] = None,
                                             display_name: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                             filters: Optional[pulumi.Input[Optional[Sequence[Union['GetComputeCapacityReservationsFilterArgs', 'GetComputeCapacityReservationsFilterArgsDict']]]]] = None,
                                             state: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                             opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetComputeCapacityReservationsResult]:
    """
    This data source provides the list of Compute Capacity Reservations in Oracle Cloud Infrastructure Core service.

    Lists the compute capacity reservations that match the specified criteria and compartment.

    You can limit the list by specifying a compute capacity reservation display name
    (the list will include all the identically-named compute capacity reservations in the compartment).

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_capacity_reservations = oci.Core.get_compute_capacity_reservations(compartment_id=compartment_id,
        availability_domain=compute_capacity_reservation_availability_domain,
        display_name=compute_capacity_reservation_display_name,
        state=compute_capacity_reservation_state)
    ```


    :param builtins.str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param builtins.str display_name: A filter to return only resources that match the given display name exactly.
    :param builtins.str state: A filter to only return resources that match the given lifecycle state.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getComputeCapacityReservations:getComputeCapacityReservations', __args__, opts=opts, typ=GetComputeCapacityReservationsResult)
    return __ret__.apply(lambda __response__: GetComputeCapacityReservationsResult(
        availability_domain=pulumi.get(__response__, 'availability_domain'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        compute_capacity_reservations=pulumi.get(__response__, 'compute_capacity_reservations'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        state=pulumi.get(__response__, 'state')))
