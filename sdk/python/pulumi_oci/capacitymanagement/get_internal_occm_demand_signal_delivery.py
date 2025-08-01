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
    'GetInternalOccmDemandSignalDeliveryResult',
    'AwaitableGetInternalOccmDemandSignalDeliveryResult',
    'get_internal_occm_demand_signal_delivery',
    'get_internal_occm_demand_signal_delivery_output',
]

@pulumi.output_type
class GetInternalOccmDemandSignalDeliveryResult:
    """
    A collection of values returned by getInternalOccmDemandSignalDelivery.
    """
    def __init__(__self__, accepted_quantity=None, compartment_id=None, defined_tags=None, demand_signal_id=None, demand_signal_item_id=None, freeform_tags=None, id=None, justification=None, lifecycle_details=None, notes=None, occ_customer_group_id=None, occm_demand_signal_delivery_id=None, state=None, system_tags=None, time_delivered=None):
        if accepted_quantity and not isinstance(accepted_quantity, str):
            raise TypeError("Expected argument 'accepted_quantity' to be a str")
        pulumi.set(__self__, "accepted_quantity", accepted_quantity)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if demand_signal_id and not isinstance(demand_signal_id, str):
            raise TypeError("Expected argument 'demand_signal_id' to be a str")
        pulumi.set(__self__, "demand_signal_id", demand_signal_id)
        if demand_signal_item_id and not isinstance(demand_signal_item_id, str):
            raise TypeError("Expected argument 'demand_signal_item_id' to be a str")
        pulumi.set(__self__, "demand_signal_item_id", demand_signal_item_id)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if justification and not isinstance(justification, str):
            raise TypeError("Expected argument 'justification' to be a str")
        pulumi.set(__self__, "justification", justification)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if notes and not isinstance(notes, str):
            raise TypeError("Expected argument 'notes' to be a str")
        pulumi.set(__self__, "notes", notes)
        if occ_customer_group_id and not isinstance(occ_customer_group_id, str):
            raise TypeError("Expected argument 'occ_customer_group_id' to be a str")
        pulumi.set(__self__, "occ_customer_group_id", occ_customer_group_id)
        if occm_demand_signal_delivery_id and not isinstance(occm_demand_signal_delivery_id, str):
            raise TypeError("Expected argument 'occm_demand_signal_delivery_id' to be a str")
        pulumi.set(__self__, "occm_demand_signal_delivery_id", occm_demand_signal_delivery_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_delivered and not isinstance(time_delivered, str):
            raise TypeError("Expected argument 'time_delivered' to be a str")
        pulumi.set(__self__, "time_delivered", time_delivered)

    @_builtins.property
    @pulumi.getter(name="acceptedQuantity")
    def accepted_quantity(self) -> _builtins.str:
        """
        The quantity of the resource that Oracle Cloud Infrastructure will supply to the customer.
        """
        return pulumi.get(self, "accepted_quantity")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the tenancy from which the demand signal delivery resource is created.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="demandSignalId")
    def demand_signal_id(self) -> _builtins.str:
        """
        The OCID of the demand signal under which this delivery will be grouped.
        """
        return pulumi.get(self, "demand_signal_id")

    @_builtins.property
    @pulumi.getter(name="demandSignalItemId")
    def demand_signal_item_id(self) -> _builtins.str:
        """
        The OCID of the demand signal item corresponding to which this delivery is made.
        """
        return pulumi.get(self, "demand_signal_item_id")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The OCID of this demand signal delivery resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def justification(self) -> _builtins.str:
        """
        This field could be used by Oracle Cloud Infrastructure to communicate the reason for accepting or declining the request.
        """
        return pulumi.get(self, "justification")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        The enum values corresponding to the various states associated with the delivery resource.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter
    def notes(self) -> _builtins.str:
        """
        This field acts as a notes section for operators.
        """
        return pulumi.get(self, "notes")

    @_builtins.property
    @pulumi.getter(name="occCustomerGroupId")
    def occ_customer_group_id(self) -> _builtins.str:
        """
        The OCID of the corresponding customer group to which this demand signal delivery resource belongs to.
        """
        return pulumi.get(self, "occ_customer_group_id")

    @_builtins.property
    @pulumi.getter(name="occmDemandSignalDeliveryId")
    def occm_demand_signal_delivery_id(self) -> _builtins.str:
        return pulumi.get(self, "occm_demand_signal_delivery_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current lifecycle state of the resource.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeDelivered")
    def time_delivered(self) -> _builtins.str:
        """
        The date on which the Oracle Cloud Infrastructure delivered the resource to the customers. The default value for this will be the corresponding demand signal item resource's need by date.
        """
        return pulumi.get(self, "time_delivered")


class AwaitableGetInternalOccmDemandSignalDeliveryResult(GetInternalOccmDemandSignalDeliveryResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetInternalOccmDemandSignalDeliveryResult(
            accepted_quantity=self.accepted_quantity,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            demand_signal_id=self.demand_signal_id,
            demand_signal_item_id=self.demand_signal_item_id,
            freeform_tags=self.freeform_tags,
            id=self.id,
            justification=self.justification,
            lifecycle_details=self.lifecycle_details,
            notes=self.notes,
            occ_customer_group_id=self.occ_customer_group_id,
            occm_demand_signal_delivery_id=self.occm_demand_signal_delivery_id,
            state=self.state,
            system_tags=self.system_tags,
            time_delivered=self.time_delivered)


def get_internal_occm_demand_signal_delivery(occm_demand_signal_delivery_id: Optional[_builtins.str] = None,
                                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetInternalOccmDemandSignalDeliveryResult:
    """
    This data source provides details about a specific Internal Occm Demand Signal Delivery resource in Oracle Cloud Infrastructure Capacity Management service.

    This is an internal GET API to get the details of a demand signal delivery resource corresponding to a demand signal item.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_internal_occm_demand_signal_delivery = oci.CapacityManagement.get_internal_occm_demand_signal_delivery(occm_demand_signal_delivery_id=test_occm_demand_signal_delivery["id"])
    ```


    :param _builtins.str occm_demand_signal_delivery_id: The OCID of the demand signal delivery.
    """
    __args__ = dict()
    __args__['occmDemandSignalDeliveryId'] = occm_demand_signal_delivery_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:CapacityManagement/getInternalOccmDemandSignalDelivery:getInternalOccmDemandSignalDelivery', __args__, opts=opts, typ=GetInternalOccmDemandSignalDeliveryResult).value

    return AwaitableGetInternalOccmDemandSignalDeliveryResult(
        accepted_quantity=pulumi.get(__ret__, 'accepted_quantity'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        demand_signal_id=pulumi.get(__ret__, 'demand_signal_id'),
        demand_signal_item_id=pulumi.get(__ret__, 'demand_signal_item_id'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        justification=pulumi.get(__ret__, 'justification'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        notes=pulumi.get(__ret__, 'notes'),
        occ_customer_group_id=pulumi.get(__ret__, 'occ_customer_group_id'),
        occm_demand_signal_delivery_id=pulumi.get(__ret__, 'occm_demand_signal_delivery_id'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_delivered=pulumi.get(__ret__, 'time_delivered'))
def get_internal_occm_demand_signal_delivery_output(occm_demand_signal_delivery_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                    opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetInternalOccmDemandSignalDeliveryResult]:
    """
    This data source provides details about a specific Internal Occm Demand Signal Delivery resource in Oracle Cloud Infrastructure Capacity Management service.

    This is an internal GET API to get the details of a demand signal delivery resource corresponding to a demand signal item.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_internal_occm_demand_signal_delivery = oci.CapacityManagement.get_internal_occm_demand_signal_delivery(occm_demand_signal_delivery_id=test_occm_demand_signal_delivery["id"])
    ```


    :param _builtins.str occm_demand_signal_delivery_id: The OCID of the demand signal delivery.
    """
    __args__ = dict()
    __args__['occmDemandSignalDeliveryId'] = occm_demand_signal_delivery_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:CapacityManagement/getInternalOccmDemandSignalDelivery:getInternalOccmDemandSignalDelivery', __args__, opts=opts, typ=GetInternalOccmDemandSignalDeliveryResult)
    return __ret__.apply(lambda __response__: GetInternalOccmDemandSignalDeliveryResult(
        accepted_quantity=pulumi.get(__response__, 'accepted_quantity'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        demand_signal_id=pulumi.get(__response__, 'demand_signal_id'),
        demand_signal_item_id=pulumi.get(__response__, 'demand_signal_item_id'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        justification=pulumi.get(__response__, 'justification'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        notes=pulumi.get(__response__, 'notes'),
        occ_customer_group_id=pulumi.get(__response__, 'occ_customer_group_id'),
        occm_demand_signal_delivery_id=pulumi.get(__response__, 'occm_demand_signal_delivery_id'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_delivered=pulumi.get(__response__, 'time_delivered')))
