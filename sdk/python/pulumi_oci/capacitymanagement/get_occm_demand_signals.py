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
    'GetOccmDemandSignalsResult',
    'AwaitableGetOccmDemandSignalsResult',
    'get_occm_demand_signals',
    'get_occm_demand_signals_output',
]

@pulumi.output_type
class GetOccmDemandSignalsResult:
    """
    A collection of values returned by getOccmDemandSignals.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, id=None, lifecycle_details=None, occm_demand_signal_collections=None):
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
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if occm_demand_signal_collections and not isinstance(occm_demand_signal_collections, list):
            raise TypeError("Expected argument 'occm_demand_signal_collections' to be a list")
        pulumi.set(__self__, "occm_demand_signal_collections", occm_demand_signal_collections)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the tenancy from which the request to create the demand signal was made.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        The display name of the demand signal.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetOccmDemandSignalsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> Optional[_builtins.str]:
        """
        The OCID of the demand signal.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> Optional[_builtins.str]:
        """
        The different states associated with a demand signal.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="occmDemandSignalCollections")
    def occm_demand_signal_collections(self) -> Sequence['outputs.GetOccmDemandSignalsOccmDemandSignalCollectionResult']:
        """
        The list of occm_demand_signal_collection.
        """
        return pulumi.get(self, "occm_demand_signal_collections")


class AwaitableGetOccmDemandSignalsResult(GetOccmDemandSignalsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetOccmDemandSignalsResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            occm_demand_signal_collections=self.occm_demand_signal_collections)


def get_occm_demand_signals(compartment_id: Optional[_builtins.str] = None,
                            display_name: Optional[_builtins.str] = None,
                            filters: Optional[Sequence[Union['GetOccmDemandSignalsFilterArgs', 'GetOccmDemandSignalsFilterArgsDict']]] = None,
                            id: Optional[_builtins.str] = None,
                            lifecycle_details: Optional[_builtins.str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetOccmDemandSignalsResult:
    """
    This data source provides the list of Occm Demand Signals in Oracle Cloud Infrastructure Capacity Management service.

    This GET call is used to list all demand signals within the compartment passed as a query parameter.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_occm_demand_signals = oci.CapacityManagement.get_occm_demand_signals(compartment_id=compartment_id,
        display_name=occm_demand_signal_display_name,
        id=occm_demand_signal_id,
        lifecycle_details=occm_demand_signal_lifecycle_details)
    ```


    :param _builtins.str compartment_id: The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
    :param _builtins.str display_name: A filter to return only the resources that match the entire display name. The match is not case sensitive.
    :param _builtins.str id: A query parameter to filter the list of demand signals based on it's OCID.
    :param _builtins.str lifecycle_details: A query parameter to filter the list of demand signals based on its state.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['lifecycleDetails'] = lifecycle_details
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:CapacityManagement/getOccmDemandSignals:getOccmDemandSignals', __args__, opts=opts, typ=GetOccmDemandSignalsResult).value

    return AwaitableGetOccmDemandSignalsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        occm_demand_signal_collections=pulumi.get(__ret__, 'occm_demand_signal_collections'))
def get_occm_demand_signals_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                   display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   filters: Optional[pulumi.Input[Optional[Sequence[Union['GetOccmDemandSignalsFilterArgs', 'GetOccmDemandSignalsFilterArgsDict']]]]] = None,
                                   id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   lifecycle_details: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetOccmDemandSignalsResult]:
    """
    This data source provides the list of Occm Demand Signals in Oracle Cloud Infrastructure Capacity Management service.

    This GET call is used to list all demand signals within the compartment passed as a query parameter.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_occm_demand_signals = oci.CapacityManagement.get_occm_demand_signals(compartment_id=compartment_id,
        display_name=occm_demand_signal_display_name,
        id=occm_demand_signal_id,
        lifecycle_details=occm_demand_signal_lifecycle_details)
    ```


    :param _builtins.str compartment_id: The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
    :param _builtins.str display_name: A filter to return only the resources that match the entire display name. The match is not case sensitive.
    :param _builtins.str id: A query parameter to filter the list of demand signals based on it's OCID.
    :param _builtins.str lifecycle_details: A query parameter to filter the list of demand signals based on its state.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['lifecycleDetails'] = lifecycle_details
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:CapacityManagement/getOccmDemandSignals:getOccmDemandSignals', __args__, opts=opts, typ=GetOccmDemandSignalsResult)
    return __ret__.apply(lambda __response__: GetOccmDemandSignalsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        occm_demand_signal_collections=pulumi.get(__response__, 'occm_demand_signal_collections')))
