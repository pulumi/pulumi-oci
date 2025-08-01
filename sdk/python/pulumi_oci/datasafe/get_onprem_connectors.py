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
    'GetOnpremConnectorsResult',
    'AwaitableGetOnpremConnectorsResult',
    'get_onprem_connectors',
    'get_onprem_connectors_output',
]

@pulumi.output_type
class GetOnpremConnectorsResult:
    """
    A collection of values returned by getOnpremConnectors.
    """
    def __init__(__self__, access_level=None, compartment_id=None, compartment_id_in_subtree=None, display_name=None, filters=None, id=None, on_prem_connector_id=None, on_prem_connector_lifecycle_state=None, on_prem_connectors=None):
        if access_level and not isinstance(access_level, str):
            raise TypeError("Expected argument 'access_level' to be a str")
        pulumi.set(__self__, "access_level", access_level)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compartment_id_in_subtree and not isinstance(compartment_id_in_subtree, bool):
            raise TypeError("Expected argument 'compartment_id_in_subtree' to be a bool")
        pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if on_prem_connector_id and not isinstance(on_prem_connector_id, str):
            raise TypeError("Expected argument 'on_prem_connector_id' to be a str")
        pulumi.set(__self__, "on_prem_connector_id", on_prem_connector_id)
        if on_prem_connector_lifecycle_state and not isinstance(on_prem_connector_lifecycle_state, str):
            raise TypeError("Expected argument 'on_prem_connector_lifecycle_state' to be a str")
        pulumi.set(__self__, "on_prem_connector_lifecycle_state", on_prem_connector_lifecycle_state)
        if on_prem_connectors and not isinstance(on_prem_connectors, list):
            raise TypeError("Expected argument 'on_prem_connectors' to be a list")
        pulumi.set(__self__, "on_prem_connectors", on_prem_connectors)

    @_builtins.property
    @pulumi.getter(name="accessLevel")
    def access_level(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "access_level")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment that contains the on-premises connector.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        The display name of the on-premises connector.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetOnpremConnectorsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="onPremConnectorId")
    def on_prem_connector_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "on_prem_connector_id")

    @_builtins.property
    @pulumi.getter(name="onPremConnectorLifecycleState")
    def on_prem_connector_lifecycle_state(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "on_prem_connector_lifecycle_state")

    @_builtins.property
    @pulumi.getter(name="onPremConnectors")
    def on_prem_connectors(self) -> Sequence['outputs.GetOnpremConnectorsOnPremConnectorResult']:
        """
        The list of on_prem_connectors.
        """
        return pulumi.get(self, "on_prem_connectors")


class AwaitableGetOnpremConnectorsResult(GetOnpremConnectorsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetOnpremConnectorsResult(
            access_level=self.access_level,
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            on_prem_connector_id=self.on_prem_connector_id,
            on_prem_connector_lifecycle_state=self.on_prem_connector_lifecycle_state,
            on_prem_connectors=self.on_prem_connectors)


def get_onprem_connectors(access_level: Optional[_builtins.str] = None,
                          compartment_id: Optional[_builtins.str] = None,
                          compartment_id_in_subtree: Optional[_builtins.bool] = None,
                          display_name: Optional[_builtins.str] = None,
                          filters: Optional[Sequence[Union['GetOnpremConnectorsFilterArgs', 'GetOnpremConnectorsFilterArgsDict']]] = None,
                          on_prem_connector_id: Optional[_builtins.str] = None,
                          on_prem_connector_lifecycle_state: Optional[_builtins.str] = None,
                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetOnpremConnectorsResult:
    """
    This data source provides the list of On Prem Connectors in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of on-premises connectors.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_on_prem_connectors = oci.DataSafe.get_onprem_connectors(compartment_id=compartment_id,
        access_level=on_prem_connector_access_level,
        compartment_id_in_subtree=on_prem_connector_compartment_id_in_subtree,
        display_name=on_prem_connector_display_name,
        on_prem_connector_id=test_on_prem_connector["id"],
        on_prem_connector_lifecycle_state=on_prem_connector_on_prem_connector_lifecycle_state)
    ```


    :param _builtins.str access_level: Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
    :param _builtins.str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param _builtins.bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param _builtins.str display_name: A filter to return only resources that match the specified display name.
    :param _builtins.str on_prem_connector_id: A filter to return only the on-premises connector that matches the specified id.
    :param _builtins.str on_prem_connector_lifecycle_state: A filter to return only on-premises connector resources that match the specified lifecycle state.
    """
    __args__ = dict()
    __args__['accessLevel'] = access_level
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['onPremConnectorId'] = on_prem_connector_id
    __args__['onPremConnectorLifecycleState'] = on_prem_connector_lifecycle_state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getOnpremConnectors:getOnpremConnectors', __args__, opts=opts, typ=GetOnpremConnectorsResult).value

    return AwaitableGetOnpremConnectorsResult(
        access_level=pulumi.get(__ret__, 'access_level'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compartment_id_in_subtree=pulumi.get(__ret__, 'compartment_id_in_subtree'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        on_prem_connector_id=pulumi.get(__ret__, 'on_prem_connector_id'),
        on_prem_connector_lifecycle_state=pulumi.get(__ret__, 'on_prem_connector_lifecycle_state'),
        on_prem_connectors=pulumi.get(__ret__, 'on_prem_connectors'))
def get_onprem_connectors_output(access_level: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                 compartment_id_in_subtree: Optional[pulumi.Input[Optional[_builtins.bool]]] = None,
                                 display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                 filters: Optional[pulumi.Input[Optional[Sequence[Union['GetOnpremConnectorsFilterArgs', 'GetOnpremConnectorsFilterArgsDict']]]]] = None,
                                 on_prem_connector_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                 on_prem_connector_lifecycle_state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                 opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetOnpremConnectorsResult]:
    """
    This data source provides the list of On Prem Connectors in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of on-premises connectors.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_on_prem_connectors = oci.DataSafe.get_onprem_connectors(compartment_id=compartment_id,
        access_level=on_prem_connector_access_level,
        compartment_id_in_subtree=on_prem_connector_compartment_id_in_subtree,
        display_name=on_prem_connector_display_name,
        on_prem_connector_id=test_on_prem_connector["id"],
        on_prem_connector_lifecycle_state=on_prem_connector_on_prem_connector_lifecycle_state)
    ```


    :param _builtins.str access_level: Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
    :param _builtins.str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param _builtins.bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param _builtins.str display_name: A filter to return only resources that match the specified display name.
    :param _builtins.str on_prem_connector_id: A filter to return only the on-premises connector that matches the specified id.
    :param _builtins.str on_prem_connector_lifecycle_state: A filter to return only on-premises connector resources that match the specified lifecycle state.
    """
    __args__ = dict()
    __args__['accessLevel'] = access_level
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['onPremConnectorId'] = on_prem_connector_id
    __args__['onPremConnectorLifecycleState'] = on_prem_connector_lifecycle_state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataSafe/getOnpremConnectors:getOnpremConnectors', __args__, opts=opts, typ=GetOnpremConnectorsResult)
    return __ret__.apply(lambda __response__: GetOnpremConnectorsResult(
        access_level=pulumi.get(__response__, 'access_level'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        compartment_id_in_subtree=pulumi.get(__response__, 'compartment_id_in_subtree'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        on_prem_connector_id=pulumi.get(__response__, 'on_prem_connector_id'),
        on_prem_connector_lifecycle_state=pulumi.get(__response__, 'on_prem_connector_lifecycle_state'),
        on_prem_connectors=pulumi.get(__response__, 'on_prem_connectors')))
