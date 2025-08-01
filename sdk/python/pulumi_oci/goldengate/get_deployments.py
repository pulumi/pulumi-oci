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
    'GetDeploymentsResult',
    'AwaitableGetDeploymentsResult',
    'get_deployments',
    'get_deployments_output',
]

@pulumi.output_type
class GetDeploymentsResult:
    """
    A collection of values returned by getDeployments.
    """
    def __init__(__self__, assignable_connection_id=None, assigned_connection_id=None, compartment_id=None, deployment_collections=None, display_name=None, filters=None, fqdn=None, id=None, lifecycle_sub_state=None, state=None, supported_connection_type=None):
        if assignable_connection_id and not isinstance(assignable_connection_id, str):
            raise TypeError("Expected argument 'assignable_connection_id' to be a str")
        pulumi.set(__self__, "assignable_connection_id", assignable_connection_id)
        if assigned_connection_id and not isinstance(assigned_connection_id, str):
            raise TypeError("Expected argument 'assigned_connection_id' to be a str")
        pulumi.set(__self__, "assigned_connection_id", assigned_connection_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if deployment_collections and not isinstance(deployment_collections, list):
            raise TypeError("Expected argument 'deployment_collections' to be a list")
        pulumi.set(__self__, "deployment_collections", deployment_collections)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if fqdn and not isinstance(fqdn, str):
            raise TypeError("Expected argument 'fqdn' to be a str")
        pulumi.set(__self__, "fqdn", fqdn)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_sub_state and not isinstance(lifecycle_sub_state, str):
            raise TypeError("Expected argument 'lifecycle_sub_state' to be a str")
        pulumi.set(__self__, "lifecycle_sub_state", lifecycle_sub_state)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if supported_connection_type and not isinstance(supported_connection_type, str):
            raise TypeError("Expected argument 'supported_connection_type' to be a str")
        pulumi.set(__self__, "supported_connection_type", supported_connection_type)

    @_builtins.property
    @pulumi.getter(name="assignableConnectionId")
    def assignable_connection_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "assignable_connection_id")

    @_builtins.property
    @pulumi.getter(name="assignedConnectionId")
    def assigned_connection_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "assigned_connection_id")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="deploymentCollections")
    def deployment_collections(self) -> Sequence['outputs.GetDeploymentsDeploymentCollectionResult']:
        """
        The list of deployment_collection.
        """
        return pulumi.get(self, "deployment_collections")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        An object's Display Name.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDeploymentsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def fqdn(self) -> Optional[_builtins.str]:
        """
        A three-label Fully Qualified Domain Name (FQDN) for a resource.
        """
        return pulumi.get(self, "fqdn")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleSubState")
    def lifecycle_sub_state(self) -> Optional[_builtins.str]:
        """
        Possible GGS lifecycle sub-states.
        """
        return pulumi.get(self, "lifecycle_sub_state")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        Possible lifecycle states.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="supportedConnectionType")
    def supported_connection_type(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "supported_connection_type")


class AwaitableGetDeploymentsResult(GetDeploymentsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDeploymentsResult(
            assignable_connection_id=self.assignable_connection_id,
            assigned_connection_id=self.assigned_connection_id,
            compartment_id=self.compartment_id,
            deployment_collections=self.deployment_collections,
            display_name=self.display_name,
            filters=self.filters,
            fqdn=self.fqdn,
            id=self.id,
            lifecycle_sub_state=self.lifecycle_sub_state,
            state=self.state,
            supported_connection_type=self.supported_connection_type)


def get_deployments(assignable_connection_id: Optional[_builtins.str] = None,
                    assigned_connection_id: Optional[_builtins.str] = None,
                    compartment_id: Optional[_builtins.str] = None,
                    display_name: Optional[_builtins.str] = None,
                    filters: Optional[Sequence[Union['GetDeploymentsFilterArgs', 'GetDeploymentsFilterArgsDict']]] = None,
                    fqdn: Optional[_builtins.str] = None,
                    lifecycle_sub_state: Optional[_builtins.str] = None,
                    state: Optional[_builtins.str] = None,
                    supported_connection_type: Optional[_builtins.str] = None,
                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDeploymentsResult:
    """
    This data source provides the list of Deployments in Oracle Cloud Infrastructure Golden Gate service.

    Lists the Deployments in a compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deployments = oci.GoldenGate.get_deployments(compartment_id=compartment_id,
        assignable_connection_id=test_connection["id"],
        assigned_connection_id=test_connection["id"],
        display_name=deployment_display_name,
        fqdn=deployment_fqdn,
        lifecycle_sub_state=deployment_lifecycle_sub_state,
        state=deployment_state,
        supported_connection_type=deployment_supported_connection_type)
    ```


    :param _builtins.str assignable_connection_id: Return the deployments to which the specified connectionId may be assigned.
    :param _builtins.str assigned_connection_id: The OCID of the connection which for the deployment must be assigned.
    :param _builtins.str compartment_id: The OCID of the compartment that contains the work request. Work requests should be scoped  to the same compartment as the resource the work request affects. If the work request concerns  multiple resources, and those resources are not in the same compartment, it is up to the service team  to pick the primary resource whose compartment should be used.
    :param _builtins.str display_name: A filter to return only the resources that match the entire 'displayName' given.
    :param _builtins.str fqdn: A filter to return only the resources that match the 'fqdn' given.
    :param _builtins.str lifecycle_sub_state: A filter to return only the resources that match the 'lifecycleSubState' given.
    :param _builtins.str state: A filter to return only the resources that match the 'lifecycleState' given.
    :param _builtins.str supported_connection_type: The connection type which the deployment must support.
    """
    __args__ = dict()
    __args__['assignableConnectionId'] = assignable_connection_id
    __args__['assignedConnectionId'] = assigned_connection_id
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['fqdn'] = fqdn
    __args__['lifecycleSubState'] = lifecycle_sub_state
    __args__['state'] = state
    __args__['supportedConnectionType'] = supported_connection_type
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:GoldenGate/getDeployments:getDeployments', __args__, opts=opts, typ=GetDeploymentsResult).value

    return AwaitableGetDeploymentsResult(
        assignable_connection_id=pulumi.get(__ret__, 'assignable_connection_id'),
        assigned_connection_id=pulumi.get(__ret__, 'assigned_connection_id'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        deployment_collections=pulumi.get(__ret__, 'deployment_collections'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        fqdn=pulumi.get(__ret__, 'fqdn'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_sub_state=pulumi.get(__ret__, 'lifecycle_sub_state'),
        state=pulumi.get(__ret__, 'state'),
        supported_connection_type=pulumi.get(__ret__, 'supported_connection_type'))
def get_deployments_output(assignable_connection_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                           assigned_connection_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                           compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                           display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                           filters: Optional[pulumi.Input[Optional[Sequence[Union['GetDeploymentsFilterArgs', 'GetDeploymentsFilterArgsDict']]]]] = None,
                           fqdn: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                           lifecycle_sub_state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                           state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                           supported_connection_type: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                           opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDeploymentsResult]:
    """
    This data source provides the list of Deployments in Oracle Cloud Infrastructure Golden Gate service.

    Lists the Deployments in a compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deployments = oci.GoldenGate.get_deployments(compartment_id=compartment_id,
        assignable_connection_id=test_connection["id"],
        assigned_connection_id=test_connection["id"],
        display_name=deployment_display_name,
        fqdn=deployment_fqdn,
        lifecycle_sub_state=deployment_lifecycle_sub_state,
        state=deployment_state,
        supported_connection_type=deployment_supported_connection_type)
    ```


    :param _builtins.str assignable_connection_id: Return the deployments to which the specified connectionId may be assigned.
    :param _builtins.str assigned_connection_id: The OCID of the connection which for the deployment must be assigned.
    :param _builtins.str compartment_id: The OCID of the compartment that contains the work request. Work requests should be scoped  to the same compartment as the resource the work request affects. If the work request concerns  multiple resources, and those resources are not in the same compartment, it is up to the service team  to pick the primary resource whose compartment should be used.
    :param _builtins.str display_name: A filter to return only the resources that match the entire 'displayName' given.
    :param _builtins.str fqdn: A filter to return only the resources that match the 'fqdn' given.
    :param _builtins.str lifecycle_sub_state: A filter to return only the resources that match the 'lifecycleSubState' given.
    :param _builtins.str state: A filter to return only the resources that match the 'lifecycleState' given.
    :param _builtins.str supported_connection_type: The connection type which the deployment must support.
    """
    __args__ = dict()
    __args__['assignableConnectionId'] = assignable_connection_id
    __args__['assignedConnectionId'] = assigned_connection_id
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['fqdn'] = fqdn
    __args__['lifecycleSubState'] = lifecycle_sub_state
    __args__['state'] = state
    __args__['supportedConnectionType'] = supported_connection_type
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:GoldenGate/getDeployments:getDeployments', __args__, opts=opts, typ=GetDeploymentsResult)
    return __ret__.apply(lambda __response__: GetDeploymentsResult(
        assignable_connection_id=pulumi.get(__response__, 'assignable_connection_id'),
        assigned_connection_id=pulumi.get(__response__, 'assigned_connection_id'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        deployment_collections=pulumi.get(__response__, 'deployment_collections'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        fqdn=pulumi.get(__response__, 'fqdn'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_sub_state=pulumi.get(__response__, 'lifecycle_sub_state'),
        state=pulumi.get(__response__, 'state'),
        supported_connection_type=pulumi.get(__response__, 'supported_connection_type')))
