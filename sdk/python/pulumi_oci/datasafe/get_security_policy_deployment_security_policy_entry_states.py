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
    'GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult',
    'AwaitableGetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult',
    'get_security_policy_deployment_security_policy_entry_states',
    'get_security_policy_deployment_security_policy_entry_states_output',
]

@pulumi.output_type
class GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult:
    """
    A collection of values returned by getSecurityPolicyDeploymentSecurityPolicyEntryStates.
    """
    def __init__(__self__, deployment_status=None, filters=None, id=None, security_policy_deployment_id=None, security_policy_entry_id=None, security_policy_entry_state_collections=None):
        if deployment_status and not isinstance(deployment_status, str):
            raise TypeError("Expected argument 'deployment_status' to be a str")
        pulumi.set(__self__, "deployment_status", deployment_status)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if security_policy_deployment_id and not isinstance(security_policy_deployment_id, str):
            raise TypeError("Expected argument 'security_policy_deployment_id' to be a str")
        pulumi.set(__self__, "security_policy_deployment_id", security_policy_deployment_id)
        if security_policy_entry_id and not isinstance(security_policy_entry_id, str):
            raise TypeError("Expected argument 'security_policy_entry_id' to be a str")
        pulumi.set(__self__, "security_policy_entry_id", security_policy_entry_id)
        if security_policy_entry_state_collections and not isinstance(security_policy_entry_state_collections, list):
            raise TypeError("Expected argument 'security_policy_entry_state_collections' to be a list")
        pulumi.set(__self__, "security_policy_entry_state_collections", security_policy_entry_state_collections)

    @_builtins.property
    @pulumi.getter(name="deploymentStatus")
    def deployment_status(self) -> Optional[_builtins.str]:
        """
        The current deployment status of the security policy deployment and the security policy entry associated.
        """
        return pulumi.get(self, "deployment_status")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStatesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="securityPolicyDeploymentId")
    def security_policy_deployment_id(self) -> _builtins.str:
        """
        The OCID of the security policy deployment associated.
        """
        return pulumi.get(self, "security_policy_deployment_id")

    @_builtins.property
    @pulumi.getter(name="securityPolicyEntryId")
    def security_policy_entry_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the security policy entry type associated.
        """
        return pulumi.get(self, "security_policy_entry_id")

    @_builtins.property
    @pulumi.getter(name="securityPolicyEntryStateCollections")
    def security_policy_entry_state_collections(self) -> Sequence['outputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStatesSecurityPolicyEntryStateCollectionResult']:
        """
        The list of security_policy_entry_state_collection.
        """
        return pulumi.get(self, "security_policy_entry_state_collections")


class AwaitableGetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult(GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult(
            deployment_status=self.deployment_status,
            filters=self.filters,
            id=self.id,
            security_policy_deployment_id=self.security_policy_deployment_id,
            security_policy_entry_id=self.security_policy_entry_id,
            security_policy_entry_state_collections=self.security_policy_entry_state_collections)


def get_security_policy_deployment_security_policy_entry_states(deployment_status: Optional[_builtins.str] = None,
                                                                filters: Optional[Sequence[Union['GetSecurityPolicyDeploymentSecurityPolicyEntryStatesFilterArgs', 'GetSecurityPolicyDeploymentSecurityPolicyEntryStatesFilterArgsDict']]] = None,
                                                                security_policy_deployment_id: Optional[_builtins.str] = None,
                                                                security_policy_entry_id: Optional[_builtins.str] = None,
                                                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult:
    """
    This data source provides the list of Security Policy Deployment Security Policy Entry States in Oracle Cloud Infrastructure Data Safe service.

    Retrieves a list of all security policy entry states in Data Safe.

    The ListSecurityPolicyEntryStates operation returns only the security policy entry states for the specified security policy entry.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_policy_deployment_security_policy_entry_states = oci.DataSafe.get_security_policy_deployment_security_policy_entry_states(security_policy_deployment_id=test_security_policy_deployment["id"],
        deployment_status=security_policy_deployment_security_policy_entry_state_deployment_status,
        security_policy_entry_id=test_security_policy_entry["id"])
    ```


    :param _builtins.str deployment_status: The current state of the security policy deployment.
    :param _builtins.str security_policy_deployment_id: The OCID of the security policy deployment resource.
    :param _builtins.str security_policy_entry_id: An optional filter to return only resources that match the specified security policy entry OCID.
    """
    __args__ = dict()
    __args__['deploymentStatus'] = deployment_status
    __args__['filters'] = filters
    __args__['securityPolicyDeploymentId'] = security_policy_deployment_id
    __args__['securityPolicyEntryId'] = security_policy_entry_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getSecurityPolicyDeploymentSecurityPolicyEntryStates:getSecurityPolicyDeploymentSecurityPolicyEntryStates', __args__, opts=opts, typ=GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult).value

    return AwaitableGetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult(
        deployment_status=pulumi.get(__ret__, 'deployment_status'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        security_policy_deployment_id=pulumi.get(__ret__, 'security_policy_deployment_id'),
        security_policy_entry_id=pulumi.get(__ret__, 'security_policy_entry_id'),
        security_policy_entry_state_collections=pulumi.get(__ret__, 'security_policy_entry_state_collections'))
def get_security_policy_deployment_security_policy_entry_states_output(deployment_status: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                                       filters: Optional[pulumi.Input[Optional[Sequence[Union['GetSecurityPolicyDeploymentSecurityPolicyEntryStatesFilterArgs', 'GetSecurityPolicyDeploymentSecurityPolicyEntryStatesFilterArgsDict']]]]] = None,
                                                                       security_policy_deployment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                                       security_policy_entry_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                                       opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult]:
    """
    This data source provides the list of Security Policy Deployment Security Policy Entry States in Oracle Cloud Infrastructure Data Safe service.

    Retrieves a list of all security policy entry states in Data Safe.

    The ListSecurityPolicyEntryStates operation returns only the security policy entry states for the specified security policy entry.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_policy_deployment_security_policy_entry_states = oci.DataSafe.get_security_policy_deployment_security_policy_entry_states(security_policy_deployment_id=test_security_policy_deployment["id"],
        deployment_status=security_policy_deployment_security_policy_entry_state_deployment_status,
        security_policy_entry_id=test_security_policy_entry["id"])
    ```


    :param _builtins.str deployment_status: The current state of the security policy deployment.
    :param _builtins.str security_policy_deployment_id: The OCID of the security policy deployment resource.
    :param _builtins.str security_policy_entry_id: An optional filter to return only resources that match the specified security policy entry OCID.
    """
    __args__ = dict()
    __args__['deploymentStatus'] = deployment_status
    __args__['filters'] = filters
    __args__['securityPolicyDeploymentId'] = security_policy_deployment_id
    __args__['securityPolicyEntryId'] = security_policy_entry_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataSafe/getSecurityPolicyDeploymentSecurityPolicyEntryStates:getSecurityPolicyDeploymentSecurityPolicyEntryStates', __args__, opts=opts, typ=GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult)
    return __ret__.apply(lambda __response__: GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult(
        deployment_status=pulumi.get(__response__, 'deployment_status'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        security_policy_deployment_id=pulumi.get(__response__, 'security_policy_deployment_id'),
        security_policy_entry_id=pulumi.get(__response__, 'security_policy_entry_id'),
        security_policy_entry_state_collections=pulumi.get(__response__, 'security_policy_entry_state_collections')))
