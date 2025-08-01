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

__all__ = [
    'GetSecurityPolicyDeploymentSecurityPolicyEntryStateResult',
    'AwaitableGetSecurityPolicyDeploymentSecurityPolicyEntryStateResult',
    'get_security_policy_deployment_security_policy_entry_state',
    'get_security_policy_deployment_security_policy_entry_state_output',
]

@pulumi.output_type
class GetSecurityPolicyDeploymentSecurityPolicyEntryStateResult:
    """
    A collection of values returned by getSecurityPolicyDeploymentSecurityPolicyEntryState.
    """
    def __init__(__self__, deployment_status=None, entry_details=None, id=None, security_policy_deployment_id=None, security_policy_entry_id=None, security_policy_entry_state_id=None):
        if deployment_status and not isinstance(deployment_status, str):
            raise TypeError("Expected argument 'deployment_status' to be a str")
        pulumi.set(__self__, "deployment_status", deployment_status)
        if entry_details and not isinstance(entry_details, list):
            raise TypeError("Expected argument 'entry_details' to be a list")
        pulumi.set(__self__, "entry_details", entry_details)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if security_policy_deployment_id and not isinstance(security_policy_deployment_id, str):
            raise TypeError("Expected argument 'security_policy_deployment_id' to be a str")
        pulumi.set(__self__, "security_policy_deployment_id", security_policy_deployment_id)
        if security_policy_entry_id and not isinstance(security_policy_entry_id, str):
            raise TypeError("Expected argument 'security_policy_entry_id' to be a str")
        pulumi.set(__self__, "security_policy_entry_id", security_policy_entry_id)
        if security_policy_entry_state_id and not isinstance(security_policy_entry_state_id, str):
            raise TypeError("Expected argument 'security_policy_entry_state_id' to be a str")
        pulumi.set(__self__, "security_policy_entry_state_id", security_policy_entry_state_id)

    @_builtins.property
    @pulumi.getter(name="deploymentStatus")
    def deployment_status(self) -> _builtins.str:
        """
        The current deployment status of the security policy deployment and the security policy entry associated.
        """
        return pulumi.get(self, "deployment_status")

    @_builtins.property
    @pulumi.getter(name="entryDetails")
    def entry_details(self) -> Sequence['outputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStateEntryDetailResult']:
        """
        Details specific to the security policy entry.
        """
        return pulumi.get(self, "entry_details")

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
    def security_policy_entry_id(self) -> _builtins.str:
        """
        The OCID of the security policy entry type associated.
        """
        return pulumi.get(self, "security_policy_entry_id")

    @_builtins.property
    @pulumi.getter(name="securityPolicyEntryStateId")
    def security_policy_entry_state_id(self) -> _builtins.str:
        return pulumi.get(self, "security_policy_entry_state_id")


class AwaitableGetSecurityPolicyDeploymentSecurityPolicyEntryStateResult(GetSecurityPolicyDeploymentSecurityPolicyEntryStateResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSecurityPolicyDeploymentSecurityPolicyEntryStateResult(
            deployment_status=self.deployment_status,
            entry_details=self.entry_details,
            id=self.id,
            security_policy_deployment_id=self.security_policy_deployment_id,
            security_policy_entry_id=self.security_policy_entry_id,
            security_policy_entry_state_id=self.security_policy_entry_state_id)


def get_security_policy_deployment_security_policy_entry_state(security_policy_deployment_id: Optional[_builtins.str] = None,
                                                               security_policy_entry_state_id: Optional[_builtins.str] = None,
                                                               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSecurityPolicyDeploymentSecurityPolicyEntryStateResult:
    """
    This data source provides details about a specific Security Policy Deployment Security Policy Entry State resource in Oracle Cloud Infrastructure Data Safe service.

    Gets a security policy entity states by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_policy_deployment_security_policy_entry_state = oci.DataSafe.get_security_policy_deployment_security_policy_entry_state(security_policy_deployment_id=test_security_policy_deployment["id"],
        security_policy_entry_state_id=test_security_policy_entry_state["id"])
    ```


    :param _builtins.str security_policy_deployment_id: The OCID of the security policy deployment resource.
    :param _builtins.str security_policy_entry_state_id: Unique security policy entry state identifier. The unique id for a given security policy entry state can be obtained  from the list api by passing the OCID of the corresponding  security policy deployment resource as the query parameter.
    """
    __args__ = dict()
    __args__['securityPolicyDeploymentId'] = security_policy_deployment_id
    __args__['securityPolicyEntryStateId'] = security_policy_entry_state_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getSecurityPolicyDeploymentSecurityPolicyEntryState:getSecurityPolicyDeploymentSecurityPolicyEntryState', __args__, opts=opts, typ=GetSecurityPolicyDeploymentSecurityPolicyEntryStateResult).value

    return AwaitableGetSecurityPolicyDeploymentSecurityPolicyEntryStateResult(
        deployment_status=pulumi.get(__ret__, 'deployment_status'),
        entry_details=pulumi.get(__ret__, 'entry_details'),
        id=pulumi.get(__ret__, 'id'),
        security_policy_deployment_id=pulumi.get(__ret__, 'security_policy_deployment_id'),
        security_policy_entry_id=pulumi.get(__ret__, 'security_policy_entry_id'),
        security_policy_entry_state_id=pulumi.get(__ret__, 'security_policy_entry_state_id'))
def get_security_policy_deployment_security_policy_entry_state_output(security_policy_deployment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                                      security_policy_entry_state_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                                      opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetSecurityPolicyDeploymentSecurityPolicyEntryStateResult]:
    """
    This data source provides details about a specific Security Policy Deployment Security Policy Entry State resource in Oracle Cloud Infrastructure Data Safe service.

    Gets a security policy entity states by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_policy_deployment_security_policy_entry_state = oci.DataSafe.get_security_policy_deployment_security_policy_entry_state(security_policy_deployment_id=test_security_policy_deployment["id"],
        security_policy_entry_state_id=test_security_policy_entry_state["id"])
    ```


    :param _builtins.str security_policy_deployment_id: The OCID of the security policy deployment resource.
    :param _builtins.str security_policy_entry_state_id: Unique security policy entry state identifier. The unique id for a given security policy entry state can be obtained  from the list api by passing the OCID of the corresponding  security policy deployment resource as the query parameter.
    """
    __args__ = dict()
    __args__['securityPolicyDeploymentId'] = security_policy_deployment_id
    __args__['securityPolicyEntryStateId'] = security_policy_entry_state_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataSafe/getSecurityPolicyDeploymentSecurityPolicyEntryState:getSecurityPolicyDeploymentSecurityPolicyEntryState', __args__, opts=opts, typ=GetSecurityPolicyDeploymentSecurityPolicyEntryStateResult)
    return __ret__.apply(lambda __response__: GetSecurityPolicyDeploymentSecurityPolicyEntryStateResult(
        deployment_status=pulumi.get(__response__, 'deployment_status'),
        entry_details=pulumi.get(__response__, 'entry_details'),
        id=pulumi.get(__response__, 'id'),
        security_policy_deployment_id=pulumi.get(__response__, 'security_policy_deployment_id'),
        security_policy_entry_id=pulumi.get(__response__, 'security_policy_entry_id'),
        security_policy_entry_state_id=pulumi.get(__response__, 'security_policy_entry_state_id')))
