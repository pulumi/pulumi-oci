# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetSecurityPolicyDeploymentsResult',
    'AwaitableGetSecurityPolicyDeploymentsResult',
    'get_security_policy_deployments',
    'get_security_policy_deployments_output',
]

@pulumi.output_type
class GetSecurityPolicyDeploymentsResult:
    """
    A collection of values returned by getSecurityPolicyDeployments.
    """
    def __init__(__self__, access_level=None, compartment_id=None, compartment_id_in_subtree=None, display_name=None, filters=None, id=None, security_policy_deployment_collections=None, security_policy_deployment_id=None, security_policy_id=None, state=None, target_id=None):
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
        if security_policy_deployment_collections and not isinstance(security_policy_deployment_collections, list):
            raise TypeError("Expected argument 'security_policy_deployment_collections' to be a list")
        pulumi.set(__self__, "security_policy_deployment_collections", security_policy_deployment_collections)
        if security_policy_deployment_id and not isinstance(security_policy_deployment_id, str):
            raise TypeError("Expected argument 'security_policy_deployment_id' to be a str")
        pulumi.set(__self__, "security_policy_deployment_id", security_policy_deployment_id)
        if security_policy_id and not isinstance(security_policy_id, str):
            raise TypeError("Expected argument 'security_policy_id' to be a str")
        pulumi.set(__self__, "security_policy_id", security_policy_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if target_id and not isinstance(target_id, str):
            raise TypeError("Expected argument 'target_id' to be a str")
        pulumi.set(__self__, "target_id", target_id)

    @property
    @pulumi.getter(name="accessLevel")
    def access_level(self) -> Optional[str]:
        return pulumi.get(self, "access_level")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment containing the security policy deployment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        The display name of the security policy deployment.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSecurityPolicyDeploymentsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="securityPolicyDeploymentCollections")
    def security_policy_deployment_collections(self) -> Sequence['outputs.GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollectionResult']:
        """
        The list of security_policy_deployment_collection.
        """
        return pulumi.get(self, "security_policy_deployment_collections")

    @property
    @pulumi.getter(name="securityPolicyDeploymentId")
    def security_policy_deployment_id(self) -> Optional[str]:
        return pulumi.get(self, "security_policy_deployment_id")

    @property
    @pulumi.getter(name="securityPolicyId")
    def security_policy_id(self) -> Optional[str]:
        """
        The OCID of the security policy corresponding to the security policy deployment.
        """
        return pulumi.get(self, "security_policy_id")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the security policy deployment.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="targetId")
    def target_id(self) -> Optional[str]:
        """
        The OCID of the target where the security policy is deployed.
        """
        return pulumi.get(self, "target_id")


class AwaitableGetSecurityPolicyDeploymentsResult(GetSecurityPolicyDeploymentsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSecurityPolicyDeploymentsResult(
            access_level=self.access_level,
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            security_policy_deployment_collections=self.security_policy_deployment_collections,
            security_policy_deployment_id=self.security_policy_deployment_id,
            security_policy_id=self.security_policy_id,
            state=self.state,
            target_id=self.target_id)


def get_security_policy_deployments(access_level: Optional[str] = None,
                                    compartment_id: Optional[str] = None,
                                    compartment_id_in_subtree: Optional[bool] = None,
                                    display_name: Optional[str] = None,
                                    filters: Optional[Sequence[pulumi.InputType['GetSecurityPolicyDeploymentsFilterArgs']]] = None,
                                    security_policy_deployment_id: Optional[str] = None,
                                    security_policy_id: Optional[str] = None,
                                    state: Optional[str] = None,
                                    target_id: Optional[str] = None,
                                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSecurityPolicyDeploymentsResult:
    """
    This data source provides the list of Security Policy Deployments in Oracle Cloud Infrastructure Data Safe service.

    Retrieves a list of all security policy deployments in Data Safe.

    The ListSecurityPolicyDeployments operation returns only the security policy deployments in the specified `compartmentId`.

    The parameter `accessLevel` specifies whether to return only those compartments for which the
    requestor has INSPECT permissions on at least one resource directly
    or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
    Principal doesn't have access to even one of the child compartments. This is valid only when
    `compartmentIdInSubtree` is set to `true`.

    The parameter `compartmentIdInSubtree` applies when you perform ListSecurityPolicyDeployments on the
    `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
    To get a full list of all compartments and subcompartments in the tenancy (root compartment),
    set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_policy_deployments = oci.DataSafe.get_security_policy_deployments(compartment_id=var["compartment_id"],
        access_level=var["security_policy_deployment_access_level"],
        compartment_id_in_subtree=var["security_policy_deployment_compartment_id_in_subtree"],
        display_name=var["security_policy_deployment_display_name"],
        security_policy_deployment_id=oci_data_safe_security_policy_deployment["test_security_policy_deployment"]["id"],
        security_policy_id=oci_data_safe_security_policy["test_security_policy"]["id"],
        state=var["security_policy_deployment_state"],
        target_id=oci_cloud_guard_target["test_target"]["id"])
    ```


    :param str access_level: Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
    :param str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param str display_name: A filter to return only resources that match the specified display name.
    :param str security_policy_deployment_id: An optional filter to return only resources that match the specified OCID of the security policy deployment resource.
    :param str security_policy_id: An optional filter to return only resources that match the specified OCID of the security policy resource.
    :param str state: The current state of the security policy deployment.
    :param str target_id: A filter to return only items related to a specific target OCID.
    """
    __args__ = dict()
    __args__['accessLevel'] = access_level
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['securityPolicyDeploymentId'] = security_policy_deployment_id
    __args__['securityPolicyId'] = security_policy_id
    __args__['state'] = state
    __args__['targetId'] = target_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getSecurityPolicyDeployments:getSecurityPolicyDeployments', __args__, opts=opts, typ=GetSecurityPolicyDeploymentsResult).value

    return AwaitableGetSecurityPolicyDeploymentsResult(
        access_level=pulumi.get(__ret__, 'access_level'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compartment_id_in_subtree=pulumi.get(__ret__, 'compartment_id_in_subtree'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        security_policy_deployment_collections=pulumi.get(__ret__, 'security_policy_deployment_collections'),
        security_policy_deployment_id=pulumi.get(__ret__, 'security_policy_deployment_id'),
        security_policy_id=pulumi.get(__ret__, 'security_policy_id'),
        state=pulumi.get(__ret__, 'state'),
        target_id=pulumi.get(__ret__, 'target_id'))


@_utilities.lift_output_func(get_security_policy_deployments)
def get_security_policy_deployments_output(access_level: Optional[pulumi.Input[Optional[str]]] = None,
                                           compartment_id: Optional[pulumi.Input[str]] = None,
                                           compartment_id_in_subtree: Optional[pulumi.Input[Optional[bool]]] = None,
                                           display_name: Optional[pulumi.Input[Optional[str]]] = None,
                                           filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetSecurityPolicyDeploymentsFilterArgs']]]]] = None,
                                           security_policy_deployment_id: Optional[pulumi.Input[Optional[str]]] = None,
                                           security_policy_id: Optional[pulumi.Input[Optional[str]]] = None,
                                           state: Optional[pulumi.Input[Optional[str]]] = None,
                                           target_id: Optional[pulumi.Input[Optional[str]]] = None,
                                           opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetSecurityPolicyDeploymentsResult]:
    """
    This data source provides the list of Security Policy Deployments in Oracle Cloud Infrastructure Data Safe service.

    Retrieves a list of all security policy deployments in Data Safe.

    The ListSecurityPolicyDeployments operation returns only the security policy deployments in the specified `compartmentId`.

    The parameter `accessLevel` specifies whether to return only those compartments for which the
    requestor has INSPECT permissions on at least one resource directly
    or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
    Principal doesn't have access to even one of the child compartments. This is valid only when
    `compartmentIdInSubtree` is set to `true`.

    The parameter `compartmentIdInSubtree` applies when you perform ListSecurityPolicyDeployments on the
    `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
    To get a full list of all compartments and subcompartments in the tenancy (root compartment),
    set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_policy_deployments = oci.DataSafe.get_security_policy_deployments(compartment_id=var["compartment_id"],
        access_level=var["security_policy_deployment_access_level"],
        compartment_id_in_subtree=var["security_policy_deployment_compartment_id_in_subtree"],
        display_name=var["security_policy_deployment_display_name"],
        security_policy_deployment_id=oci_data_safe_security_policy_deployment["test_security_policy_deployment"]["id"],
        security_policy_id=oci_data_safe_security_policy["test_security_policy"]["id"],
        state=var["security_policy_deployment_state"],
        target_id=oci_cloud_guard_target["test_target"]["id"])
    ```


    :param str access_level: Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
    :param str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param str display_name: A filter to return only resources that match the specified display name.
    :param str security_policy_deployment_id: An optional filter to return only resources that match the specified OCID of the security policy deployment resource.
    :param str security_policy_id: An optional filter to return only resources that match the specified OCID of the security policy resource.
    :param str state: The current state of the security policy deployment.
    :param str target_id: A filter to return only items related to a specific target OCID.
    """
    ...