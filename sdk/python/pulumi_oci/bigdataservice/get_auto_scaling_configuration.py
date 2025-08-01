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
    'GetAutoScalingConfigurationResult',
    'AwaitableGetAutoScalingConfigurationResult',
    'get_auto_scaling_configuration',
    'get_auto_scaling_configuration_output',
]

@pulumi.output_type
class GetAutoScalingConfigurationResult:
    """
    A collection of values returned by getAutoScalingConfiguration.
    """
    def __init__(__self__, auto_scaling_configuration_id=None, bds_instance_id=None, cluster_admin_password=None, display_name=None, id=None, is_enabled=None, node_type=None, policies=None, policy_details=None, state=None, time_created=None, time_updated=None):
        if auto_scaling_configuration_id and not isinstance(auto_scaling_configuration_id, str):
            raise TypeError("Expected argument 'auto_scaling_configuration_id' to be a str")
        pulumi.set(__self__, "auto_scaling_configuration_id", auto_scaling_configuration_id)
        if bds_instance_id and not isinstance(bds_instance_id, str):
            raise TypeError("Expected argument 'bds_instance_id' to be a str")
        pulumi.set(__self__, "bds_instance_id", bds_instance_id)
        if cluster_admin_password and not isinstance(cluster_admin_password, str):
            raise TypeError("Expected argument 'cluster_admin_password' to be a str")
        pulumi.set(__self__, "cluster_admin_password", cluster_admin_password)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_enabled and not isinstance(is_enabled, bool):
            raise TypeError("Expected argument 'is_enabled' to be a bool")
        pulumi.set(__self__, "is_enabled", is_enabled)
        if node_type and not isinstance(node_type, str):
            raise TypeError("Expected argument 'node_type' to be a str")
        pulumi.set(__self__, "node_type", node_type)
        if policies and not isinstance(policies, list):
            raise TypeError("Expected argument 'policies' to be a list")
        pulumi.set(__self__, "policies", policies)
        if policy_details and not isinstance(policy_details, list):
            raise TypeError("Expected argument 'policy_details' to be a list")
        pulumi.set(__self__, "policy_details", policy_details)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter(name="autoScalingConfigurationId")
    def auto_scaling_configuration_id(self) -> _builtins.str:
        return pulumi.get(self, "auto_scaling_configuration_id")

    @_builtins.property
    @pulumi.getter(name="bdsInstanceId")
    def bds_instance_id(self) -> _builtins.str:
        return pulumi.get(self, "bds_instance_id")

    @_builtins.property
    @pulumi.getter(name="clusterAdminPassword")
    def cluster_admin_password(self) -> _builtins.str:
        return pulumi.get(self, "cluster_admin_password")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly name. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The unique identifier for the autoscale configuration.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isEnabled")
    def is_enabled(self) -> _builtins.bool:
        return pulumi.get(self, "is_enabled")

    @_builtins.property
    @pulumi.getter(name="nodeType")
    def node_type(self) -> _builtins.str:
        """
        A node type that is managed by an autoscale configuration. The only supported types are WORKER, COMPUTE_ONLY_WORKER, KAFKA_BROKER.
        """
        return pulumi.get(self, "node_type")

    @_builtins.property
    @pulumi.getter
    def policies(self) -> Sequence['outputs.GetAutoScalingConfigurationPolicyResult']:
        """
        This model for autoscaling policy is deprecated and not supported for ODH clusters. Use the `AutoScalePolicyDetails` model to manage autoscale policy details for ODH clusters.
        """
        return pulumi.get(self, "policies")

    @_builtins.property
    @pulumi.getter(name="policyDetails")
    def policy_details(self) -> Sequence['outputs.GetAutoScalingConfigurationPolicyDetailResult']:
        """
        Details of an autoscale policy.
        """
        return pulumi.get(self, "policy_details")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The state of the autoscale configuration.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The time the cluster was created, shown as an RFC 3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The time the autoscale configuration was updated, shown as an RFC 3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetAutoScalingConfigurationResult(GetAutoScalingConfigurationResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAutoScalingConfigurationResult(
            auto_scaling_configuration_id=self.auto_scaling_configuration_id,
            bds_instance_id=self.bds_instance_id,
            cluster_admin_password=self.cluster_admin_password,
            display_name=self.display_name,
            id=self.id,
            is_enabled=self.is_enabled,
            node_type=self.node_type,
            policies=self.policies,
            policy_details=self.policy_details,
            state=self.state,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_auto_scaling_configuration(auto_scaling_configuration_id: Optional[_builtins.str] = None,
                                   bds_instance_id: Optional[_builtins.str] = None,
                                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAutoScalingConfigurationResult:
    """
    This data source provides details about a specific Auto Scaling Configuration resource in Oracle Cloud Infrastructure Big Data Service service.

    Returns details of the autoscale configuration identified by the given ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_auto_scaling_configuration = oci.BigDataService.get_auto_scaling_configuration(auto_scaling_configuration_id=test_auto_scaling_configuration_oci_autoscaling_auto_scaling_configuration["id"],
        bds_instance_id=test_bds_instance["id"])
    ```


    :param _builtins.str auto_scaling_configuration_id: Unique Oracle-assigned identifier of the autoscale configuration.
    :param _builtins.str bds_instance_id: The OCID of the cluster.
    """
    __args__ = dict()
    __args__['autoScalingConfigurationId'] = auto_scaling_configuration_id
    __args__['bdsInstanceId'] = bds_instance_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:BigDataService/getAutoScalingConfiguration:getAutoScalingConfiguration', __args__, opts=opts, typ=GetAutoScalingConfigurationResult).value

    return AwaitableGetAutoScalingConfigurationResult(
        auto_scaling_configuration_id=pulumi.get(__ret__, 'auto_scaling_configuration_id'),
        bds_instance_id=pulumi.get(__ret__, 'bds_instance_id'),
        cluster_admin_password=pulumi.get(__ret__, 'cluster_admin_password'),
        display_name=pulumi.get(__ret__, 'display_name'),
        id=pulumi.get(__ret__, 'id'),
        is_enabled=pulumi.get(__ret__, 'is_enabled'),
        node_type=pulumi.get(__ret__, 'node_type'),
        policies=pulumi.get(__ret__, 'policies'),
        policy_details=pulumi.get(__ret__, 'policy_details'),
        state=pulumi.get(__ret__, 'state'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_auto_scaling_configuration_output(auto_scaling_configuration_id: Optional[pulumi.Input[_builtins.str]] = None,
                                          bds_instance_id: Optional[pulumi.Input[_builtins.str]] = None,
                                          opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetAutoScalingConfigurationResult]:
    """
    This data source provides details about a specific Auto Scaling Configuration resource in Oracle Cloud Infrastructure Big Data Service service.

    Returns details of the autoscale configuration identified by the given ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_auto_scaling_configuration = oci.BigDataService.get_auto_scaling_configuration(auto_scaling_configuration_id=test_auto_scaling_configuration_oci_autoscaling_auto_scaling_configuration["id"],
        bds_instance_id=test_bds_instance["id"])
    ```


    :param _builtins.str auto_scaling_configuration_id: Unique Oracle-assigned identifier of the autoscale configuration.
    :param _builtins.str bds_instance_id: The OCID of the cluster.
    """
    __args__ = dict()
    __args__['autoScalingConfigurationId'] = auto_scaling_configuration_id
    __args__['bdsInstanceId'] = bds_instance_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:BigDataService/getAutoScalingConfiguration:getAutoScalingConfiguration', __args__, opts=opts, typ=GetAutoScalingConfigurationResult)
    return __ret__.apply(lambda __response__: GetAutoScalingConfigurationResult(
        auto_scaling_configuration_id=pulumi.get(__response__, 'auto_scaling_configuration_id'),
        bds_instance_id=pulumi.get(__response__, 'bds_instance_id'),
        cluster_admin_password=pulumi.get(__response__, 'cluster_admin_password'),
        display_name=pulumi.get(__response__, 'display_name'),
        id=pulumi.get(__response__, 'id'),
        is_enabled=pulumi.get(__response__, 'is_enabled'),
        node_type=pulumi.get(__response__, 'node_type'),
        policies=pulumi.get(__response__, 'policies'),
        policy_details=pulumi.get(__response__, 'policy_details'),
        state=pulumi.get(__response__, 'state'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
