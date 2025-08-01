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
    'GetDeployEnvironmentResult',
    'AwaitableGetDeployEnvironmentResult',
    'get_deploy_environment',
    'get_deploy_environment_output',
]

@pulumi.output_type
class GetDeployEnvironmentResult:
    """
    A collection of values returned by getDeployEnvironment.
    """
    def __init__(__self__, cluster_id=None, compartment_id=None, compute_instance_group_selectors=None, defined_tags=None, deploy_environment_id=None, deploy_environment_type=None, description=None, display_name=None, freeform_tags=None, function_id=None, id=None, lifecycle_details=None, network_channels=None, project_id=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if cluster_id and not isinstance(cluster_id, str):
            raise TypeError("Expected argument 'cluster_id' to be a str")
        pulumi.set(__self__, "cluster_id", cluster_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compute_instance_group_selectors and not isinstance(compute_instance_group_selectors, list):
            raise TypeError("Expected argument 'compute_instance_group_selectors' to be a list")
        pulumi.set(__self__, "compute_instance_group_selectors", compute_instance_group_selectors)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if deploy_environment_id and not isinstance(deploy_environment_id, str):
            raise TypeError("Expected argument 'deploy_environment_id' to be a str")
        pulumi.set(__self__, "deploy_environment_id", deploy_environment_id)
        if deploy_environment_type and not isinstance(deploy_environment_type, str):
            raise TypeError("Expected argument 'deploy_environment_type' to be a str")
        pulumi.set(__self__, "deploy_environment_type", deploy_environment_type)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if function_id and not isinstance(function_id, str):
            raise TypeError("Expected argument 'function_id' to be a str")
        pulumi.set(__self__, "function_id", function_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if network_channels and not isinstance(network_channels, list):
            raise TypeError("Expected argument 'network_channels' to be a list")
        pulumi.set(__self__, "network_channels", network_channels)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter(name="clusterId")
    def cluster_id(self) -> _builtins.str:
        """
        The OCID of the Kubernetes cluster.
        """
        return pulumi.get(self, "cluster_id")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of a compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="computeInstanceGroupSelectors")
    def compute_instance_group_selectors(self) -> Sequence['outputs.GetDeployEnvironmentComputeInstanceGroupSelectorResult']:
        """
        A collection of selectors. The combination of instances matching the selectors are included in the instance group.
        """
        return pulumi.get(self, "compute_instance_group_selectors")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="deployEnvironmentId")
    def deploy_environment_id(self) -> _builtins.str:
        return pulumi.get(self, "deploy_environment_id")

    @_builtins.property
    @pulumi.getter(name="deployEnvironmentType")
    def deploy_environment_type(self) -> _builtins.str:
        """
        Deployment environment type.
        """
        return pulumi.get(self, "deploy_environment_type")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        Optional description about the deployment environment.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        Deployment environment display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter(name="functionId")
    def function_id(self) -> _builtins.str:
        """
        The OCID of the Function.
        """
        return pulumi.get(self, "function_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="networkChannels")
    def network_channels(self) -> Sequence['outputs.GetDeployEnvironmentNetworkChannelResult']:
        """
        Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer's private network.
        """
        return pulumi.get(self, "network_channels")

    @_builtins.property
    @pulumi.getter(name="projectId")
    def project_id(self) -> _builtins.str:
        """
        The OCID of a project.
        """
        return pulumi.get(self, "project_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the deployment environment.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        Time the deployment environment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        Time the deployment environment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetDeployEnvironmentResult(GetDeployEnvironmentResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDeployEnvironmentResult(
            cluster_id=self.cluster_id,
            compartment_id=self.compartment_id,
            compute_instance_group_selectors=self.compute_instance_group_selectors,
            defined_tags=self.defined_tags,
            deploy_environment_id=self.deploy_environment_id,
            deploy_environment_type=self.deploy_environment_type,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            function_id=self.function_id,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            network_channels=self.network_channels,
            project_id=self.project_id,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_deploy_environment(deploy_environment_id: Optional[_builtins.str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDeployEnvironmentResult:
    """
    This data source provides details about a specific Deploy Environment resource in Oracle Cloud Infrastructure Devops service.

    Retrieves a deployment environment by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deploy_environment = oci.DevOps.get_deploy_environment(deploy_environment_id=test_deploy_environment_oci_devops_deploy_environment["id"])
    ```


    :param _builtins.str deploy_environment_id: Unique environment identifier.
    """
    __args__ = dict()
    __args__['deployEnvironmentId'] = deploy_environment_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DevOps/getDeployEnvironment:getDeployEnvironment', __args__, opts=opts, typ=GetDeployEnvironmentResult).value

    return AwaitableGetDeployEnvironmentResult(
        cluster_id=pulumi.get(__ret__, 'cluster_id'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compute_instance_group_selectors=pulumi.get(__ret__, 'compute_instance_group_selectors'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        deploy_environment_id=pulumi.get(__ret__, 'deploy_environment_id'),
        deploy_environment_type=pulumi.get(__ret__, 'deploy_environment_type'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        function_id=pulumi.get(__ret__, 'function_id'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        network_channels=pulumi.get(__ret__, 'network_channels'),
        project_id=pulumi.get(__ret__, 'project_id'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_deploy_environment_output(deploy_environment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                  opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDeployEnvironmentResult]:
    """
    This data source provides details about a specific Deploy Environment resource in Oracle Cloud Infrastructure Devops service.

    Retrieves a deployment environment by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deploy_environment = oci.DevOps.get_deploy_environment(deploy_environment_id=test_deploy_environment_oci_devops_deploy_environment["id"])
    ```


    :param _builtins.str deploy_environment_id: Unique environment identifier.
    """
    __args__ = dict()
    __args__['deployEnvironmentId'] = deploy_environment_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DevOps/getDeployEnvironment:getDeployEnvironment', __args__, opts=opts, typ=GetDeployEnvironmentResult)
    return __ret__.apply(lambda __response__: GetDeployEnvironmentResult(
        cluster_id=pulumi.get(__response__, 'cluster_id'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        compute_instance_group_selectors=pulumi.get(__response__, 'compute_instance_group_selectors'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        deploy_environment_id=pulumi.get(__response__, 'deploy_environment_id'),
        deploy_environment_type=pulumi.get(__response__, 'deploy_environment_type'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        function_id=pulumi.get(__response__, 'function_id'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        network_channels=pulumi.get(__response__, 'network_channels'),
        project_id=pulumi.get(__response__, 'project_id'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
