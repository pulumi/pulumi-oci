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

__all__ = [
    'GetLifecycleEnvironmentResult',
    'AwaitableGetLifecycleEnvironmentResult',
    'get_lifecycle_environment',
    'get_lifecycle_environment_output',
]

@pulumi.output_type
class GetLifecycleEnvironmentResult:
    """
    A collection of values returned by getLifecycleEnvironment.
    """
    def __init__(__self__, arch_type=None, compartment_id=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, id=None, lifecycle_environment_id=None, managed_instance_ids=None, os_family=None, stages=None, state=None, system_tags=None, time_created=None, time_modified=None, vendor_name=None):
        if arch_type and not isinstance(arch_type, str):
            raise TypeError("Expected argument 'arch_type' to be a str")
        pulumi.set(__self__, "arch_type", arch_type)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_environment_id and not isinstance(lifecycle_environment_id, str):
            raise TypeError("Expected argument 'lifecycle_environment_id' to be a str")
        pulumi.set(__self__, "lifecycle_environment_id", lifecycle_environment_id)
        if managed_instance_ids and not isinstance(managed_instance_ids, list):
            raise TypeError("Expected argument 'managed_instance_ids' to be a list")
        pulumi.set(__self__, "managed_instance_ids", managed_instance_ids)
        if os_family and not isinstance(os_family, str):
            raise TypeError("Expected argument 'os_family' to be a str")
        pulumi.set(__self__, "os_family", os_family)
        if stages and not isinstance(stages, list):
            raise TypeError("Expected argument 'stages' to be a list")
        pulumi.set(__self__, "stages", stages)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_modified and not isinstance(time_modified, str):
            raise TypeError("Expected argument 'time_modified' to be a str")
        pulumi.set(__self__, "time_modified", time_modified)
        if vendor_name and not isinstance(vendor_name, str):
            raise TypeError("Expected argument 'vendor_name' to be a str")
        pulumi.set(__self__, "vendor_name", vendor_name)

    @property
    @pulumi.getter(name="archType")
    def arch_type(self) -> str:
        """
        The CPU architecture of the target instances.
        """
        return pulumi.get(self, "arch_type")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the tenancy containing the lifecycle stage.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Software source description.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        Software source name.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The OCID of the software source.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lifecycleEnvironmentId")
    def lifecycle_environment_id(self) -> str:
        """
        The OCID of the lifecycle environment for the lifecycle stage.
        """
        return pulumi.get(self, "lifecycle_environment_id")

    @property
    @pulumi.getter(name="managedInstanceIds")
    def managed_instance_ids(self) -> Sequence['outputs.GetLifecycleEnvironmentManagedInstanceIdResult']:
        """
        The list of managed instances specified lifecycle stage.
        """
        return pulumi.get(self, "managed_instance_ids")

    @property
    @pulumi.getter(name="osFamily")
    def os_family(self) -> str:
        """
        The operating system type of the target instances.
        """
        return pulumi.get(self, "os_family")

    @property
    @pulumi.getter
    def stages(self) -> Sequence['outputs.GetLifecycleEnvironmentStageResult']:
        """
        User specified list of lifecycle stages to be created for the lifecycle environment.
        """
        return pulumi.get(self, "stages")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the lifecycle environment.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the lifecycle environment was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeModified")
    def time_modified(self) -> str:
        """
        The time the lifecycle environment was last modified. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_modified")

    @property
    @pulumi.getter(name="vendorName")
    def vendor_name(self) -> str:
        """
        The software source vendor name.
        """
        return pulumi.get(self, "vendor_name")


class AwaitableGetLifecycleEnvironmentResult(GetLifecycleEnvironmentResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetLifecycleEnvironmentResult(
            arch_type=self.arch_type,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_environment_id=self.lifecycle_environment_id,
            managed_instance_ids=self.managed_instance_ids,
            os_family=self.os_family,
            stages=self.stages,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_modified=self.time_modified,
            vendor_name=self.vendor_name)


def get_lifecycle_environment(lifecycle_environment_id: Optional[str] = None,
                              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetLifecycleEnvironmentResult:
    """
    This data source provides details about a specific Lifecycle Environment resource in Oracle Cloud Infrastructure Os Management Hub service.

    Gets information about the specified lifecycle environment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_lifecycle_environment = oci.OsManagementHub.get_lifecycle_environment(lifecycle_environment_id=oci_os_management_hub_lifecycle_environment["test_lifecycle_environment"]["id"])
    ```


    :param str lifecycle_environment_id: The OCID of the lifecycle environment.
    """
    __args__ = dict()
    __args__['lifecycleEnvironmentId'] = lifecycle_environment_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:OsManagementHub/getLifecycleEnvironment:getLifecycleEnvironment', __args__, opts=opts, typ=GetLifecycleEnvironmentResult).value

    return AwaitableGetLifecycleEnvironmentResult(
        arch_type=pulumi.get(__ret__, 'arch_type'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_environment_id=pulumi.get(__ret__, 'lifecycle_environment_id'),
        managed_instance_ids=pulumi.get(__ret__, 'managed_instance_ids'),
        os_family=pulumi.get(__ret__, 'os_family'),
        stages=pulumi.get(__ret__, 'stages'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_modified=pulumi.get(__ret__, 'time_modified'),
        vendor_name=pulumi.get(__ret__, 'vendor_name'))


@_utilities.lift_output_func(get_lifecycle_environment)
def get_lifecycle_environment_output(lifecycle_environment_id: Optional[pulumi.Input[str]] = None,
                                     opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetLifecycleEnvironmentResult]:
    """
    This data source provides details about a specific Lifecycle Environment resource in Oracle Cloud Infrastructure Os Management Hub service.

    Gets information about the specified lifecycle environment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_lifecycle_environment = oci.OsManagementHub.get_lifecycle_environment(lifecycle_environment_id=oci_os_management_hub_lifecycle_environment["test_lifecycle_environment"]["id"])
    ```


    :param str lifecycle_environment_id: The OCID of the lifecycle environment.
    """
    ...