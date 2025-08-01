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

__all__ = ['CloudVmClusterIormConfigArgs', 'CloudVmClusterIormConfig']

@pulumi.input_type
class CloudVmClusterIormConfigArgs:
    def __init__(__self__, *,
                 cloud_vm_cluster_id: pulumi.Input[_builtins.str],
                 db_plans: pulumi.Input[Sequence[pulumi.Input['CloudVmClusterIormConfigDbPlanArgs']]],
                 objective: Optional[pulumi.Input[_builtins.str]] = None):
        """
        The set of arguments for constructing a CloudVmClusterIormConfig resource.
        :param pulumi.Input[_builtins.str] cloud_vm_cluster_id: The Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[Sequence[pulumi.Input['CloudVmClusterIormConfigDbPlanArgs']]] db_plans: (Updatable) Array of IORM Setting for all the database in this Cloud Vm Cluster
        :param pulumi.Input[_builtins.str] objective: (Updatable) Value for the IORM objective Default is "Auto"
        """
        pulumi.set(__self__, "cloud_vm_cluster_id", cloud_vm_cluster_id)
        pulumi.set(__self__, "db_plans", db_plans)
        if objective is not None:
            pulumi.set(__self__, "objective", objective)

    @_builtins.property
    @pulumi.getter(name="cloudVmClusterId")
    def cloud_vm_cluster_id(self) -> pulumi.Input[_builtins.str]:
        """
        The Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "cloud_vm_cluster_id")

    @cloud_vm_cluster_id.setter
    def cloud_vm_cluster_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "cloud_vm_cluster_id", value)

    @_builtins.property
    @pulumi.getter(name="dbPlans")
    def db_plans(self) -> pulumi.Input[Sequence[pulumi.Input['CloudVmClusterIormConfigDbPlanArgs']]]:
        """
        (Updatable) Array of IORM Setting for all the database in this Cloud Vm Cluster
        """
        return pulumi.get(self, "db_plans")

    @db_plans.setter
    def db_plans(self, value: pulumi.Input[Sequence[pulumi.Input['CloudVmClusterIormConfigDbPlanArgs']]]):
        pulumi.set(self, "db_plans", value)

    @_builtins.property
    @pulumi.getter
    def objective(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Value for the IORM objective Default is "Auto"
        """
        return pulumi.get(self, "objective")

    @objective.setter
    def objective(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "objective", value)


@pulumi.input_type
class _CloudVmClusterIormConfigState:
    def __init__(__self__, *,
                 cloud_vm_cluster_id: Optional[pulumi.Input[_builtins.str]] = None,
                 db_plans: Optional[pulumi.Input[Sequence[pulumi.Input['CloudVmClusterIormConfigDbPlanArgs']]]] = None,
                 lifecycle_details: Optional[pulumi.Input[_builtins.str]] = None,
                 objective: Optional[pulumi.Input[_builtins.str]] = None,
                 state: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering CloudVmClusterIormConfig resources.
        :param pulumi.Input[_builtins.str] cloud_vm_cluster_id: The Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[Sequence[pulumi.Input['CloudVmClusterIormConfigDbPlanArgs']]] db_plans: (Updatable) Array of IORM Setting for all the database in this Cloud Vm Cluster
        :param pulumi.Input[_builtins.str] lifecycle_details: Additional information about the current `lifecycleState`.
        :param pulumi.Input[_builtins.str] objective: (Updatable) Value for the IORM objective Default is "Auto"
        :param pulumi.Input[_builtins.str] state: The current state of IORM configuration for the Exadata DB system.
        """
        if cloud_vm_cluster_id is not None:
            pulumi.set(__self__, "cloud_vm_cluster_id", cloud_vm_cluster_id)
        if db_plans is not None:
            pulumi.set(__self__, "db_plans", db_plans)
        if lifecycle_details is not None:
            pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if objective is not None:
            pulumi.set(__self__, "objective", objective)
        if state is not None:
            pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="cloudVmClusterId")
    def cloud_vm_cluster_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "cloud_vm_cluster_id")

    @cloud_vm_cluster_id.setter
    def cloud_vm_cluster_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "cloud_vm_cluster_id", value)

    @_builtins.property
    @pulumi.getter(name="dbPlans")
    def db_plans(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['CloudVmClusterIormConfigDbPlanArgs']]]]:
        """
        (Updatable) Array of IORM Setting for all the database in this Cloud Vm Cluster
        """
        return pulumi.get(self, "db_plans")

    @db_plans.setter
    def db_plans(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['CloudVmClusterIormConfigDbPlanArgs']]]]):
        pulumi.set(self, "db_plans", value)

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Additional information about the current `lifecycleState`.
        """
        return pulumi.get(self, "lifecycle_details")

    @lifecycle_details.setter
    def lifecycle_details(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "lifecycle_details", value)

    @_builtins.property
    @pulumi.getter
    def objective(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Value for the IORM objective Default is "Auto"
        """
        return pulumi.get(self, "objective")

    @objective.setter
    def objective(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "objective", value)

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The current state of IORM configuration for the Exadata DB system.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "state", value)


@pulumi.type_token("oci:Database/cloudVmClusterIormConfig:CloudVmClusterIormConfig")
class CloudVmClusterIormConfig(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 cloud_vm_cluster_id: Optional[pulumi.Input[_builtins.str]] = None,
                 db_plans: Optional[pulumi.Input[Sequence[pulumi.Input[Union['CloudVmClusterIormConfigDbPlanArgs', 'CloudVmClusterIormConfigDbPlanArgsDict']]]]] = None,
                 objective: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Cloud Vm Cluster Iorm Config resource in Oracle Cloud Infrastructure Database service.

        Updates IORM settings for the specified Cloud Vm Cluster.

        The [UpdateCloudVmClusterIormConfig](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudVmCluster/UpdateCloudVmClusterIormConfig/) API is used for Cloud Vm Cluster.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_cloud_vm_cluster_iorm_config = oci.database.CloudVmClusterIormConfig("test_cloud_vm_cluster_iorm_config",
            db_plans=[{
                "db_name": cloud_vm_cluster_iorm_config_db_plans_db_name,
                "share": cloud_vm_cluster_iorm_config_db_plans_share,
            }],
            cloud_vm_cluster_id=test_cloud_vm_cluster["id"],
            objective="AUTO")
        ```

        ## Import

        CloudVmClusterIormConfigs can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:Database/cloudVmClusterIormConfig:CloudVmClusterIormConfig test_cloud_vm_cluster_iorm_config "cloudVmClusters/{cloudVmClusterId}/CloudVmClusterIormConfig"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] cloud_vm_cluster_id: The Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[Sequence[pulumi.Input[Union['CloudVmClusterIormConfigDbPlanArgs', 'CloudVmClusterIormConfigDbPlanArgsDict']]]] db_plans: (Updatable) Array of IORM Setting for all the database in this Cloud Vm Cluster
        :param pulumi.Input[_builtins.str] objective: (Updatable) Value for the IORM objective Default is "Auto"
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: CloudVmClusterIormConfigArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Cloud Vm Cluster Iorm Config resource in Oracle Cloud Infrastructure Database service.

        Updates IORM settings for the specified Cloud Vm Cluster.

        The [UpdateCloudVmClusterIormConfig](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudVmCluster/UpdateCloudVmClusterIormConfig/) API is used for Cloud Vm Cluster.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_cloud_vm_cluster_iorm_config = oci.database.CloudVmClusterIormConfig("test_cloud_vm_cluster_iorm_config",
            db_plans=[{
                "db_name": cloud_vm_cluster_iorm_config_db_plans_db_name,
                "share": cloud_vm_cluster_iorm_config_db_plans_share,
            }],
            cloud_vm_cluster_id=test_cloud_vm_cluster["id"],
            objective="AUTO")
        ```

        ## Import

        CloudVmClusterIormConfigs can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:Database/cloudVmClusterIormConfig:CloudVmClusterIormConfig test_cloud_vm_cluster_iorm_config "cloudVmClusters/{cloudVmClusterId}/CloudVmClusterIormConfig"
        ```

        :param str resource_name: The name of the resource.
        :param CloudVmClusterIormConfigArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(CloudVmClusterIormConfigArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 cloud_vm_cluster_id: Optional[pulumi.Input[_builtins.str]] = None,
                 db_plans: Optional[pulumi.Input[Sequence[pulumi.Input[Union['CloudVmClusterIormConfigDbPlanArgs', 'CloudVmClusterIormConfigDbPlanArgsDict']]]]] = None,
                 objective: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = CloudVmClusterIormConfigArgs.__new__(CloudVmClusterIormConfigArgs)

            if cloud_vm_cluster_id is None and not opts.urn:
                raise TypeError("Missing required property 'cloud_vm_cluster_id'")
            __props__.__dict__["cloud_vm_cluster_id"] = cloud_vm_cluster_id
            if db_plans is None and not opts.urn:
                raise TypeError("Missing required property 'db_plans'")
            __props__.__dict__["db_plans"] = db_plans
            __props__.__dict__["objective"] = objective
            __props__.__dict__["lifecycle_details"] = None
            __props__.__dict__["state"] = None
        super(CloudVmClusterIormConfig, __self__).__init__(
            'oci:Database/cloudVmClusterIormConfig:CloudVmClusterIormConfig',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            cloud_vm_cluster_id: Optional[pulumi.Input[_builtins.str]] = None,
            db_plans: Optional[pulumi.Input[Sequence[pulumi.Input[Union['CloudVmClusterIormConfigDbPlanArgs', 'CloudVmClusterIormConfigDbPlanArgsDict']]]]] = None,
            lifecycle_details: Optional[pulumi.Input[_builtins.str]] = None,
            objective: Optional[pulumi.Input[_builtins.str]] = None,
            state: Optional[pulumi.Input[_builtins.str]] = None) -> 'CloudVmClusterIormConfig':
        """
        Get an existing CloudVmClusterIormConfig resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] cloud_vm_cluster_id: The Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[Sequence[pulumi.Input[Union['CloudVmClusterIormConfigDbPlanArgs', 'CloudVmClusterIormConfigDbPlanArgsDict']]]] db_plans: (Updatable) Array of IORM Setting for all the database in this Cloud Vm Cluster
        :param pulumi.Input[_builtins.str] lifecycle_details: Additional information about the current `lifecycleState`.
        :param pulumi.Input[_builtins.str] objective: (Updatable) Value for the IORM objective Default is "Auto"
        :param pulumi.Input[_builtins.str] state: The current state of IORM configuration for the Exadata DB system.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _CloudVmClusterIormConfigState.__new__(_CloudVmClusterIormConfigState)

        __props__.__dict__["cloud_vm_cluster_id"] = cloud_vm_cluster_id
        __props__.__dict__["db_plans"] = db_plans
        __props__.__dict__["lifecycle_details"] = lifecycle_details
        __props__.__dict__["objective"] = objective
        __props__.__dict__["state"] = state
        return CloudVmClusterIormConfig(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="cloudVmClusterId")
    def cloud_vm_cluster_id(self) -> pulumi.Output[_builtins.str]:
        """
        The Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "cloud_vm_cluster_id")

    @_builtins.property
    @pulumi.getter(name="dbPlans")
    def db_plans(self) -> pulumi.Output[Sequence['outputs.CloudVmClusterIormConfigDbPlan']]:
        """
        (Updatable) Array of IORM Setting for all the database in this Cloud Vm Cluster
        """
        return pulumi.get(self, "db_plans")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> pulumi.Output[_builtins.str]:
        """
        Additional information about the current `lifecycleState`.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter
    def objective(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) Value for the IORM objective Default is "Auto"
        """
        return pulumi.get(self, "objective")

    @_builtins.property
    @pulumi.getter
    def state(self) -> pulumi.Output[_builtins.str]:
        """
        The current state of IORM configuration for the Exadata DB system.
        """
        return pulumi.get(self, "state")

