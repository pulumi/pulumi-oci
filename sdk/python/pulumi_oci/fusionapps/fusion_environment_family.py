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

__all__ = ['FusionEnvironmentFamilyArgs', 'FusionEnvironmentFamily']

@pulumi.input_type
class FusionEnvironmentFamilyArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 display_name: pulumi.Input[str],
                 subscription_ids: pulumi.Input[Sequence[pulumi.Input[str]]],
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 family_maintenance_policy: Optional[pulumi.Input['FusionEnvironmentFamilyFamilyMaintenancePolicyArgs']] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a FusionEnvironmentFamily resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The OCID of the compartment where the environment family is located.
        :param pulumi.Input[str] display_name: (Updatable) A friendly name for the environment family. The name must contain only letters, numbers, dashes, and underscores. Can be changed later.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] subscription_ids: (Updatable) The list of the IDs of the applications subscriptions that are associated with the environment family.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input['FusionEnvironmentFamilyFamilyMaintenancePolicyArgs'] family_maintenance_policy: (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "subscription_ids", subscription_ids)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if family_maintenance_policy is not None:
            pulumi.set(__self__, "family_maintenance_policy", family_maintenance_policy)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        (Updatable) The OCID of the compartment where the environment family is located.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Input[str]:
        """
        (Updatable) A friendly name for the environment family. The name must contain only letters, numbers, dashes, and underscores. Can be changed later.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: pulumi.Input[str]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="subscriptionIds")
    def subscription_ids(self) -> pulumi.Input[Sequence[pulumi.Input[str]]]:
        """
        (Updatable) The list of the IDs of the applications subscriptions that are associated with the environment family.
        """
        return pulumi.get(self, "subscription_ids")

    @subscription_ids.setter
    def subscription_ids(self, value: pulumi.Input[Sequence[pulumi.Input[str]]]):
        pulumi.set(self, "subscription_ids", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter(name="familyMaintenancePolicy")
    def family_maintenance_policy(self) -> Optional[pulumi.Input['FusionEnvironmentFamilyFamilyMaintenancePolicyArgs']]:
        """
        (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
        """
        return pulumi.get(self, "family_maintenance_policy")

    @family_maintenance_policy.setter
    def family_maintenance_policy(self, value: Optional[pulumi.Input['FusionEnvironmentFamilyFamilyMaintenancePolicyArgs']]):
        pulumi.set(self, "family_maintenance_policy", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_updated", value)


@pulumi.input_type
class _FusionEnvironmentFamilyState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 family_maintenance_policy: Optional[pulumi.Input['FusionEnvironmentFamilyFamilyMaintenancePolicyArgs']] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 is_subscription_update_needed: Optional[pulumi.Input[bool]] = None,
                 lifecycle_details: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 subscription_ids: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 system_name: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering FusionEnvironmentFamily resources.
        :param pulumi.Input[str] compartment_id: (Updatable) The OCID of the compartment where the environment family is located.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) A friendly name for the environment family. The name must contain only letters, numbers, dashes, and underscores. Can be changed later.
        :param pulumi.Input['FusionEnvironmentFamilyFamilyMaintenancePolicyArgs'] family_maintenance_policy: (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[bool] is_subscription_update_needed: When set to True, a subscription update is required for the environment family.
        :param pulumi.Input[str] lifecycle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        :param pulumi.Input[str] state: The current state of the FusionEnvironmentFamily.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] subscription_ids: (Updatable) The list of the IDs of the applications subscriptions that are associated with the environment family.
        :param pulumi.Input[str] system_name: Environment Specific Guid/ System Name
        :param pulumi.Input[str] time_created: The time the the FusionEnvironmentFamily was created. An RFC3339 formatted datetime string.
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if family_maintenance_policy is not None:
            pulumi.set(__self__, "family_maintenance_policy", family_maintenance_policy)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if is_subscription_update_needed is not None:
            pulumi.set(__self__, "is_subscription_update_needed", is_subscription_update_needed)
        if lifecycle_details is not None:
            pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if subscription_ids is not None:
            pulumi.set(__self__, "subscription_ids", subscription_ids)
        if system_name is not None:
            pulumi.set(__self__, "system_name", system_name)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The OCID of the compartment where the environment family is located.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) A friendly name for the environment family. The name must contain only letters, numbers, dashes, and underscores. Can be changed later.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="familyMaintenancePolicy")
    def family_maintenance_policy(self) -> Optional[pulumi.Input['FusionEnvironmentFamilyFamilyMaintenancePolicyArgs']]:
        """
        (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
        """
        return pulumi.get(self, "family_maintenance_policy")

    @family_maintenance_policy.setter
    def family_maintenance_policy(self, value: Optional[pulumi.Input['FusionEnvironmentFamilyFamilyMaintenancePolicyArgs']]):
        pulumi.set(self, "family_maintenance_policy", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter(name="isSubscriptionUpdateNeeded")
    def is_subscription_update_needed(self) -> Optional[pulumi.Input[bool]]:
        """
        When set to True, a subscription update is required for the environment family.
        """
        return pulumi.get(self, "is_subscription_update_needed")

    @is_subscription_update_needed.setter
    def is_subscription_update_needed(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_subscription_update_needed", value)

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> Optional[pulumi.Input[str]]:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @lifecycle_details.setter
    def lifecycle_details(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "lifecycle_details", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current state of the FusionEnvironmentFamily.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="subscriptionIds")
    def subscription_ids(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        (Updatable) The list of the IDs of the applications subscriptions that are associated with the environment family.
        """
        return pulumi.get(self, "subscription_ids")

    @subscription_ids.setter
    def subscription_ids(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "subscription_ids", value)

    @property
    @pulumi.getter(name="systemName")
    def system_name(self) -> Optional[pulumi.Input[str]]:
        """
        Environment Specific Guid/ System Name
        """
        return pulumi.get(self, "system_name")

    @system_name.setter
    def system_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "system_name", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The time the the FusionEnvironmentFamily was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_updated", value)


class FusionEnvironmentFamily(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 family_maintenance_policy: Optional[pulumi.Input[pulumi.InputType['FusionEnvironmentFamilyFamilyMaintenancePolicyArgs']]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 subscription_ids: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Fusion Environment Family resource in Oracle Cloud Infrastructure Fusion Apps service.

        Creates a new FusionEnvironmentFamily.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_fusion_environment_family = oci.fusion_apps.FusionEnvironmentFamily("testFusionEnvironmentFamily",
            compartment_id=var["compartment_id"],
            display_name=var["fusion_environment_family_display_name"],
            subscription_ids=var["fusion_environment_family_subscription_ids"],
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            family_maintenance_policy=oci.fusion_apps.FusionEnvironmentFamilyFamilyMaintenancePolicyArgs(
                concurrent_maintenance=var["fusion_environment_family_family_maintenance_policy_concurrent_maintenance"],
                is_monthly_patching_enabled=var["fusion_environment_family_family_maintenance_policy_is_monthly_patching_enabled"],
                quarterly_upgrade_begin_times=var["fusion_environment_family_family_maintenance_policy_quarterly_upgrade_begin_times"],
            ),
            freeform_tags={
                "bar-key": "value",
            })
        ```

        ## Import

        FusionEnvironmentFamilies can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:FusionApps/fusionEnvironmentFamily:FusionEnvironmentFamily test_fusion_environment_family "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The OCID of the compartment where the environment family is located.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) A friendly name for the environment family. The name must contain only letters, numbers, dashes, and underscores. Can be changed later.
        :param pulumi.Input[pulumi.InputType['FusionEnvironmentFamilyFamilyMaintenancePolicyArgs']] family_maintenance_policy: (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[Sequence[pulumi.Input[str]]] subscription_ids: (Updatable) The list of the IDs of the applications subscriptions that are associated with the environment family.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: FusionEnvironmentFamilyArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Fusion Environment Family resource in Oracle Cloud Infrastructure Fusion Apps service.

        Creates a new FusionEnvironmentFamily.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_fusion_environment_family = oci.fusion_apps.FusionEnvironmentFamily("testFusionEnvironmentFamily",
            compartment_id=var["compartment_id"],
            display_name=var["fusion_environment_family_display_name"],
            subscription_ids=var["fusion_environment_family_subscription_ids"],
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            family_maintenance_policy=oci.fusion_apps.FusionEnvironmentFamilyFamilyMaintenancePolicyArgs(
                concurrent_maintenance=var["fusion_environment_family_family_maintenance_policy_concurrent_maintenance"],
                is_monthly_patching_enabled=var["fusion_environment_family_family_maintenance_policy_is_monthly_patching_enabled"],
                quarterly_upgrade_begin_times=var["fusion_environment_family_family_maintenance_policy_quarterly_upgrade_begin_times"],
            ),
            freeform_tags={
                "bar-key": "value",
            })
        ```

        ## Import

        FusionEnvironmentFamilies can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:FusionApps/fusionEnvironmentFamily:FusionEnvironmentFamily test_fusion_environment_family "id"
        ```

        :param str resource_name: The name of the resource.
        :param FusionEnvironmentFamilyArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(FusionEnvironmentFamilyArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 family_maintenance_policy: Optional[pulumi.Input[pulumi.InputType['FusionEnvironmentFamilyFamilyMaintenancePolicyArgs']]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 subscription_ids: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = FusionEnvironmentFamilyArgs.__new__(FusionEnvironmentFamilyArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            if display_name is None and not opts.urn:
                raise TypeError("Missing required property 'display_name'")
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["family_maintenance_policy"] = family_maintenance_policy
            __props__.__dict__["freeform_tags"] = freeform_tags
            if subscription_ids is None and not opts.urn:
                raise TypeError("Missing required property 'subscription_ids'")
            __props__.__dict__["subscription_ids"] = subscription_ids
            __props__.__dict__["time_updated"] = time_updated
            __props__.__dict__["is_subscription_update_needed"] = None
            __props__.__dict__["lifecycle_details"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["system_name"] = None
            __props__.__dict__["time_created"] = None
        super(FusionEnvironmentFamily, __self__).__init__(
            'oci:FusionApps/fusionEnvironmentFamily:FusionEnvironmentFamily',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            display_name: Optional[pulumi.Input[str]] = None,
            family_maintenance_policy: Optional[pulumi.Input[pulumi.InputType['FusionEnvironmentFamilyFamilyMaintenancePolicyArgs']]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            is_subscription_update_needed: Optional[pulumi.Input[bool]] = None,
            lifecycle_details: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            subscription_ids: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
            system_name: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_updated: Optional[pulumi.Input[str]] = None) -> 'FusionEnvironmentFamily':
        """
        Get an existing FusionEnvironmentFamily resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The OCID of the compartment where the environment family is located.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) A friendly name for the environment family. The name must contain only letters, numbers, dashes, and underscores. Can be changed later.
        :param pulumi.Input[pulumi.InputType['FusionEnvironmentFamilyFamilyMaintenancePolicyArgs']] family_maintenance_policy: (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[bool] is_subscription_update_needed: When set to True, a subscription update is required for the environment family.
        :param pulumi.Input[str] lifecycle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        :param pulumi.Input[str] state: The current state of the FusionEnvironmentFamily.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] subscription_ids: (Updatable) The list of the IDs of the applications subscriptions that are associated with the environment family.
        :param pulumi.Input[str] system_name: Environment Specific Guid/ System Name
        :param pulumi.Input[str] time_created: The time the the FusionEnvironmentFamily was created. An RFC3339 formatted datetime string.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _FusionEnvironmentFamilyState.__new__(_FusionEnvironmentFamilyState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["family_maintenance_policy"] = family_maintenance_policy
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["is_subscription_update_needed"] = is_subscription_update_needed
        __props__.__dict__["lifecycle_details"] = lifecycle_details
        __props__.__dict__["state"] = state
        __props__.__dict__["subscription_ids"] = subscription_ids
        __props__.__dict__["system_name"] = system_name
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        return FusionEnvironmentFamily(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        (Updatable) The OCID of the compartment where the environment family is located.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[str]:
        """
        (Updatable) A friendly name for the environment family. The name must contain only letters, numbers, dashes, and underscores. Can be changed later.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="familyMaintenancePolicy")
    def family_maintenance_policy(self) -> pulumi.Output['outputs.FusionEnvironmentFamilyFamilyMaintenancePolicy']:
        """
        (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
        """
        return pulumi.get(self, "family_maintenance_policy")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="isSubscriptionUpdateNeeded")
    def is_subscription_update_needed(self) -> pulumi.Output[bool]:
        """
        When set to True, a subscription update is required for the environment family.
        """
        return pulumi.get(self, "is_subscription_update_needed")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> pulumi.Output[str]:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current state of the FusionEnvironmentFamily.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="subscriptionIds")
    def subscription_ids(self) -> pulumi.Output[Sequence[str]]:
        """
        (Updatable) The list of the IDs of the applications subscriptions that are associated with the environment family.
        """
        return pulumi.get(self, "subscription_ids")

    @property
    @pulumi.getter(name="systemName")
    def system_name(self) -> pulumi.Output[str]:
        """
        Environment Specific Guid/ System Name
        """
        return pulumi.get(self, "system_name")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The time the the FusionEnvironmentFamily was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[Optional[str]]:
        return pulumi.get(self, "time_updated")
