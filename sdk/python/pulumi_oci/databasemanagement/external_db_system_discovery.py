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

__all__ = ['ExternalDbSystemDiscoveryArgs', 'ExternalDbSystemDiscovery']

@pulumi.input_type
class ExternalDbSystemDiscoveryArgs:
    def __init__(__self__, *,
                 agent_id: pulumi.Input[str],
                 compartment_id: pulumi.Input[str],
                 display_name: Optional[pulumi.Input[str]] = None,
                 patch_operations: Optional[pulumi.Input[Sequence[pulumi.Input['ExternalDbSystemDiscoveryPatchOperationArgs']]]] = None):
        """
        The set of arguments for constructing a ExternalDbSystemDiscovery resource.
        :param pulumi.Input[str] agent_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system discovery.
        :param pulumi.Input[str] compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
        :param pulumi.Input[str] display_name: (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
        :param pulumi.Input[Sequence[pulumi.Input['ExternalDbSystemDiscoveryPatchOperationArgs']]] patch_operations: (Updatable)
        """
        pulumi.set(__self__, "agent_id", agent_id)
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if patch_operations is not None:
            pulumi.set(__self__, "patch_operations", patch_operations)

    @property
    @pulumi.getter(name="agentId")
    def agent_id(self) -> pulumi.Input[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system discovery.
        """
        return pulumi.get(self, "agent_id")

    @agent_id.setter
    def agent_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "agent_id", value)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="patchOperations")
    def patch_operations(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ExternalDbSystemDiscoveryPatchOperationArgs']]]]:
        """
        (Updatable)
        """
        return pulumi.get(self, "patch_operations")

    @patch_operations.setter
    def patch_operations(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ExternalDbSystemDiscoveryPatchOperationArgs']]]]):
        pulumi.set(self, "patch_operations", value)


@pulumi.input_type
class _ExternalDbSystemDiscoveryState:
    def __init__(__self__, *,
                 agent_id: Optional[pulumi.Input[str]] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 discovered_components: Optional[pulumi.Input[Sequence[pulumi.Input['ExternalDbSystemDiscoveryDiscoveredComponentArgs']]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 external_db_system_discovery_id: Optional[pulumi.Input[str]] = None,
                 grid_home: Optional[pulumi.Input[str]] = None,
                 lifecycle_details: Optional[pulumi.Input[str]] = None,
                 patch_operations: Optional[pulumi.Input[Sequence[pulumi.Input['ExternalDbSystemDiscoveryPatchOperationArgs']]]] = None,
                 resource_id: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering ExternalDbSystemDiscovery resources.
        :param pulumi.Input[str] agent_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system discovery.
        :param pulumi.Input[str] compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
        :param pulumi.Input[Sequence[pulumi.Input['ExternalDbSystemDiscoveryDiscoveredComponentArgs']]] discovered_components: The list of DB system components that were found in the DB system discovery.
        :param pulumi.Input[str] display_name: (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
        :param pulumi.Input[str] grid_home: The directory in which Oracle Grid Infrastructure is installed.
        :param pulumi.Input[str] lifecycle_details: Additional information about the current lifecycle state.
        :param pulumi.Input[Sequence[pulumi.Input['ExternalDbSystemDiscoveryPatchOperationArgs']]] patch_operations: (Updatable)
        :param pulumi.Input[str] resource_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the existing Oracle Cloud Infrastructure resource matching the discovered DB system.
        :param pulumi.Input[str] state: The current lifecycle state of the external DB system discovery resource.
        :param pulumi.Input[str] time_created: The date and time the external DB system discovery was created.
        :param pulumi.Input[str] time_updated: The date and time the external DB system discovery was last updated.
        """
        if agent_id is not None:
            pulumi.set(__self__, "agent_id", agent_id)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if discovered_components is not None:
            pulumi.set(__self__, "discovered_components", discovered_components)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if external_db_system_discovery_id is not None:
            pulumi.set(__self__, "external_db_system_discovery_id", external_db_system_discovery_id)
        if grid_home is not None:
            pulumi.set(__self__, "grid_home", grid_home)
        if lifecycle_details is not None:
            pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if patch_operations is not None:
            pulumi.set(__self__, "patch_operations", patch_operations)
        if resource_id is not None:
            pulumi.set(__self__, "resource_id", resource_id)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="agentId")
    def agent_id(self) -> Optional[pulumi.Input[str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system discovery.
        """
        return pulumi.get(self, "agent_id")

    @agent_id.setter
    def agent_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "agent_id", value)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="discoveredComponents")
    def discovered_components(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ExternalDbSystemDiscoveryDiscoveredComponentArgs']]]]:
        """
        The list of DB system components that were found in the DB system discovery.
        """
        return pulumi.get(self, "discovered_components")

    @discovered_components.setter
    def discovered_components(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ExternalDbSystemDiscoveryDiscoveredComponentArgs']]]]):
        pulumi.set(self, "discovered_components", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="externalDbSystemDiscoveryId")
    def external_db_system_discovery_id(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "external_db_system_discovery_id")

    @external_db_system_discovery_id.setter
    def external_db_system_discovery_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "external_db_system_discovery_id", value)

    @property
    @pulumi.getter(name="gridHome")
    def grid_home(self) -> Optional[pulumi.Input[str]]:
        """
        The directory in which Oracle Grid Infrastructure is installed.
        """
        return pulumi.get(self, "grid_home")

    @grid_home.setter
    def grid_home(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "grid_home", value)

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> Optional[pulumi.Input[str]]:
        """
        Additional information about the current lifecycle state.
        """
        return pulumi.get(self, "lifecycle_details")

    @lifecycle_details.setter
    def lifecycle_details(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "lifecycle_details", value)

    @property
    @pulumi.getter(name="patchOperations")
    def patch_operations(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ExternalDbSystemDiscoveryPatchOperationArgs']]]]:
        """
        (Updatable)
        """
        return pulumi.get(self, "patch_operations")

    @patch_operations.setter
    def patch_operations(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ExternalDbSystemDiscoveryPatchOperationArgs']]]]):
        pulumi.set(self, "patch_operations", value)

    @property
    @pulumi.getter(name="resourceId")
    def resource_id(self) -> Optional[pulumi.Input[str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the existing Oracle Cloud Infrastructure resource matching the discovered DB system.
        """
        return pulumi.get(self, "resource_id")

    @resource_id.setter
    def resource_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "resource_id", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current lifecycle state of the external DB system discovery resource.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the external DB system discovery was created.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the external DB system discovery was last updated.
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_updated", value)


class ExternalDbSystemDiscovery(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 agent_id: Optional[pulumi.Input[str]] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 patch_operations: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ExternalDbSystemDiscoveryPatchOperationArgs']]]]] = None,
                 __props__=None):
        """
        This resource provides the External Db System Discovery resource in Oracle Cloud Infrastructure Database Management service.

        Creates an external DB system discovery resource and initiates the discovery process.

          Patches the external DB system discovery specified by `externalDbSystemDiscoveryId`.

        ## Import

        ExternalDbSystemDiscoveries can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:DatabaseManagement/externalDbSystemDiscovery:ExternalDbSystemDiscovery test_external_db_system_discovery "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] agent_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system discovery.
        :param pulumi.Input[str] compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
        :param pulumi.Input[str] display_name: (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ExternalDbSystemDiscoveryPatchOperationArgs']]]] patch_operations: (Updatable)
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ExternalDbSystemDiscoveryArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the External Db System Discovery resource in Oracle Cloud Infrastructure Database Management service.

        Creates an external DB system discovery resource and initiates the discovery process.

          Patches the external DB system discovery specified by `externalDbSystemDiscoveryId`.

        ## Import

        ExternalDbSystemDiscoveries can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:DatabaseManagement/externalDbSystemDiscovery:ExternalDbSystemDiscovery test_external_db_system_discovery "id"
        ```

        :param str resource_name: The name of the resource.
        :param ExternalDbSystemDiscoveryArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ExternalDbSystemDiscoveryArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 agent_id: Optional[pulumi.Input[str]] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 patch_operations: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ExternalDbSystemDiscoveryPatchOperationArgs']]]]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = ExternalDbSystemDiscoveryArgs.__new__(ExternalDbSystemDiscoveryArgs)

            if agent_id is None and not opts.urn:
                raise TypeError("Missing required property 'agent_id'")
            __props__.__dict__["agent_id"] = agent_id
            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["patch_operations"] = patch_operations
            __props__.__dict__["discovered_components"] = None
            __props__.__dict__["external_db_system_discovery_id"] = None
            __props__.__dict__["grid_home"] = None
            __props__.__dict__["lifecycle_details"] = None
            __props__.__dict__["resource_id"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
        super(ExternalDbSystemDiscovery, __self__).__init__(
            'oci:DatabaseManagement/externalDbSystemDiscovery:ExternalDbSystemDiscovery',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            agent_id: Optional[pulumi.Input[str]] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            discovered_components: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ExternalDbSystemDiscoveryDiscoveredComponentArgs']]]]] = None,
            display_name: Optional[pulumi.Input[str]] = None,
            external_db_system_discovery_id: Optional[pulumi.Input[str]] = None,
            grid_home: Optional[pulumi.Input[str]] = None,
            lifecycle_details: Optional[pulumi.Input[str]] = None,
            patch_operations: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ExternalDbSystemDiscoveryPatchOperationArgs']]]]] = None,
            resource_id: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_updated: Optional[pulumi.Input[str]] = None) -> 'ExternalDbSystemDiscovery':
        """
        Get an existing ExternalDbSystemDiscovery resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] agent_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system discovery.
        :param pulumi.Input[str] compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ExternalDbSystemDiscoveryDiscoveredComponentArgs']]]] discovered_components: The list of DB system components that were found in the DB system discovery.
        :param pulumi.Input[str] display_name: (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
        :param pulumi.Input[str] grid_home: The directory in which Oracle Grid Infrastructure is installed.
        :param pulumi.Input[str] lifecycle_details: Additional information about the current lifecycle state.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ExternalDbSystemDiscoveryPatchOperationArgs']]]] patch_operations: (Updatable)
        :param pulumi.Input[str] resource_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the existing Oracle Cloud Infrastructure resource matching the discovered DB system.
        :param pulumi.Input[str] state: The current lifecycle state of the external DB system discovery resource.
        :param pulumi.Input[str] time_created: The date and time the external DB system discovery was created.
        :param pulumi.Input[str] time_updated: The date and time the external DB system discovery was last updated.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ExternalDbSystemDiscoveryState.__new__(_ExternalDbSystemDiscoveryState)

        __props__.__dict__["agent_id"] = agent_id
        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["discovered_components"] = discovered_components
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["external_db_system_discovery_id"] = external_db_system_discovery_id
        __props__.__dict__["grid_home"] = grid_home
        __props__.__dict__["lifecycle_details"] = lifecycle_details
        __props__.__dict__["patch_operations"] = patch_operations
        __props__.__dict__["resource_id"] = resource_id
        __props__.__dict__["state"] = state
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        return ExternalDbSystemDiscovery(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="agentId")
    def agent_id(self) -> pulumi.Output[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system discovery.
        """
        return pulumi.get(self, "agent_id")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="discoveredComponents")
    def discovered_components(self) -> pulumi.Output[Sequence['outputs.ExternalDbSystemDiscoveryDiscoveredComponent']]:
        """
        The list of DB system components that were found in the DB system discovery.
        """
        return pulumi.get(self, "discovered_components")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[str]:
        """
        (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="externalDbSystemDiscoveryId")
    def external_db_system_discovery_id(self) -> pulumi.Output[str]:
        return pulumi.get(self, "external_db_system_discovery_id")

    @property
    @pulumi.getter(name="gridHome")
    def grid_home(self) -> pulumi.Output[str]:
        """
        The directory in which Oracle Grid Infrastructure is installed.
        """
        return pulumi.get(self, "grid_home")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> pulumi.Output[str]:
        """
        Additional information about the current lifecycle state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="patchOperations")
    def patch_operations(self) -> pulumi.Output[Optional[Sequence['outputs.ExternalDbSystemDiscoveryPatchOperation']]]:
        """
        (Updatable)
        """
        return pulumi.get(self, "patch_operations")

    @property
    @pulumi.getter(name="resourceId")
    def resource_id(self) -> pulumi.Output[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the existing Oracle Cloud Infrastructure resource matching the discovered DB system.
        """
        return pulumi.get(self, "resource_id")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current lifecycle state of the external DB system discovery resource.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The date and time the external DB system discovery was created.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[str]:
        """
        The date and time the external DB system discovery was last updated.
        """
        return pulumi.get(self, "time_updated")
