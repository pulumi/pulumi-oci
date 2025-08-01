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

__all__ = ['TaskRecordArgs', 'TaskRecord']

@pulumi.input_type
class TaskRecordArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[_builtins.str],
                 details: pulumi.Input['TaskRecordDetailsArgs'],
                 display_name: pulumi.Input[_builtins.str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 description: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None):
        """
        The set of arguments for constructing a TaskRecord resource.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable)
        :param pulumi.Input['TaskRecordDetailsArgs'] details: (Updatable) The details of the task.
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[_builtins.str] description: (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}` 
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "details", details)
        pulumi.set(__self__, "display_name", display_name)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable)
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter
    def details(self) -> pulumi.Input['TaskRecordDetailsArgs']:
        """
        (Updatable) The details of the task.
        """
        return pulumi.get(self, "details")

    @details.setter
    def details(self, value: pulumi.Input['TaskRecordDetailsArgs']):
        pulumi.set(self, "details", value)

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "display_name", value)

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "defined_tags", value)

    @_builtins.property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "description", value)

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}` 


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "freeform_tags", value)


@pulumi.input_type
class _TaskRecordState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 description: Optional[pulumi.Input[_builtins.str]] = None,
                 details: Optional[pulumi.Input['TaskRecordDetailsArgs']] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 lifecycle_details: Optional[pulumi.Input[_builtins.str]] = None,
                 resource_region: Optional[pulumi.Input[_builtins.str]] = None,
                 state: Optional[pulumi.Input[_builtins.str]] = None,
                 system_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 time_created: Optional[pulumi.Input[_builtins.str]] = None,
                 time_updated: Optional[pulumi.Input[_builtins.str]] = None,
                 type: Optional[pulumi.Input[_builtins.str]] = None,
                 version: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering TaskRecord resources.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable)
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[_builtins.str] description: (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
        :param pulumi.Input['TaskRecordDetailsArgs'] details: (Updatable) The details of the task.
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}` 
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] lifecycle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        :param pulumi.Input[_builtins.str] resource_region: Associated region
        :param pulumi.Input[_builtins.str] state: The current state of the task record.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] system_tags: System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[_builtins.str] time_created: The time this resource was created. An RFC3339 formatted datetime string.
        :param pulumi.Input[_builtins.str] time_updated: The time this resource was last updated. An RFC3339 formatted datetime string.
        :param pulumi.Input[_builtins.str] type: Task type.
        :param pulumi.Input[_builtins.str] version: The version of the task record.
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if details is not None:
            pulumi.set(__self__, "details", details)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if lifecycle_details is not None:
            pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if resource_region is not None:
            pulumi.set(__self__, "resource_region", resource_region)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if system_tags is not None:
            pulumi.set(__self__, "system_tags", system_tags)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)
        if type is not None:
            pulumi.set(__self__, "type", type)
        if version is not None:
            pulumi.set(__self__, "version", version)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable)
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "defined_tags", value)

    @_builtins.property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "description", value)

    @_builtins.property
    @pulumi.getter
    def details(self) -> Optional[pulumi.Input['TaskRecordDetailsArgs']]:
        """
        (Updatable) The details of the task.
        """
        return pulumi.get(self, "details")

    @details.setter
    def details(self, value: Optional[pulumi.Input['TaskRecordDetailsArgs']]):
        pulumi.set(self, "details", value)

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "display_name", value)

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}` 


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "freeform_tags", value)

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @lifecycle_details.setter
    def lifecycle_details(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "lifecycle_details", value)

    @_builtins.property
    @pulumi.getter(name="resourceRegion")
    def resource_region(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Associated region
        """
        return pulumi.get(self, "resource_region")

    @resource_region.setter
    def resource_region(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "resource_region", value)

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The current state of the task record.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "state", value)

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @system_tags.setter
    def system_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "system_tags", value)

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The time this resource was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_created", value)

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The time this resource was last updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_updated", value)

    @_builtins.property
    @pulumi.getter
    def type(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Task type.
        """
        return pulumi.get(self, "type")

    @type.setter
    def type(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "type", value)

    @_builtins.property
    @pulumi.getter
    def version(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The version of the task record.
        """
        return pulumi.get(self, "version")

    @version.setter
    def version(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "version", value)


@pulumi.type_token("oci:FleetAppsManagement/taskRecord:TaskRecord")
class TaskRecord(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 description: Optional[pulumi.Input[_builtins.str]] = None,
                 details: Optional[pulumi.Input[Union['TaskRecordDetailsArgs', 'TaskRecordDetailsArgsDict']]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 __props__=None):
        """
        This resource provides the Task Record resource in Oracle Cloud Infrastructure Fleet Apps Management service.

        Creates a new task record.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_task_record = oci.fleetappsmanagement.TaskRecord("test_task_record",
            compartment_id=compartment_id,
            details={
                "execution_details": {
                    "execution_type": task_record_details_execution_details_execution_type,
                    "catalog_id": test_catalog["id"],
                    "command": task_record_details_execution_details_command,
                    "config_file": task_record_details_execution_details_config_file,
                    "content": {
                        "source_type": task_record_details_execution_details_content_source_type,
                        "bucket": task_record_details_execution_details_content_bucket,
                        "catalog_id": test_catalog["id"],
                        "checksum": task_record_details_execution_details_content_checksum,
                        "namespace": task_record_details_execution_details_content_namespace,
                        "object": task_record_details_execution_details_content_object,
                    },
                    "credentials": [{
                        "display_name": task_record_details_execution_details_credentials_display_name,
                        "id": task_record_details_execution_details_credentials_id,
                    }],
                    "endpoint": task_record_details_execution_details_endpoint,
                    "is_executable_content": task_record_details_execution_details_is_executable_content,
                    "is_locked": task_record_details_execution_details_is_locked,
                    "is_read_output_variable_enabled": task_record_details_execution_details_is_read_output_variable_enabled,
                    "target_compartment_id": test_compartment["id"],
                    "variables": {
                        "input_variables": [{
                            "description": task_record_details_execution_details_variables_input_variables_description,
                            "name": task_record_details_execution_details_variables_input_variables_name,
                            "type": task_record_details_execution_details_variables_input_variables_type,
                        }],
                        "output_variables": task_record_details_execution_details_variables_output_variables,
                    },
                },
                "scope": task_record_details_scope,
                "is_apply_subject_task": task_record_details_is_apply_subject_task,
                "is_discovery_output_task": task_record_details_is_discovery_output_task,
                "operation": task_record_details_operation,
                "os_type": task_record_details_os_type,
                "platform": task_record_details_platform,
                "properties": {
                    "num_retries": task_record_details_properties_num_retries,
                    "timeout_in_seconds": task_record_details_properties_timeout_in_seconds,
                },
            },
            display_name=task_record_display_name,
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            description=task_record_description,
            freeform_tags={
                "bar-key": "value",
            })
        ```

        ## Import

        TaskRecords can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:FleetAppsManagement/taskRecord:TaskRecord test_task_record "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable)
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[_builtins.str] description: (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
        :param pulumi.Input[Union['TaskRecordDetailsArgs', 'TaskRecordDetailsArgsDict']] details: (Updatable) The details of the task.
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}` 
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: TaskRecordArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Task Record resource in Oracle Cloud Infrastructure Fleet Apps Management service.

        Creates a new task record.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_task_record = oci.fleetappsmanagement.TaskRecord("test_task_record",
            compartment_id=compartment_id,
            details={
                "execution_details": {
                    "execution_type": task_record_details_execution_details_execution_type,
                    "catalog_id": test_catalog["id"],
                    "command": task_record_details_execution_details_command,
                    "config_file": task_record_details_execution_details_config_file,
                    "content": {
                        "source_type": task_record_details_execution_details_content_source_type,
                        "bucket": task_record_details_execution_details_content_bucket,
                        "catalog_id": test_catalog["id"],
                        "checksum": task_record_details_execution_details_content_checksum,
                        "namespace": task_record_details_execution_details_content_namespace,
                        "object": task_record_details_execution_details_content_object,
                    },
                    "credentials": [{
                        "display_name": task_record_details_execution_details_credentials_display_name,
                        "id": task_record_details_execution_details_credentials_id,
                    }],
                    "endpoint": task_record_details_execution_details_endpoint,
                    "is_executable_content": task_record_details_execution_details_is_executable_content,
                    "is_locked": task_record_details_execution_details_is_locked,
                    "is_read_output_variable_enabled": task_record_details_execution_details_is_read_output_variable_enabled,
                    "target_compartment_id": test_compartment["id"],
                    "variables": {
                        "input_variables": [{
                            "description": task_record_details_execution_details_variables_input_variables_description,
                            "name": task_record_details_execution_details_variables_input_variables_name,
                            "type": task_record_details_execution_details_variables_input_variables_type,
                        }],
                        "output_variables": task_record_details_execution_details_variables_output_variables,
                    },
                },
                "scope": task_record_details_scope,
                "is_apply_subject_task": task_record_details_is_apply_subject_task,
                "is_discovery_output_task": task_record_details_is_discovery_output_task,
                "operation": task_record_details_operation,
                "os_type": task_record_details_os_type,
                "platform": task_record_details_platform,
                "properties": {
                    "num_retries": task_record_details_properties_num_retries,
                    "timeout_in_seconds": task_record_details_properties_timeout_in_seconds,
                },
            },
            display_name=task_record_display_name,
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            description=task_record_description,
            freeform_tags={
                "bar-key": "value",
            })
        ```

        ## Import

        TaskRecords can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:FleetAppsManagement/taskRecord:TaskRecord test_task_record "id"
        ```

        :param str resource_name: The name of the resource.
        :param TaskRecordArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(TaskRecordArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 description: Optional[pulumi.Input[_builtins.str]] = None,
                 details: Optional[pulumi.Input[Union['TaskRecordDetailsArgs', 'TaskRecordDetailsArgsDict']]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = TaskRecordArgs.__new__(TaskRecordArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            __props__.__dict__["description"] = description
            if details is None and not opts.urn:
                raise TypeError("Missing required property 'details'")
            __props__.__dict__["details"] = details
            if display_name is None and not opts.urn:
                raise TypeError("Missing required property 'display_name'")
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["freeform_tags"] = freeform_tags
            __props__.__dict__["lifecycle_details"] = None
            __props__.__dict__["resource_region"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["system_tags"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
            __props__.__dict__["type"] = None
            __props__.__dict__["version"] = None
        super(TaskRecord, __self__).__init__(
            'oci:FleetAppsManagement/taskRecord:TaskRecord',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            description: Optional[pulumi.Input[_builtins.str]] = None,
            details: Optional[pulumi.Input[Union['TaskRecordDetailsArgs', 'TaskRecordDetailsArgsDict']]] = None,
            display_name: Optional[pulumi.Input[_builtins.str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            lifecycle_details: Optional[pulumi.Input[_builtins.str]] = None,
            resource_region: Optional[pulumi.Input[_builtins.str]] = None,
            state: Optional[pulumi.Input[_builtins.str]] = None,
            system_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            time_created: Optional[pulumi.Input[_builtins.str]] = None,
            time_updated: Optional[pulumi.Input[_builtins.str]] = None,
            type: Optional[pulumi.Input[_builtins.str]] = None,
            version: Optional[pulumi.Input[_builtins.str]] = None) -> 'TaskRecord':
        """
        Get an existing TaskRecord resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable)
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[_builtins.str] description: (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
        :param pulumi.Input[Union['TaskRecordDetailsArgs', 'TaskRecordDetailsArgsDict']] details: (Updatable) The details of the task.
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}` 
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] lifecycle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        :param pulumi.Input[_builtins.str] resource_region: Associated region
        :param pulumi.Input[_builtins.str] state: The current state of the task record.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] system_tags: System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[_builtins.str] time_created: The time this resource was created. An RFC3339 formatted datetime string.
        :param pulumi.Input[_builtins.str] time_updated: The time this resource was last updated. An RFC3339 formatted datetime string.
        :param pulumi.Input[_builtins.str] type: Task type.
        :param pulumi.Input[_builtins.str] version: The version of the task record.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _TaskRecordState.__new__(_TaskRecordState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["description"] = description
        __props__.__dict__["details"] = details
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["lifecycle_details"] = lifecycle_details
        __props__.__dict__["resource_region"] = resource_region
        __props__.__dict__["state"] = state
        __props__.__dict__["system_tags"] = system_tags
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        __props__.__dict__["type"] = type
        __props__.__dict__["version"] = version
        return TaskRecord(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable)
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter
    def details(self) -> pulumi.Output['outputs.TaskRecordDetails']:
        """
        (Updatable) The details of the task.
        """
        return pulumi.get(self, "details")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}` 


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> pulumi.Output[_builtins.str]:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="resourceRegion")
    def resource_region(self) -> pulumi.Output[_builtins.str]:
        """
        Associated region
        """
        return pulumi.get(self, "resource_region")

    @_builtins.property
    @pulumi.getter
    def state(self) -> pulumi.Output[_builtins.str]:
        """
        The current state of the task record.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[_builtins.str]:
        """
        The time this resource was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[_builtins.str]:
        """
        The time this resource was last updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")

    @_builtins.property
    @pulumi.getter
    def type(self) -> pulumi.Output[_builtins.str]:
        """
        Task type.
        """
        return pulumi.get(self, "type")

    @_builtins.property
    @pulumi.getter
    def version(self) -> pulumi.Output[_builtins.str]:
        """
        The version of the task record.
        """
        return pulumi.get(self, "version")

