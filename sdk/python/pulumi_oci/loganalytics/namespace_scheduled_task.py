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

__all__ = ['NamespaceScheduledTaskArgs', 'NamespaceScheduledTask']

@pulumi.input_type
class NamespaceScheduledTaskArgs:
    def __init__(__self__, *,
                 action: pulumi.Input['NamespaceScheduledTaskActionArgs'],
                 compartment_id: pulumi.Input[str],
                 kind: pulumi.Input[str],
                 namespace: pulumi.Input[str],
                 schedules: pulumi.Input['NamespaceScheduledTaskSchedulesArgs'],
                 task_type: pulumi.Input[str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 saved_search_id: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a NamespaceScheduledTask resource.
        :param pulumi.Input['NamespaceScheduledTaskActionArgs'] action: Action for scheduled task.
        :param pulumi.Input[str] compartment_id: (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[str] kind: Discriminator.
        :param pulumi.Input[str] namespace: The Logging Analytics namespace used for the request.
        :param pulumi.Input['NamespaceScheduledTaskSchedulesArgs'] schedules: (Updatable) Schedules, typically a single schedule. Note there may only be a single schedule for SAVED_SEARCH and PURGE scheduled tasks.
        :param pulumi.Input[str] task_type: Task type.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] saved_search_id: The ManagementSavedSearch id [OCID] to be accelerated.
        """
        pulumi.set(__self__, "action", action)
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "kind", kind)
        pulumi.set(__self__, "namespace", namespace)
        pulumi.set(__self__, "schedules", schedules)
        pulumi.set(__self__, "task_type", task_type)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if saved_search_id is not None:
            pulumi.set(__self__, "saved_search_id", saved_search_id)

    @property
    @pulumi.getter
    def action(self) -> pulumi.Input['NamespaceScheduledTaskActionArgs']:
        """
        Action for scheduled task.
        """
        return pulumi.get(self, "action")

    @action.setter
    def action(self, value: pulumi.Input['NamespaceScheduledTaskActionArgs']):
        pulumi.set(self, "action", value)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter
    def kind(self) -> pulumi.Input[str]:
        """
        Discriminator.
        """
        return pulumi.get(self, "kind")

    @kind.setter
    def kind(self, value: pulumi.Input[str]):
        pulumi.set(self, "kind", value)

    @property
    @pulumi.getter
    def namespace(self) -> pulumi.Input[str]:
        """
        The Logging Analytics namespace used for the request.
        """
        return pulumi.get(self, "namespace")

    @namespace.setter
    def namespace(self, value: pulumi.Input[str]):
        pulumi.set(self, "namespace", value)

    @property
    @pulumi.getter
    def schedules(self) -> pulumi.Input['NamespaceScheduledTaskSchedulesArgs']:
        """
        (Updatable) Schedules, typically a single schedule. Note there may only be a single schedule for SAVED_SEARCH and PURGE scheduled tasks.
        """
        return pulumi.get(self, "schedules")

    @schedules.setter
    def schedules(self, value: pulumi.Input['NamespaceScheduledTaskSchedulesArgs']):
        pulumi.set(self, "schedules", value)

    @property
    @pulumi.getter(name="taskType")
    def task_type(self) -> pulumi.Input[str]:
        """
        Task type.
        """
        return pulumi.get(self, "task_type")

    @task_type.setter
    def task_type(self, value: pulumi.Input[str]):
        pulumi.set(self, "task_type", value)

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
        (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

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
    @pulumi.getter(name="savedSearchId")
    def saved_search_id(self) -> Optional[pulumi.Input[str]]:
        """
        The ManagementSavedSearch id [OCID] to be accelerated.
        """
        return pulumi.get(self, "saved_search_id")

    @saved_search_id.setter
    def saved_search_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "saved_search_id", value)


@pulumi.input_type
class _NamespaceScheduledTaskState:
    def __init__(__self__, *,
                 action: Optional[pulumi.Input['NamespaceScheduledTaskActionArgs']] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 kind: Optional[pulumi.Input[str]] = None,
                 namespace: Optional[pulumi.Input[str]] = None,
                 num_occurrences: Optional[pulumi.Input[str]] = None,
                 saved_search_id: Optional[pulumi.Input[str]] = None,
                 scheduled_task_id: Optional[pulumi.Input[str]] = None,
                 schedules: Optional[pulumi.Input['NamespaceScheduledTaskSchedulesArgs']] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 task_status: Optional[pulumi.Input[str]] = None,
                 task_type: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None,
                 work_request_id: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering NamespaceScheduledTask resources.
        :param pulumi.Input['NamespaceScheduledTaskActionArgs'] action: Action for scheduled task.
        :param pulumi.Input[str] compartment_id: (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] kind: Discriminator.
        :param pulumi.Input[str] namespace: The Logging Analytics namespace used for the request.
        :param pulumi.Input[str] num_occurrences: Number of execution occurrences.
        :param pulumi.Input[str] saved_search_id: The ManagementSavedSearch id [OCID] to be accelerated.
        :param pulumi.Input['NamespaceScheduledTaskSchedulesArgs'] schedules: (Updatable) Schedules, typically a single schedule. Note there may only be a single schedule for SAVED_SEARCH and PURGE scheduled tasks.
        :param pulumi.Input[str] state: The current state of the scheduled task.
        :param pulumi.Input[str] task_status: Status of the scheduled task. - PURGE_RESOURCE_NOT_FOUND
        :param pulumi.Input[str] task_type: Task type.
        :param pulumi.Input[str] time_created: The date and time the scheduled task was created, in the format defined by RFC3339.
        :param pulumi.Input[str] time_updated: The date and time the scheduled task was last updated, in the format defined by RFC3339.
        :param pulumi.Input[str] work_request_id: most recent Work Request Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the asynchronous request.
        """
        if action is not None:
            pulumi.set(__self__, "action", action)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if kind is not None:
            pulumi.set(__self__, "kind", kind)
        if namespace is not None:
            pulumi.set(__self__, "namespace", namespace)
        if num_occurrences is not None:
            pulumi.set(__self__, "num_occurrences", num_occurrences)
        if saved_search_id is not None:
            pulumi.set(__self__, "saved_search_id", saved_search_id)
        if scheduled_task_id is not None:
            pulumi.set(__self__, "scheduled_task_id", scheduled_task_id)
        if schedules is not None:
            pulumi.set(__self__, "schedules", schedules)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if task_status is not None:
            pulumi.set(__self__, "task_status", task_status)
        if task_type is not None:
            pulumi.set(__self__, "task_type", task_type)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)
        if work_request_id is not None:
            pulumi.set(__self__, "work_request_id", work_request_id)

    @property
    @pulumi.getter
    def action(self) -> Optional[pulumi.Input['NamespaceScheduledTaskActionArgs']]:
        """
        Action for scheduled task.
        """
        return pulumi.get(self, "action")

    @action.setter
    def action(self, value: Optional[pulumi.Input['NamespaceScheduledTaskActionArgs']]):
        pulumi.set(self, "action", value)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
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
        (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

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
    @pulumi.getter
    def kind(self) -> Optional[pulumi.Input[str]]:
        """
        Discriminator.
        """
        return pulumi.get(self, "kind")

    @kind.setter
    def kind(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "kind", value)

    @property
    @pulumi.getter
    def namespace(self) -> Optional[pulumi.Input[str]]:
        """
        The Logging Analytics namespace used for the request.
        """
        return pulumi.get(self, "namespace")

    @namespace.setter
    def namespace(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "namespace", value)

    @property
    @pulumi.getter(name="numOccurrences")
    def num_occurrences(self) -> Optional[pulumi.Input[str]]:
        """
        Number of execution occurrences.
        """
        return pulumi.get(self, "num_occurrences")

    @num_occurrences.setter
    def num_occurrences(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "num_occurrences", value)

    @property
    @pulumi.getter(name="savedSearchId")
    def saved_search_id(self) -> Optional[pulumi.Input[str]]:
        """
        The ManagementSavedSearch id [OCID] to be accelerated.
        """
        return pulumi.get(self, "saved_search_id")

    @saved_search_id.setter
    def saved_search_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "saved_search_id", value)

    @property
    @pulumi.getter(name="scheduledTaskId")
    def scheduled_task_id(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "scheduled_task_id")

    @scheduled_task_id.setter
    def scheduled_task_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "scheduled_task_id", value)

    @property
    @pulumi.getter
    def schedules(self) -> Optional[pulumi.Input['NamespaceScheduledTaskSchedulesArgs']]:
        """
        (Updatable) Schedules, typically a single schedule. Note there may only be a single schedule for SAVED_SEARCH and PURGE scheduled tasks.
        """
        return pulumi.get(self, "schedules")

    @schedules.setter
    def schedules(self, value: Optional[pulumi.Input['NamespaceScheduledTaskSchedulesArgs']]):
        pulumi.set(self, "schedules", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current state of the scheduled task.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="taskStatus")
    def task_status(self) -> Optional[pulumi.Input[str]]:
        """
        Status of the scheduled task. - PURGE_RESOURCE_NOT_FOUND
        """
        return pulumi.get(self, "task_status")

    @task_status.setter
    def task_status(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "task_status", value)

    @property
    @pulumi.getter(name="taskType")
    def task_type(self) -> Optional[pulumi.Input[str]]:
        """
        Task type.
        """
        return pulumi.get(self, "task_type")

    @task_type.setter
    def task_type(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "task_type", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the scheduled task was created, in the format defined by RFC3339.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the scheduled task was last updated, in the format defined by RFC3339.
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_updated", value)

    @property
    @pulumi.getter(name="workRequestId")
    def work_request_id(self) -> Optional[pulumi.Input[str]]:
        """
        most recent Work Request Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the asynchronous request.
        """
        return pulumi.get(self, "work_request_id")

    @work_request_id.setter
    def work_request_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "work_request_id", value)


class NamespaceScheduledTask(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 action: Optional[pulumi.Input[pulumi.InputType['NamespaceScheduledTaskActionArgs']]] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 kind: Optional[pulumi.Input[str]] = None,
                 namespace: Optional[pulumi.Input[str]] = None,
                 saved_search_id: Optional[pulumi.Input[str]] = None,
                 schedules: Optional[pulumi.Input[pulumi.InputType['NamespaceScheduledTaskSchedulesArgs']]] = None,
                 task_type: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Namespace Scheduled Task resource in Oracle Cloud Infrastructure Log Analytics service.

        Schedule a task as specified and return task info.

        ## Import

        NamespaceScheduledTasks can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:LogAnalytics/namespaceScheduledTask:NamespaceScheduledTask test_namespace_scheduled_task "namespaces/{namespaceName}/scheduledTasks/{scheduledTaskId}"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[pulumi.InputType['NamespaceScheduledTaskActionArgs']] action: Action for scheduled task.
        :param pulumi.Input[str] compartment_id: (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] kind: Discriminator.
        :param pulumi.Input[str] namespace: The Logging Analytics namespace used for the request.
        :param pulumi.Input[str] saved_search_id: The ManagementSavedSearch id [OCID] to be accelerated.
        :param pulumi.Input[pulumi.InputType['NamespaceScheduledTaskSchedulesArgs']] schedules: (Updatable) Schedules, typically a single schedule. Note there may only be a single schedule for SAVED_SEARCH and PURGE scheduled tasks.
        :param pulumi.Input[str] task_type: Task type.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: NamespaceScheduledTaskArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Namespace Scheduled Task resource in Oracle Cloud Infrastructure Log Analytics service.

        Schedule a task as specified and return task info.

        ## Import

        NamespaceScheduledTasks can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:LogAnalytics/namespaceScheduledTask:NamespaceScheduledTask test_namespace_scheduled_task "namespaces/{namespaceName}/scheduledTasks/{scheduledTaskId}"
        ```

        :param str resource_name: The name of the resource.
        :param NamespaceScheduledTaskArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(NamespaceScheduledTaskArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 action: Optional[pulumi.Input[pulumi.InputType['NamespaceScheduledTaskActionArgs']]] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 kind: Optional[pulumi.Input[str]] = None,
                 namespace: Optional[pulumi.Input[str]] = None,
                 saved_search_id: Optional[pulumi.Input[str]] = None,
                 schedules: Optional[pulumi.Input[pulumi.InputType['NamespaceScheduledTaskSchedulesArgs']]] = None,
                 task_type: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = NamespaceScheduledTaskArgs.__new__(NamespaceScheduledTaskArgs)

            if action is None and not opts.urn:
                raise TypeError("Missing required property 'action'")
            __props__.__dict__["action"] = action
            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["freeform_tags"] = freeform_tags
            if kind is None and not opts.urn:
                raise TypeError("Missing required property 'kind'")
            __props__.__dict__["kind"] = kind
            if namespace is None and not opts.urn:
                raise TypeError("Missing required property 'namespace'")
            __props__.__dict__["namespace"] = namespace
            __props__.__dict__["saved_search_id"] = saved_search_id
            if schedules is None and not opts.urn:
                raise TypeError("Missing required property 'schedules'")
            __props__.__dict__["schedules"] = schedules
            if task_type is None and not opts.urn:
                raise TypeError("Missing required property 'task_type'")
            __props__.__dict__["task_type"] = task_type
            __props__.__dict__["num_occurrences"] = None
            __props__.__dict__["scheduled_task_id"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["task_status"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
            __props__.__dict__["work_request_id"] = None
        super(NamespaceScheduledTask, __self__).__init__(
            'oci:LogAnalytics/namespaceScheduledTask:NamespaceScheduledTask',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            action: Optional[pulumi.Input[pulumi.InputType['NamespaceScheduledTaskActionArgs']]] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            display_name: Optional[pulumi.Input[str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            kind: Optional[pulumi.Input[str]] = None,
            namespace: Optional[pulumi.Input[str]] = None,
            num_occurrences: Optional[pulumi.Input[str]] = None,
            saved_search_id: Optional[pulumi.Input[str]] = None,
            scheduled_task_id: Optional[pulumi.Input[str]] = None,
            schedules: Optional[pulumi.Input[pulumi.InputType['NamespaceScheduledTaskSchedulesArgs']]] = None,
            state: Optional[pulumi.Input[str]] = None,
            task_status: Optional[pulumi.Input[str]] = None,
            task_type: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_updated: Optional[pulumi.Input[str]] = None,
            work_request_id: Optional[pulumi.Input[str]] = None) -> 'NamespaceScheduledTask':
        """
        Get an existing NamespaceScheduledTask resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[pulumi.InputType['NamespaceScheduledTaskActionArgs']] action: Action for scheduled task.
        :param pulumi.Input[str] compartment_id: (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] kind: Discriminator.
        :param pulumi.Input[str] namespace: The Logging Analytics namespace used for the request.
        :param pulumi.Input[str] num_occurrences: Number of execution occurrences.
        :param pulumi.Input[str] saved_search_id: The ManagementSavedSearch id [OCID] to be accelerated.
        :param pulumi.Input[pulumi.InputType['NamespaceScheduledTaskSchedulesArgs']] schedules: (Updatable) Schedules, typically a single schedule. Note there may only be a single schedule for SAVED_SEARCH and PURGE scheduled tasks.
        :param pulumi.Input[str] state: The current state of the scheduled task.
        :param pulumi.Input[str] task_status: Status of the scheduled task. - PURGE_RESOURCE_NOT_FOUND
        :param pulumi.Input[str] task_type: Task type.
        :param pulumi.Input[str] time_created: The date and time the scheduled task was created, in the format defined by RFC3339.
        :param pulumi.Input[str] time_updated: The date and time the scheduled task was last updated, in the format defined by RFC3339.
        :param pulumi.Input[str] work_request_id: most recent Work Request Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the asynchronous request.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _NamespaceScheduledTaskState.__new__(_NamespaceScheduledTaskState)

        __props__.__dict__["action"] = action
        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["kind"] = kind
        __props__.__dict__["namespace"] = namespace
        __props__.__dict__["num_occurrences"] = num_occurrences
        __props__.__dict__["saved_search_id"] = saved_search_id
        __props__.__dict__["scheduled_task_id"] = scheduled_task_id
        __props__.__dict__["schedules"] = schedules
        __props__.__dict__["state"] = state
        __props__.__dict__["task_status"] = task_status
        __props__.__dict__["task_type"] = task_type
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        __props__.__dict__["work_request_id"] = work_request_id
        return NamespaceScheduledTask(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter
    def action(self) -> pulumi.Output['outputs.NamespaceScheduledTaskAction']:
        """
        Action for scheduled task.
        """
        return pulumi.get(self, "action")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
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
        (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def kind(self) -> pulumi.Output[str]:
        """
        Discriminator.
        """
        return pulumi.get(self, "kind")

    @property
    @pulumi.getter
    def namespace(self) -> pulumi.Output[str]:
        """
        The Logging Analytics namespace used for the request.
        """
        return pulumi.get(self, "namespace")

    @property
    @pulumi.getter(name="numOccurrences")
    def num_occurrences(self) -> pulumi.Output[str]:
        """
        Number of execution occurrences.
        """
        return pulumi.get(self, "num_occurrences")

    @property
    @pulumi.getter(name="savedSearchId")
    def saved_search_id(self) -> pulumi.Output[str]:
        """
        The ManagementSavedSearch id [OCID] to be accelerated.
        """
        return pulumi.get(self, "saved_search_id")

    @property
    @pulumi.getter(name="scheduledTaskId")
    def scheduled_task_id(self) -> pulumi.Output[str]:
        return pulumi.get(self, "scheduled_task_id")

    @property
    @pulumi.getter
    def schedules(self) -> pulumi.Output['outputs.NamespaceScheduledTaskSchedules']:
        """
        (Updatable) Schedules, typically a single schedule. Note there may only be a single schedule for SAVED_SEARCH and PURGE scheduled tasks.
        """
        return pulumi.get(self, "schedules")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current state of the scheduled task.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="taskStatus")
    def task_status(self) -> pulumi.Output[str]:
        """
        Status of the scheduled task. - PURGE_RESOURCE_NOT_FOUND
        """
        return pulumi.get(self, "task_status")

    @property
    @pulumi.getter(name="taskType")
    def task_type(self) -> pulumi.Output[str]:
        """
        Task type.
        """
        return pulumi.get(self, "task_type")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The date and time the scheduled task was created, in the format defined by RFC3339.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[str]:
        """
        The date and time the scheduled task was last updated, in the format defined by RFC3339.
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter(name="workRequestId")
    def work_request_id(self) -> pulumi.Output[str]:
        """
        most recent Work Request Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the asynchronous request.
        """
        return pulumi.get(self, "work_request_id")
