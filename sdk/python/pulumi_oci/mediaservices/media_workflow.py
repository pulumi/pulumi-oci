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

__all__ = ['MediaWorkflowArgs', 'MediaWorkflow']

@pulumi.input_type
class MediaWorkflowArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 display_name: pulumi.Input[str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 media_workflow_configuration_ids: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 parameters: Optional[pulumi.Input[str]] = None,
                 tasks: Optional[pulumi.Input[Sequence[pulumi.Input['MediaWorkflowTaskArgs']]]] = None):
        """
        The set of arguments for constructing a MediaWorkflow resource.
        :param pulumi.Input[str] compartment_id: (Updatable) Compartment Identifier.
        :param pulumi.Input[str] display_name: (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[Sequence[pulumi.Input[str]]] media_workflow_configuration_ids: (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
        :param pulumi.Input[str] parameters: (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
        :param pulumi.Input[Sequence[pulumi.Input['MediaWorkflowTaskArgs']]] tasks: (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "display_name", display_name)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if media_workflow_configuration_ids is not None:
            pulumi.set(__self__, "media_workflow_configuration_ids", media_workflow_configuration_ids)
        if parameters is not None:
            pulumi.set(__self__, "parameters", parameters)
        if tasks is not None:
            pulumi.set(__self__, "tasks", tasks)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        (Updatable) Compartment Identifier.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Input[str]:
        """
        (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: pulumi.Input[str]):
        pulumi.set(self, "display_name", value)

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
    @pulumi.getter(name="mediaWorkflowConfigurationIds")
    def media_workflow_configuration_ids(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
        """
        return pulumi.get(self, "media_workflow_configuration_ids")

    @media_workflow_configuration_ids.setter
    def media_workflow_configuration_ids(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "media_workflow_configuration_ids", value)

    @property
    @pulumi.getter
    def parameters(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
        """
        return pulumi.get(self, "parameters")

    @parameters.setter
    def parameters(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "parameters", value)

    @property
    @pulumi.getter
    def tasks(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['MediaWorkflowTaskArgs']]]]:
        """
        (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
        """
        return pulumi.get(self, "tasks")

    @tasks.setter
    def tasks(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['MediaWorkflowTaskArgs']]]]):
        pulumi.set(self, "tasks", value)


@pulumi.input_type
class _MediaWorkflowState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 lifecyle_details: Optional[pulumi.Input[str]] = None,
                 media_workflow_configuration_ids: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 parameters: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 system_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 tasks: Optional[pulumi.Input[Sequence[pulumi.Input['MediaWorkflowTaskArgs']]]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None,
                 version: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering MediaWorkflow resources.
        :param pulumi.Input[str] compartment_id: (Updatable) Compartment Identifier.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] lifecyle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] media_workflow_configuration_ids: (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
        :param pulumi.Input[str] parameters: (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
        :param pulumi.Input[str] state: The current state of the MediaWorkflow.
        :param pulumi.Input[Mapping[str, Any]] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[Sequence[pulumi.Input['MediaWorkflowTaskArgs']]] tasks: (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
        :param pulumi.Input[str] time_created: The time when the MediaWorkflow was created. An RFC3339 formatted datetime string.
        :param pulumi.Input[str] time_updated: The time when the MediaWorkflow was updated. An RFC3339 formatted datetime string.
        :param pulumi.Input[str] version: (Updatable) The version of the MediaWorkflowTaskDeclaration.
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if lifecyle_details is not None:
            pulumi.set(__self__, "lifecyle_details", lifecyle_details)
        if media_workflow_configuration_ids is not None:
            pulumi.set(__self__, "media_workflow_configuration_ids", media_workflow_configuration_ids)
        if parameters is not None:
            pulumi.set(__self__, "parameters", parameters)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if system_tags is not None:
            pulumi.set(__self__, "system_tags", system_tags)
        if tasks is not None:
            pulumi.set(__self__, "tasks", tasks)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)
        if version is not None:
            pulumi.set(__self__, "version", version)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Compartment Identifier.
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
        (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
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
    @pulumi.getter(name="lifecyleDetails")
    def lifecyle_details(self) -> Optional[pulumi.Input[str]]:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecyle_details")

    @lifecyle_details.setter
    def lifecyle_details(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "lifecyle_details", value)

    @property
    @pulumi.getter(name="mediaWorkflowConfigurationIds")
    def media_workflow_configuration_ids(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
        """
        return pulumi.get(self, "media_workflow_configuration_ids")

    @media_workflow_configuration_ids.setter
    def media_workflow_configuration_ids(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "media_workflow_configuration_ids", value)

    @property
    @pulumi.getter
    def parameters(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
        """
        return pulumi.get(self, "parameters")

    @parameters.setter
    def parameters(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "parameters", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current state of the MediaWorkflow.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @system_tags.setter
    def system_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "system_tags", value)

    @property
    @pulumi.getter
    def tasks(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['MediaWorkflowTaskArgs']]]]:
        """
        (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
        """
        return pulumi.get(self, "tasks")

    @tasks.setter
    def tasks(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['MediaWorkflowTaskArgs']]]]):
        pulumi.set(self, "tasks", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The time when the MediaWorkflow was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[str]]:
        """
        The time when the MediaWorkflow was updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_updated", value)

    @property
    @pulumi.getter
    def version(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The version of the MediaWorkflowTaskDeclaration.
        """
        return pulumi.get(self, "version")

    @version.setter
    def version(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "version", value)


class MediaWorkflow(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 media_workflow_configuration_ids: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 parameters: Optional[pulumi.Input[str]] = None,
                 tasks: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['MediaWorkflowTaskArgs']]]]] = None,
                 __props__=None):
        """
        This resource provides the Media Workflow resource in Oracle Cloud Infrastructure Media Services service.

        Creates a new MediaWorkflow.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_media_workflow = oci.media_services.MediaWorkflow("testMediaWorkflow",
            compartment_id=var["compartment_id"],
            display_name=var["media_workflow_display_name"],
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            freeform_tags={
                "bar-key": "value",
            },
            media_workflow_configuration_ids=var["media_workflow_media_workflow_configuration_ids"],
            parameters=var["media_workflow_parameters"],
            tasks=[oci.media_services.MediaWorkflowTaskArgs(
                key=var["media_workflow_tasks_key"],
                parameters=var["media_workflow_tasks_parameters"],
                type=var["media_workflow_tasks_type"],
                version=var["media_workflow_tasks_version"],
                enable_parameter_reference=var["media_workflow_tasks_enable_parameter_reference"],
                enable_when_referenced_parameter_equals=var["media_workflow_tasks_enable_when_referenced_parameter_equals"],
                prerequisites=var["media_workflow_tasks_prerequisites"],
            )])
        ```

        ## Import

        MediaWorkflows can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:MediaServices/mediaWorkflow:MediaWorkflow test_media_workflow "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) Compartment Identifier.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[Sequence[pulumi.Input[str]]] media_workflow_configuration_ids: (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
        :param pulumi.Input[str] parameters: (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['MediaWorkflowTaskArgs']]]] tasks: (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: MediaWorkflowArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Media Workflow resource in Oracle Cloud Infrastructure Media Services service.

        Creates a new MediaWorkflow.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_media_workflow = oci.media_services.MediaWorkflow("testMediaWorkflow",
            compartment_id=var["compartment_id"],
            display_name=var["media_workflow_display_name"],
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            freeform_tags={
                "bar-key": "value",
            },
            media_workflow_configuration_ids=var["media_workflow_media_workflow_configuration_ids"],
            parameters=var["media_workflow_parameters"],
            tasks=[oci.media_services.MediaWorkflowTaskArgs(
                key=var["media_workflow_tasks_key"],
                parameters=var["media_workflow_tasks_parameters"],
                type=var["media_workflow_tasks_type"],
                version=var["media_workflow_tasks_version"],
                enable_parameter_reference=var["media_workflow_tasks_enable_parameter_reference"],
                enable_when_referenced_parameter_equals=var["media_workflow_tasks_enable_when_referenced_parameter_equals"],
                prerequisites=var["media_workflow_tasks_prerequisites"],
            )])
        ```

        ## Import

        MediaWorkflows can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:MediaServices/mediaWorkflow:MediaWorkflow test_media_workflow "id"
        ```

        :param str resource_name: The name of the resource.
        :param MediaWorkflowArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(MediaWorkflowArgs, pulumi.ResourceOptions, *args, **kwargs)
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
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 media_workflow_configuration_ids: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 parameters: Optional[pulumi.Input[str]] = None,
                 tasks: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['MediaWorkflowTaskArgs']]]]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = MediaWorkflowArgs.__new__(MediaWorkflowArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            if display_name is None and not opts.urn:
                raise TypeError("Missing required property 'display_name'")
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["freeform_tags"] = freeform_tags
            __props__.__dict__["media_workflow_configuration_ids"] = media_workflow_configuration_ids
            __props__.__dict__["parameters"] = parameters
            __props__.__dict__["tasks"] = tasks
            __props__.__dict__["lifecyle_details"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["system_tags"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
            __props__.__dict__["version"] = None
        super(MediaWorkflow, __self__).__init__(
            'oci:MediaServices/mediaWorkflow:MediaWorkflow',
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
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            lifecyle_details: Optional[pulumi.Input[str]] = None,
            media_workflow_configuration_ids: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
            parameters: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            system_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            tasks: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['MediaWorkflowTaskArgs']]]]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_updated: Optional[pulumi.Input[str]] = None,
            version: Optional[pulumi.Input[str]] = None) -> 'MediaWorkflow':
        """
        Get an existing MediaWorkflow resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) Compartment Identifier.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] lifecyle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] media_workflow_configuration_ids: (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
        :param pulumi.Input[str] parameters: (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
        :param pulumi.Input[str] state: The current state of the MediaWorkflow.
        :param pulumi.Input[Mapping[str, Any]] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['MediaWorkflowTaskArgs']]]] tasks: (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
        :param pulumi.Input[str] time_created: The time when the MediaWorkflow was created. An RFC3339 formatted datetime string.
        :param pulumi.Input[str] time_updated: The time when the MediaWorkflow was updated. An RFC3339 formatted datetime string.
        :param pulumi.Input[str] version: (Updatable) The version of the MediaWorkflowTaskDeclaration.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _MediaWorkflowState.__new__(_MediaWorkflowState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["lifecyle_details"] = lifecyle_details
        __props__.__dict__["media_workflow_configuration_ids"] = media_workflow_configuration_ids
        __props__.__dict__["parameters"] = parameters
        __props__.__dict__["state"] = state
        __props__.__dict__["system_tags"] = system_tags
        __props__.__dict__["tasks"] = tasks
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        __props__.__dict__["version"] = version
        return MediaWorkflow(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        (Updatable) Compartment Identifier.
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
        (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
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
    @pulumi.getter(name="lifecyleDetails")
    def lifecyle_details(self) -> pulumi.Output[str]:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecyle_details")

    @property
    @pulumi.getter(name="mediaWorkflowConfigurationIds")
    def media_workflow_configuration_ids(self) -> pulumi.Output[Sequence[str]]:
        """
        (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
        """
        return pulumi.get(self, "media_workflow_configuration_ids")

    @property
    @pulumi.getter
    def parameters(self) -> pulumi.Output[str]:
        """
        (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
        """
        return pulumi.get(self, "parameters")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current state of the MediaWorkflow.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter
    def tasks(self) -> pulumi.Output[Sequence['outputs.MediaWorkflowTask']]:
        """
        (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
        """
        return pulumi.get(self, "tasks")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The time when the MediaWorkflow was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[str]:
        """
        The time when the MediaWorkflow was updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter
    def version(self) -> pulumi.Output[str]:
        """
        (Updatable) The version of the MediaWorkflowTaskDeclaration.
        """
        return pulumi.get(self, "version")
