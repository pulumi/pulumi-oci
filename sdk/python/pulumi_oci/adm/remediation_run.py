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

__all__ = ['RemediationRunArgs', 'RemediationRun']

@pulumi.input_type
class RemediationRunArgs:
    def __init__(__self__, *,
                 remediation_recipe_id: pulumi.Input[str],
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None):
        """
        The set of arguments for constructing a RemediationRun resource.
        :param pulumi.Input[str] remediation_recipe_id: The Oracle Cloud identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Remediation Recipe.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[str] compartment_id: (Updatable) The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) The name of the remediation run.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        pulumi.set(__self__, "remediation_recipe_id", remediation_recipe_id)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)

    @property
    @pulumi.getter(name="remediationRecipeId")
    def remediation_recipe_id(self) -> pulumi.Input[str]:
        """
        The Oracle Cloud identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Remediation Recipe.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "remediation_recipe_id")

    @remediation_recipe_id.setter
    def remediation_recipe_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "remediation_recipe_id", value)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
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
        (Updatable) The name of the remediation run.
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


@pulumi.input_type
class _RemediationRunState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 current_stage_type: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 remediation_recipe_id: Optional[pulumi.Input[str]] = None,
                 remediation_run_source: Optional[pulumi.Input[str]] = None,
                 stages: Optional[pulumi.Input[Sequence[pulumi.Input['RemediationRunStageArgs']]]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 system_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_finished: Optional[pulumi.Input[str]] = None,
                 time_started: Optional[pulumi.Input[str]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering RemediationRun resources.
        :param pulumi.Input[str] compartment_id: (Updatable) The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
        :param pulumi.Input[str] current_stage_type: The type of the current stage of the remediation run.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) The name of the remediation run.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] remediation_recipe_id: The Oracle Cloud identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Remediation Recipe.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[str] remediation_run_source: The source that triggered the Remediation Recipe.
        :param pulumi.Input[Sequence[pulumi.Input['RemediationRunStageArgs']]] stages: The list of remediation run stage summaries.
        :param pulumi.Input[str] state: The current lifecycle state of the remediation run.
        :param pulumi.Input[Mapping[str, Any]] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[str] time_created: The creation date and time of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        :param pulumi.Input[str] time_finished: The date and time of the finish of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        :param pulumi.Input[str] time_started: The date and time of the start of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        :param pulumi.Input[str] time_updated: The date and time the remediation run was last updated (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if current_stage_type is not None:
            pulumi.set(__self__, "current_stage_type", current_stage_type)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if remediation_recipe_id is not None:
            pulumi.set(__self__, "remediation_recipe_id", remediation_recipe_id)
        if remediation_run_source is not None:
            pulumi.set(__self__, "remediation_run_source", remediation_run_source)
        if stages is not None:
            pulumi.set(__self__, "stages", stages)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if system_tags is not None:
            pulumi.set(__self__, "system_tags", system_tags)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_finished is not None:
            pulumi.set(__self__, "time_finished", time_finished)
        if time_started is not None:
            pulumi.set(__self__, "time_started", time_started)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="currentStageType")
    def current_stage_type(self) -> Optional[pulumi.Input[str]]:
        """
        The type of the current stage of the remediation run.
        """
        return pulumi.get(self, "current_stage_type")

    @current_stage_type.setter
    def current_stage_type(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "current_stage_type", value)

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
        (Updatable) The name of the remediation run.
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
    @pulumi.getter(name="remediationRecipeId")
    def remediation_recipe_id(self) -> Optional[pulumi.Input[str]]:
        """
        The Oracle Cloud identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Remediation Recipe.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "remediation_recipe_id")

    @remediation_recipe_id.setter
    def remediation_recipe_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "remediation_recipe_id", value)

    @property
    @pulumi.getter(name="remediationRunSource")
    def remediation_run_source(self) -> Optional[pulumi.Input[str]]:
        """
        The source that triggered the Remediation Recipe.
        """
        return pulumi.get(self, "remediation_run_source")

    @remediation_run_source.setter
    def remediation_run_source(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "remediation_run_source", value)

    @property
    @pulumi.getter
    def stages(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['RemediationRunStageArgs']]]]:
        """
        The list of remediation run stage summaries.
        """
        return pulumi.get(self, "stages")

    @stages.setter
    def stages(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['RemediationRunStageArgs']]]]):
        pulumi.set(self, "stages", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current lifecycle state of the remediation run.
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
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The creation date and time of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeFinished")
    def time_finished(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time of the finish of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        """
        return pulumi.get(self, "time_finished")

    @time_finished.setter
    def time_finished(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_finished", value)

    @property
    @pulumi.getter(name="timeStarted")
    def time_started(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time of the start of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        """
        return pulumi.get(self, "time_started")

    @time_started.setter
    def time_started(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_started", value)

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the remediation run was last updated (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_updated", value)


class RemediationRun(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 remediation_recipe_id: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Remediation Run resource in Oracle Cloud Infrastructure Adm service.

        Creates a new remediation run.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_remediation_run = oci.adm.RemediationRun("testRemediationRun",
            remediation_recipe_id=oci_adm_remediation_recipe["test_remediation_recipe"]["id"],
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            display_name=var["remediation_run_display_name"],
            freeform_tags={
                "bar-key": "value",
            })
        ```

        ## Import

        RemediationRuns can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:Adm/remediationRun:RemediationRun test_remediation_run "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) The name of the remediation run.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] remediation_recipe_id: The Oracle Cloud identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Remediation Recipe.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: RemediationRunArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Remediation Run resource in Oracle Cloud Infrastructure Adm service.

        Creates a new remediation run.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_remediation_run = oci.adm.RemediationRun("testRemediationRun",
            remediation_recipe_id=oci_adm_remediation_recipe["test_remediation_recipe"]["id"],
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            display_name=var["remediation_run_display_name"],
            freeform_tags={
                "bar-key": "value",
            })
        ```

        ## Import

        RemediationRuns can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:Adm/remediationRun:RemediationRun test_remediation_run "id"
        ```

        :param str resource_name: The name of the resource.
        :param RemediationRunArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(RemediationRunArgs, pulumi.ResourceOptions, *args, **kwargs)
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
                 remediation_recipe_id: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = RemediationRunArgs.__new__(RemediationRunArgs)

            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["freeform_tags"] = freeform_tags
            if remediation_recipe_id is None and not opts.urn:
                raise TypeError("Missing required property 'remediation_recipe_id'")
            __props__.__dict__["remediation_recipe_id"] = remediation_recipe_id
            __props__.__dict__["current_stage_type"] = None
            __props__.__dict__["remediation_run_source"] = None
            __props__.__dict__["stages"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["system_tags"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_finished"] = None
            __props__.__dict__["time_started"] = None
            __props__.__dict__["time_updated"] = None
        super(RemediationRun, __self__).__init__(
            'oci:Adm/remediationRun:RemediationRun',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            current_stage_type: Optional[pulumi.Input[str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            display_name: Optional[pulumi.Input[str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            remediation_recipe_id: Optional[pulumi.Input[str]] = None,
            remediation_run_source: Optional[pulumi.Input[str]] = None,
            stages: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['RemediationRunStageArgs']]]]] = None,
            state: Optional[pulumi.Input[str]] = None,
            system_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_finished: Optional[pulumi.Input[str]] = None,
            time_started: Optional[pulumi.Input[str]] = None,
            time_updated: Optional[pulumi.Input[str]] = None) -> 'RemediationRun':
        """
        Get an existing RemediationRun resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
        :param pulumi.Input[str] current_stage_type: The type of the current stage of the remediation run.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) The name of the remediation run.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] remediation_recipe_id: The Oracle Cloud identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Remediation Recipe.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[str] remediation_run_source: The source that triggered the Remediation Recipe.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['RemediationRunStageArgs']]]] stages: The list of remediation run stage summaries.
        :param pulumi.Input[str] state: The current lifecycle state of the remediation run.
        :param pulumi.Input[Mapping[str, Any]] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[str] time_created: The creation date and time of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        :param pulumi.Input[str] time_finished: The date and time of the finish of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        :param pulumi.Input[str] time_started: The date and time of the start of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        :param pulumi.Input[str] time_updated: The date and time the remediation run was last updated (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _RemediationRunState.__new__(_RemediationRunState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["current_stage_type"] = current_stage_type
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["remediation_recipe_id"] = remediation_recipe_id
        __props__.__dict__["remediation_run_source"] = remediation_run_source
        __props__.__dict__["stages"] = stages
        __props__.__dict__["state"] = state
        __props__.__dict__["system_tags"] = system_tags
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_finished"] = time_finished
        __props__.__dict__["time_started"] = time_started
        __props__.__dict__["time_updated"] = time_updated
        return RemediationRun(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        (Updatable) The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="currentStageType")
    def current_stage_type(self) -> pulumi.Output[str]:
        """
        The type of the current stage of the remediation run.
        """
        return pulumi.get(self, "current_stage_type")

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
        (Updatable) The name of the remediation run.
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
    @pulumi.getter(name="remediationRecipeId")
    def remediation_recipe_id(self) -> pulumi.Output[str]:
        """
        The Oracle Cloud identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Remediation Recipe.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "remediation_recipe_id")

    @property
    @pulumi.getter(name="remediationRunSource")
    def remediation_run_source(self) -> pulumi.Output[str]:
        """
        The source that triggered the Remediation Recipe.
        """
        return pulumi.get(self, "remediation_run_source")

    @property
    @pulumi.getter
    def stages(self) -> pulumi.Output[Sequence['outputs.RemediationRunStage']]:
        """
        The list of remediation run stage summaries.
        """
        return pulumi.get(self, "stages")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current lifecycle state of the remediation run.
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
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The creation date and time of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeFinished")
    def time_finished(self) -> pulumi.Output[str]:
        """
        The date and time of the finish of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        """
        return pulumi.get(self, "time_finished")

    @property
    @pulumi.getter(name="timeStarted")
    def time_started(self) -> pulumi.Output[str]:
        """
        The date and time of the start of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        """
        return pulumi.get(self, "time_started")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[str]:
        """
        The date and time the remediation run was last updated (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        """
        return pulumi.get(self, "time_updated")
