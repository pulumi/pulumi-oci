# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['TagDefaultArgs', 'TagDefault']

@pulumi.input_type
class TagDefaultArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 tag_definition_id: pulumi.Input[str],
                 value: pulumi.Input[str],
                 is_required: Optional[pulumi.Input[bool]] = None):
        """
        The set of arguments for constructing a TagDefault resource.
        :param pulumi.Input[str] compartment_id: The OCID of the compartment. The tag default will be applied to all new resources created in this compartment.
        :param pulumi.Input[str] tag_definition_id: The OCID of the tag definition. The tag default will always assign a default value for this tag definition.
        :param pulumi.Input[str] value: (Updatable) The default value for the tag definition. This will be applied to all new resources created in the compartment.
        :param pulumi.Input[bool] is_required: (Updatable) If you specify that a value is required, a value is set during resource creation (either by the user creating the resource or another tag defualt). If no value is set, resource creation is blocked.
               * If the `isRequired` flag is set to "true", the value is set during resource creation.
               * If the `isRequired` flag is set to "false", the value you enter is set during resource creation.
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "tag_definition_id", tag_definition_id)
        pulumi.set(__self__, "value", value)
        if is_required is not None:
            pulumi.set(__self__, "is_required", is_required)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        The OCID of the compartment. The tag default will be applied to all new resources created in this compartment.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="tagDefinitionId")
    def tag_definition_id(self) -> pulumi.Input[str]:
        """
        The OCID of the tag definition. The tag default will always assign a default value for this tag definition.
        """
        return pulumi.get(self, "tag_definition_id")

    @tag_definition_id.setter
    def tag_definition_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "tag_definition_id", value)

    @property
    @pulumi.getter
    def value(self) -> pulumi.Input[str]:
        """
        (Updatable) The default value for the tag definition. This will be applied to all new resources created in the compartment.
        """
        return pulumi.get(self, "value")

    @value.setter
    def value(self, value: pulumi.Input[str]):
        pulumi.set(self, "value", value)

    @property
    @pulumi.getter(name="isRequired")
    def is_required(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) If you specify that a value is required, a value is set during resource creation (either by the user creating the resource or another tag defualt). If no value is set, resource creation is blocked.
        * If the `isRequired` flag is set to "true", the value is set during resource creation.
        * If the `isRequired` flag is set to "false", the value you enter is set during resource creation.
        """
        return pulumi.get(self, "is_required")

    @is_required.setter
    def is_required(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_required", value)


@pulumi.input_type
class _TagDefaultState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 is_required: Optional[pulumi.Input[bool]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 tag_definition_id: Optional[pulumi.Input[str]] = None,
                 tag_definition_name: Optional[pulumi.Input[str]] = None,
                 tag_namespace_id: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 value: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering TagDefault resources.
        :param pulumi.Input[str] compartment_id: The OCID of the compartment. The tag default will be applied to all new resources created in this compartment.
        :param pulumi.Input[bool] is_required: (Updatable) If you specify that a value is required, a value is set during resource creation (either by the user creating the resource or another tag defualt). If no value is set, resource creation is blocked.
               * If the `isRequired` flag is set to "true", the value is set during resource creation.
               * If the `isRequired` flag is set to "false", the value you enter is set during resource creation.
        :param pulumi.Input[str] state: The tag default's current state. After creating a `TagDefault`, make sure its `lifecycleState` is ACTIVE before using it.
        :param pulumi.Input[str] tag_definition_id: The OCID of the tag definition. The tag default will always assign a default value for this tag definition.
        :param pulumi.Input[str] tag_definition_name: The name used in the tag definition. This field is informational in the context of the tag default.
        :param pulumi.Input[str] tag_namespace_id: The OCID of the tag namespace that contains the tag definition.
        :param pulumi.Input[str] time_created: Date and time the `TagDefault` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        :param pulumi.Input[str] value: (Updatable) The default value for the tag definition. This will be applied to all new resources created in the compartment.
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if is_required is not None:
            pulumi.set(__self__, "is_required", is_required)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if tag_definition_id is not None:
            pulumi.set(__self__, "tag_definition_id", tag_definition_id)
        if tag_definition_name is not None:
            pulumi.set(__self__, "tag_definition_name", tag_definition_name)
        if tag_namespace_id is not None:
            pulumi.set(__self__, "tag_namespace_id", tag_namespace_id)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if value is not None:
            pulumi.set(__self__, "value", value)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the compartment. The tag default will be applied to all new resources created in this compartment.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="isRequired")
    def is_required(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) If you specify that a value is required, a value is set during resource creation (either by the user creating the resource or another tag defualt). If no value is set, resource creation is blocked.
        * If the `isRequired` flag is set to "true", the value is set during resource creation.
        * If the `isRequired` flag is set to "false", the value you enter is set during resource creation.
        """
        return pulumi.get(self, "is_required")

    @is_required.setter
    def is_required(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_required", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The tag default's current state. After creating a `TagDefault`, make sure its `lifecycleState` is ACTIVE before using it.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="tagDefinitionId")
    def tag_definition_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the tag definition. The tag default will always assign a default value for this tag definition.
        """
        return pulumi.get(self, "tag_definition_id")

    @tag_definition_id.setter
    def tag_definition_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "tag_definition_id", value)

    @property
    @pulumi.getter(name="tagDefinitionName")
    def tag_definition_name(self) -> Optional[pulumi.Input[str]]:
        """
        The name used in the tag definition. This field is informational in the context of the tag default.
        """
        return pulumi.get(self, "tag_definition_name")

    @tag_definition_name.setter
    def tag_definition_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "tag_definition_name", value)

    @property
    @pulumi.getter(name="tagNamespaceId")
    def tag_namespace_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the tag namespace that contains the tag definition.
        """
        return pulumi.get(self, "tag_namespace_id")

    @tag_namespace_id.setter
    def tag_namespace_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "tag_namespace_id", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        Date and time the `TagDefault` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter
    def value(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The default value for the tag definition. This will be applied to all new resources created in the compartment.
        """
        return pulumi.get(self, "value")

    @value.setter
    def value(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "value", value)


class TagDefault(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 is_required: Optional[pulumi.Input[bool]] = None,
                 tag_definition_id: Optional[pulumi.Input[str]] = None,
                 value: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Tag Default resource in Oracle Cloud Infrastructure Identity service.

        Creates a new tag default in the specified compartment for the specified tag definition.

        If you specify that a value is required, a value is set during resource creation (either by
        the user creating the resource or another tag defualt). If no value is set, resource creation
        is blocked.

        * If the `isRequired` flag is set to "true", the value is set during resource creation.
        * If the `isRequired` flag is set to "false", the value you enter is set during resource creation.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_tag_default = oci.identity.TagDefault("testTagDefault",
            compartment_id=var["compartment_id"],
            tag_definition_id=oci_identity_tag_definition["test_tag_definition"]["id"],
            value=var["tag_default_value"],
            is_required=var["tag_default_is_required"])
        ```

        ## Import

        TagDefaults can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:Identity/tagDefault:TagDefault test_tag_default "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: The OCID of the compartment. The tag default will be applied to all new resources created in this compartment.
        :param pulumi.Input[bool] is_required: (Updatable) If you specify that a value is required, a value is set during resource creation (either by the user creating the resource or another tag defualt). If no value is set, resource creation is blocked.
               * If the `isRequired` flag is set to "true", the value is set during resource creation.
               * If the `isRequired` flag is set to "false", the value you enter is set during resource creation.
        :param pulumi.Input[str] tag_definition_id: The OCID of the tag definition. The tag default will always assign a default value for this tag definition.
        :param pulumi.Input[str] value: (Updatable) The default value for the tag definition. This will be applied to all new resources created in the compartment.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: TagDefaultArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Tag Default resource in Oracle Cloud Infrastructure Identity service.

        Creates a new tag default in the specified compartment for the specified tag definition.

        If you specify that a value is required, a value is set during resource creation (either by
        the user creating the resource or another tag defualt). If no value is set, resource creation
        is blocked.

        * If the `isRequired` flag is set to "true", the value is set during resource creation.
        * If the `isRequired` flag is set to "false", the value you enter is set during resource creation.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_tag_default = oci.identity.TagDefault("testTagDefault",
            compartment_id=var["compartment_id"],
            tag_definition_id=oci_identity_tag_definition["test_tag_definition"]["id"],
            value=var["tag_default_value"],
            is_required=var["tag_default_is_required"])
        ```

        ## Import

        TagDefaults can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:Identity/tagDefault:TagDefault test_tag_default "id"
        ```

        :param str resource_name: The name of the resource.
        :param TagDefaultArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(TagDefaultArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 is_required: Optional[pulumi.Input[bool]] = None,
                 tag_definition_id: Optional[pulumi.Input[str]] = None,
                 value: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = TagDefaultArgs.__new__(TagDefaultArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["is_required"] = is_required
            if tag_definition_id is None and not opts.urn:
                raise TypeError("Missing required property 'tag_definition_id'")
            __props__.__dict__["tag_definition_id"] = tag_definition_id
            if value is None and not opts.urn:
                raise TypeError("Missing required property 'value'")
            __props__.__dict__["value"] = value
            __props__.__dict__["state"] = None
            __props__.__dict__["tag_definition_name"] = None
            __props__.__dict__["tag_namespace_id"] = None
            __props__.__dict__["time_created"] = None
        super(TagDefault, __self__).__init__(
            'oci:Identity/tagDefault:TagDefault',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            is_required: Optional[pulumi.Input[bool]] = None,
            state: Optional[pulumi.Input[str]] = None,
            tag_definition_id: Optional[pulumi.Input[str]] = None,
            tag_definition_name: Optional[pulumi.Input[str]] = None,
            tag_namespace_id: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            value: Optional[pulumi.Input[str]] = None) -> 'TagDefault':
        """
        Get an existing TagDefault resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: The OCID of the compartment. The tag default will be applied to all new resources created in this compartment.
        :param pulumi.Input[bool] is_required: (Updatable) If you specify that a value is required, a value is set during resource creation (either by the user creating the resource or another tag defualt). If no value is set, resource creation is blocked.
               * If the `isRequired` flag is set to "true", the value is set during resource creation.
               * If the `isRequired` flag is set to "false", the value you enter is set during resource creation.
        :param pulumi.Input[str] state: The tag default's current state. After creating a `TagDefault`, make sure its `lifecycleState` is ACTIVE before using it.
        :param pulumi.Input[str] tag_definition_id: The OCID of the tag definition. The tag default will always assign a default value for this tag definition.
        :param pulumi.Input[str] tag_definition_name: The name used in the tag definition. This field is informational in the context of the tag default.
        :param pulumi.Input[str] tag_namespace_id: The OCID of the tag namespace that contains the tag definition.
        :param pulumi.Input[str] time_created: Date and time the `TagDefault` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        :param pulumi.Input[str] value: (Updatable) The default value for the tag definition. This will be applied to all new resources created in the compartment.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _TagDefaultState.__new__(_TagDefaultState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["is_required"] = is_required
        __props__.__dict__["state"] = state
        __props__.__dict__["tag_definition_id"] = tag_definition_id
        __props__.__dict__["tag_definition_name"] = tag_definition_name
        __props__.__dict__["tag_namespace_id"] = tag_namespace_id
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["value"] = value
        return TagDefault(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        The OCID of the compartment. The tag default will be applied to all new resources created in this compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="isRequired")
    def is_required(self) -> pulumi.Output[bool]:
        """
        (Updatable) If you specify that a value is required, a value is set during resource creation (either by the user creating the resource or another tag defualt). If no value is set, resource creation is blocked.
        * If the `isRequired` flag is set to "true", the value is set during resource creation.
        * If the `isRequired` flag is set to "false", the value you enter is set during resource creation.
        """
        return pulumi.get(self, "is_required")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The tag default's current state. After creating a `TagDefault`, make sure its `lifecycleState` is ACTIVE before using it.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="tagDefinitionId")
    def tag_definition_id(self) -> pulumi.Output[str]:
        """
        The OCID of the tag definition. The tag default will always assign a default value for this tag definition.
        """
        return pulumi.get(self, "tag_definition_id")

    @property
    @pulumi.getter(name="tagDefinitionName")
    def tag_definition_name(self) -> pulumi.Output[str]:
        """
        The name used in the tag definition. This field is informational in the context of the tag default.
        """
        return pulumi.get(self, "tag_definition_name")

    @property
    @pulumi.getter(name="tagNamespaceId")
    def tag_namespace_id(self) -> pulumi.Output[str]:
        """
        The OCID of the tag namespace that contains the tag definition.
        """
        return pulumi.get(self, "tag_namespace_id")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        Date and time the `TagDefault` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter
    def value(self) -> pulumi.Output[str]:
        """
        (Updatable) The default value for the tag definition. This will be applied to all new resources created in the compartment.
        """
        return pulumi.get(self, "value")
