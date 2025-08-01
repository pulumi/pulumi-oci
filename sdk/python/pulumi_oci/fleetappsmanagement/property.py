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

__all__ = ['PropertyArgs', 'Property']

@pulumi.input_type
class PropertyArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[_builtins.str],
                 display_name: pulumi.Input[_builtins.str],
                 selection: pulumi.Input[_builtins.str],
                 value_type: pulumi.Input[_builtins.str],
                 values: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None):
        """
        The set of arguments for constructing a Property resource.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) Compartment OCID
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        :param pulumi.Input[_builtins.str] selection: (Updatable) Text selection of the property.
        :param pulumi.Input[_builtins.str] value_type: (Updatable) Format of the value.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] values: (Updatable) Values of the property (must be a single value if selection = 'SINGLE_CHOICE').
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "selection", selection)
        pulumi.set(__self__, "value_type", value_type)
        if values is not None:
            pulumi.set(__self__, "values", values)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) Compartment OCID
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "compartment_id", value)

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
    @pulumi.getter
    def selection(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) Text selection of the property.
        """
        return pulumi.get(self, "selection")

    @selection.setter
    def selection(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "selection", value)

    @_builtins.property
    @pulumi.getter(name="valueType")
    def value_type(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) Format of the value.
        """
        return pulumi.get(self, "value_type")

    @value_type.setter
    def value_type(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "value_type", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Values of the property (must be a single value if selection = 'SINGLE_CHOICE').


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "values", value)


@pulumi.input_type
class _PropertyState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 lifecycle_details: Optional[pulumi.Input[_builtins.str]] = None,
                 resource_region: Optional[pulumi.Input[_builtins.str]] = None,
                 scope: Optional[pulumi.Input[_builtins.str]] = None,
                 selection: Optional[pulumi.Input[_builtins.str]] = None,
                 state: Optional[pulumi.Input[_builtins.str]] = None,
                 system_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 time_created: Optional[pulumi.Input[_builtins.str]] = None,
                 time_updated: Optional[pulumi.Input[_builtins.str]] = None,
                 type: Optional[pulumi.Input[_builtins.str]] = None,
                 value_type: Optional[pulumi.Input[_builtins.str]] = None,
                 values: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None):
        """
        Input properties used for looking up and filtering Property resources.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) Compartment OCID
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[_builtins.str] lifecycle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        :param pulumi.Input[_builtins.str] resource_region: Associated region
        :param pulumi.Input[_builtins.str] scope: The scope of the property.
        :param pulumi.Input[_builtins.str] selection: (Updatable) Text selection of the property.
        :param pulumi.Input[_builtins.str] state: The current state of the Property.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] system_tags: System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[_builtins.str] time_created: The time this resource was created. An RFC3339 formatted datetime string.
        :param pulumi.Input[_builtins.str] time_updated: The time this resource was last updated. An RFC3339 formatted datetime string.
        :param pulumi.Input[_builtins.str] type: The type of the property.
        :param pulumi.Input[_builtins.str] value_type: (Updatable) Format of the value.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] values: (Updatable) Values of the property (must be a single value if selection = 'SINGLE_CHOICE').
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if lifecycle_details is not None:
            pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if resource_region is not None:
            pulumi.set(__self__, "resource_region", resource_region)
        if scope is not None:
            pulumi.set(__self__, "scope", scope)
        if selection is not None:
            pulumi.set(__self__, "selection", selection)
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
        if value_type is not None:
            pulumi.set(__self__, "value_type", value_type)
        if values is not None:
            pulumi.set(__self__, "values", values)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Compartment OCID
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "defined_tags", value)

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
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
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
    def scope(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The scope of the property.
        """
        return pulumi.get(self, "scope")

    @scope.setter
    def scope(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "scope", value)

    @_builtins.property
    @pulumi.getter
    def selection(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Text selection of the property.
        """
        return pulumi.get(self, "selection")

    @selection.setter
    def selection(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "selection", value)

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The current state of the Property.
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
        The type of the property.
        """
        return pulumi.get(self, "type")

    @type.setter
    def type(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "type", value)

    @_builtins.property
    @pulumi.getter(name="valueType")
    def value_type(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Format of the value.
        """
        return pulumi.get(self, "value_type")

    @value_type.setter
    def value_type(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "value_type", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Values of the property (must be a single value if selection = 'SINGLE_CHOICE').


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "values", value)


@pulumi.type_token("oci:FleetAppsManagement/property:Property")
class Property(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 selection: Optional[pulumi.Input[_builtins.str]] = None,
                 value_type: Optional[pulumi.Input[_builtins.str]] = None,
                 values: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 __props__=None):
        """
        This resource provides the Property resource in Oracle Cloud Infrastructure Fleet Apps Management service.

        Create a business-specific metadata property in Fleet Application Management.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_property = oci.fleetappsmanagement.Property("test_property",
            compartment_id=compartment_id,
            display_name=property_display_name,
            selection=property_selection,
            value_type=property_value_type,
            values=property_values)
        ```

        ## Import

        Properties can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:FleetAppsManagement/property:Property test_property "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) Compartment OCID
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        :param pulumi.Input[_builtins.str] selection: (Updatable) Text selection of the property.
        :param pulumi.Input[_builtins.str] value_type: (Updatable) Format of the value.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] values: (Updatable) Values of the property (must be a single value if selection = 'SINGLE_CHOICE').
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: PropertyArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Property resource in Oracle Cloud Infrastructure Fleet Apps Management service.

        Create a business-specific metadata property in Fleet Application Management.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_property = oci.fleetappsmanagement.Property("test_property",
            compartment_id=compartment_id,
            display_name=property_display_name,
            selection=property_selection,
            value_type=property_value_type,
            values=property_values)
        ```

        ## Import

        Properties can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:FleetAppsManagement/property:Property test_property "id"
        ```

        :param str resource_name: The name of the resource.
        :param PropertyArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(PropertyArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 selection: Optional[pulumi.Input[_builtins.str]] = None,
                 value_type: Optional[pulumi.Input[_builtins.str]] = None,
                 values: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = PropertyArgs.__new__(PropertyArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            if display_name is None and not opts.urn:
                raise TypeError("Missing required property 'display_name'")
            __props__.__dict__["display_name"] = display_name
            if selection is None and not opts.urn:
                raise TypeError("Missing required property 'selection'")
            __props__.__dict__["selection"] = selection
            if value_type is None and not opts.urn:
                raise TypeError("Missing required property 'value_type'")
            __props__.__dict__["value_type"] = value_type
            __props__.__dict__["values"] = values
            __props__.__dict__["defined_tags"] = None
            __props__.__dict__["freeform_tags"] = None
            __props__.__dict__["lifecycle_details"] = None
            __props__.__dict__["resource_region"] = None
            __props__.__dict__["scope"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["system_tags"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
            __props__.__dict__["type"] = None
        super(Property, __self__).__init__(
            'oci:FleetAppsManagement/property:Property',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            display_name: Optional[pulumi.Input[_builtins.str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            lifecycle_details: Optional[pulumi.Input[_builtins.str]] = None,
            resource_region: Optional[pulumi.Input[_builtins.str]] = None,
            scope: Optional[pulumi.Input[_builtins.str]] = None,
            selection: Optional[pulumi.Input[_builtins.str]] = None,
            state: Optional[pulumi.Input[_builtins.str]] = None,
            system_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            time_created: Optional[pulumi.Input[_builtins.str]] = None,
            time_updated: Optional[pulumi.Input[_builtins.str]] = None,
            type: Optional[pulumi.Input[_builtins.str]] = None,
            value_type: Optional[pulumi.Input[_builtins.str]] = None,
            values: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None) -> 'Property':
        """
        Get an existing Property resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) Compartment OCID
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[_builtins.str] lifecycle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        :param pulumi.Input[_builtins.str] resource_region: Associated region
        :param pulumi.Input[_builtins.str] scope: The scope of the property.
        :param pulumi.Input[_builtins.str] selection: (Updatable) Text selection of the property.
        :param pulumi.Input[_builtins.str] state: The current state of the Property.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] system_tags: System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[_builtins.str] time_created: The time this resource was created. An RFC3339 formatted datetime string.
        :param pulumi.Input[_builtins.str] time_updated: The time this resource was last updated. An RFC3339 formatted datetime string.
        :param pulumi.Input[_builtins.str] type: The type of the property.
        :param pulumi.Input[_builtins.str] value_type: (Updatable) Format of the value.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] values: (Updatable) Values of the property (must be a single value if selection = 'SINGLE_CHOICE').
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _PropertyState.__new__(_PropertyState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["lifecycle_details"] = lifecycle_details
        __props__.__dict__["resource_region"] = resource_region
        __props__.__dict__["scope"] = scope
        __props__.__dict__["selection"] = selection
        __props__.__dict__["state"] = state
        __props__.__dict__["system_tags"] = system_tags
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        __props__.__dict__["type"] = type
        __props__.__dict__["value_type"] = value_type
        __props__.__dict__["values"] = values
        return Property(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) Compartment OCID
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

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
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
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
    def scope(self) -> pulumi.Output[_builtins.str]:
        """
        The scope of the property.
        """
        return pulumi.get(self, "scope")

    @_builtins.property
    @pulumi.getter
    def selection(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) Text selection of the property.
        """
        return pulumi.get(self, "selection")

    @_builtins.property
    @pulumi.getter
    def state(self) -> pulumi.Output[_builtins.str]:
        """
        The current state of the Property.
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
        The type of the property.
        """
        return pulumi.get(self, "type")

    @_builtins.property
    @pulumi.getter(name="valueType")
    def value_type(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) Format of the value.
        """
        return pulumi.get(self, "value_type")

    @_builtins.property
    @pulumi.getter
    def values(self) -> pulumi.Output[Sequence[_builtins.str]]:
        """
        (Updatable) Values of the property (must be a single value if selection = 'SINGLE_CHOICE').


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "values")

