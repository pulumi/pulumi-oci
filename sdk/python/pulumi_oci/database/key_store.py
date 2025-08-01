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

__all__ = ['KeyStoreArgs', 'KeyStore']

@pulumi.input_type
class KeyStoreArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[_builtins.str],
                 display_name: pulumi.Input[_builtins.str],
                 type_details: pulumi.Input['KeyStoreTypeDetailsArgs'],
                 confirm_details_trigger: Optional[pulumi.Input[_builtins.int]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None):
        """
        The set of arguments for constructing a KeyStore resource.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        :param pulumi.Input[_builtins.str] display_name: The user-friendly name for the key store. The name does not need to be unique.
        :param pulumi.Input['KeyStoreTypeDetailsArgs'] type_details: (Updatable) Key store type details.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "type_details", type_details)
        if confirm_details_trigger is not None:
            pulumi.set(__self__, "confirm_details_trigger", confirm_details_trigger)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Input[_builtins.str]:
        """
        The user-friendly name for the key store. The name does not need to be unique.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "display_name", value)

    @_builtins.property
    @pulumi.getter(name="typeDetails")
    def type_details(self) -> pulumi.Input['KeyStoreTypeDetailsArgs']:
        """
        (Updatable) Key store type details.
        """
        return pulumi.get(self, "type_details")

    @type_details.setter
    def type_details(self, value: pulumi.Input['KeyStoreTypeDetailsArgs']):
        pulumi.set(self, "type_details", value)

    @_builtins.property
    @pulumi.getter(name="confirmDetailsTrigger")
    def confirm_details_trigger(self) -> Optional[pulumi.Input[_builtins.int]]:
        return pulumi.get(self, "confirm_details_trigger")

    @confirm_details_trigger.setter
    def confirm_details_trigger(self, value: Optional[pulumi.Input[_builtins.int]]):
        pulumi.set(self, "confirm_details_trigger", value)

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "defined_tags", value)

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "freeform_tags", value)


@pulumi.input_type
class _KeyStoreState:
    def __init__(__self__, *,
                 associated_databases: Optional[pulumi.Input[Sequence[pulumi.Input['KeyStoreAssociatedDatabaseArgs']]]] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 confirm_details_trigger: Optional[pulumi.Input[_builtins.int]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 lifecycle_details: Optional[pulumi.Input[_builtins.str]] = None,
                 state: Optional[pulumi.Input[_builtins.str]] = None,
                 system_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 time_created: Optional[pulumi.Input[_builtins.str]] = None,
                 type_details: Optional[pulumi.Input['KeyStoreTypeDetailsArgs']] = None):
        """
        Input properties used for looking up and filtering KeyStore resources.
        :param pulumi.Input[Sequence[pulumi.Input['KeyStoreAssociatedDatabaseArgs']]] associated_databases: List of databases associated with the key store.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        :param pulumi.Input[_builtins.str] display_name: The user-friendly name for the key store. The name does not need to be unique.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[_builtins.str] lifecycle_details: Additional information about the current lifecycle state.
        :param pulumi.Input[_builtins.str] state: The current state of the key store.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] system_tags: System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        :param pulumi.Input[_builtins.str] time_created: The date and time that the key store was created.
        :param pulumi.Input['KeyStoreTypeDetailsArgs'] type_details: (Updatable) Key store type details.
        """
        if associated_databases is not None:
            pulumi.set(__self__, "associated_databases", associated_databases)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if confirm_details_trigger is not None:
            pulumi.set(__self__, "confirm_details_trigger", confirm_details_trigger)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if lifecycle_details is not None:
            pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if system_tags is not None:
            pulumi.set(__self__, "system_tags", system_tags)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if type_details is not None:
            pulumi.set(__self__, "type_details", type_details)

    @_builtins.property
    @pulumi.getter(name="associatedDatabases")
    def associated_databases(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['KeyStoreAssociatedDatabaseArgs']]]]:
        """
        List of databases associated with the key store.
        """
        return pulumi.get(self, "associated_databases")

    @associated_databases.setter
    def associated_databases(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['KeyStoreAssociatedDatabaseArgs']]]]):
        pulumi.set(self, "associated_databases", value)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="confirmDetailsTrigger")
    def confirm_details_trigger(self) -> Optional[pulumi.Input[_builtins.int]]:
        return pulumi.get(self, "confirm_details_trigger")

    @confirm_details_trigger.setter
    def confirm_details_trigger(self, value: Optional[pulumi.Input[_builtins.int]]):
        pulumi.set(self, "confirm_details_trigger", value)

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "defined_tags", value)

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The user-friendly name for the key store. The name does not need to be unique.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "display_name", value)

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "freeform_tags", value)

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Additional information about the current lifecycle state.
        """
        return pulumi.get(self, "lifecycle_details")

    @lifecycle_details.setter
    def lifecycle_details(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "lifecycle_details", value)

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The current state of the key store.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "state", value)

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "system_tags")

    @system_tags.setter
    def system_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "system_tags", value)

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The date and time that the key store was created.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_created", value)

    @_builtins.property
    @pulumi.getter(name="typeDetails")
    def type_details(self) -> Optional[pulumi.Input['KeyStoreTypeDetailsArgs']]:
        """
        (Updatable) Key store type details.
        """
        return pulumi.get(self, "type_details")

    @type_details.setter
    def type_details(self, value: Optional[pulumi.Input['KeyStoreTypeDetailsArgs']]):
        pulumi.set(self, "type_details", value)


@pulumi.type_token("oci:Database/keyStore:KeyStore")
class KeyStore(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 confirm_details_trigger: Optional[pulumi.Input[_builtins.int]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 type_details: Optional[pulumi.Input[Union['KeyStoreTypeDetailsArgs', 'KeyStoreTypeDetailsArgsDict']]] = None,
                 __props__=None):
        """
        This resource provides the Key Store resource in Oracle Cloud Infrastructure Database service.

        Creates a Key Store.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_key_store = oci.database.KeyStore("test_key_store",
            compartment_id=compartment_id,
            display_name=key_store_display_name,
            type_details={
                "admin_username": key_store_type_details_admin_username,
                "connection_ips": key_store_type_details_connection_ips,
                "secret_id": test_secret["id"],
                "type": key_store_type_details_type,
                "vault_id": test_vault["id"],
            },
            defined_tags=key_store_defined_tags,
            freeform_tags={
                "Department": "Finance",
            })
        ```

        ## Import

        KeyStores can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:Database/keyStore:KeyStore test_key_store "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        :param pulumi.Input[_builtins.str] display_name: The user-friendly name for the key store. The name does not need to be unique.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[Union['KeyStoreTypeDetailsArgs', 'KeyStoreTypeDetailsArgsDict']] type_details: (Updatable) Key store type details.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: KeyStoreArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Key Store resource in Oracle Cloud Infrastructure Database service.

        Creates a Key Store.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_key_store = oci.database.KeyStore("test_key_store",
            compartment_id=compartment_id,
            display_name=key_store_display_name,
            type_details={
                "admin_username": key_store_type_details_admin_username,
                "connection_ips": key_store_type_details_connection_ips,
                "secret_id": test_secret["id"],
                "type": key_store_type_details_type,
                "vault_id": test_vault["id"],
            },
            defined_tags=key_store_defined_tags,
            freeform_tags={
                "Department": "Finance",
            })
        ```

        ## Import

        KeyStores can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:Database/keyStore:KeyStore test_key_store "id"
        ```

        :param str resource_name: The name of the resource.
        :param KeyStoreArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(KeyStoreArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 confirm_details_trigger: Optional[pulumi.Input[_builtins.int]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 type_details: Optional[pulumi.Input[Union['KeyStoreTypeDetailsArgs', 'KeyStoreTypeDetailsArgsDict']]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = KeyStoreArgs.__new__(KeyStoreArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["confirm_details_trigger"] = confirm_details_trigger
            __props__.__dict__["defined_tags"] = defined_tags
            if display_name is None and not opts.urn:
                raise TypeError("Missing required property 'display_name'")
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["freeform_tags"] = freeform_tags
            if type_details is None and not opts.urn:
                raise TypeError("Missing required property 'type_details'")
            __props__.__dict__["type_details"] = type_details
            __props__.__dict__["associated_databases"] = None
            __props__.__dict__["lifecycle_details"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["system_tags"] = None
            __props__.__dict__["time_created"] = None
        super(KeyStore, __self__).__init__(
            'oci:Database/keyStore:KeyStore',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            associated_databases: Optional[pulumi.Input[Sequence[pulumi.Input[Union['KeyStoreAssociatedDatabaseArgs', 'KeyStoreAssociatedDatabaseArgsDict']]]]] = None,
            compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
            confirm_details_trigger: Optional[pulumi.Input[_builtins.int]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            display_name: Optional[pulumi.Input[_builtins.str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            lifecycle_details: Optional[pulumi.Input[_builtins.str]] = None,
            state: Optional[pulumi.Input[_builtins.str]] = None,
            system_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            time_created: Optional[pulumi.Input[_builtins.str]] = None,
            type_details: Optional[pulumi.Input[Union['KeyStoreTypeDetailsArgs', 'KeyStoreTypeDetailsArgsDict']]] = None) -> 'KeyStore':
        """
        Get an existing KeyStore resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Sequence[pulumi.Input[Union['KeyStoreAssociatedDatabaseArgs', 'KeyStoreAssociatedDatabaseArgsDict']]]] associated_databases: List of databases associated with the key store.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        :param pulumi.Input[_builtins.str] display_name: The user-friendly name for the key store. The name does not need to be unique.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[_builtins.str] lifecycle_details: Additional information about the current lifecycle state.
        :param pulumi.Input[_builtins.str] state: The current state of the key store.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] system_tags: System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        :param pulumi.Input[_builtins.str] time_created: The date and time that the key store was created.
        :param pulumi.Input[Union['KeyStoreTypeDetailsArgs', 'KeyStoreTypeDetailsArgsDict']] type_details: (Updatable) Key store type details.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _KeyStoreState.__new__(_KeyStoreState)

        __props__.__dict__["associated_databases"] = associated_databases
        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["confirm_details_trigger"] = confirm_details_trigger
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["lifecycle_details"] = lifecycle_details
        __props__.__dict__["state"] = state
        __props__.__dict__["system_tags"] = system_tags
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["type_details"] = type_details
        return KeyStore(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="associatedDatabases")
    def associated_databases(self) -> pulumi.Output[Sequence['outputs.KeyStoreAssociatedDatabase']]:
        """
        List of databases associated with the key store.
        """
        return pulumi.get(self, "associated_databases")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="confirmDetailsTrigger")
    def confirm_details_trigger(self) -> pulumi.Output[Optional[_builtins.int]]:
        return pulumi.get(self, "confirm_details_trigger")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[_builtins.str]:
        """
        The user-friendly name for the key store. The name does not need to be unique.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> pulumi.Output[_builtins.str]:
        """
        Additional information about the current lifecycle state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter
    def state(self) -> pulumi.Output[_builtins.str]:
        """
        The current state of the key store.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[_builtins.str]:
        """
        The date and time that the key store was created.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="typeDetails")
    def type_details(self) -> pulumi.Output['outputs.KeyStoreTypeDetails']:
        """
        (Updatable) Key store type details.
        """
        return pulumi.get(self, "type_details")

