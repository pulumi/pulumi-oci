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

__all__ = ['OciCacheUserArgs', 'OciCacheUser']

@pulumi.input_type
class OciCacheUserArgs:
    def __init__(__self__, *,
                 acl_string: pulumi.Input[_builtins.str],
                 authentication_mode: pulumi.Input['OciCacheUserAuthenticationModeArgs'],
                 compartment_id: pulumi.Input[_builtins.str],
                 description: pulumi.Input[_builtins.str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 status: Optional[pulumi.Input[_builtins.str]] = None):
        """
        The set of arguments for constructing a OciCacheUser resource.
        :param pulumi.Input[_builtins.str] acl_string: (Updatable) ACL string of Oracle Cloud Infrastructure cache user.
        :param pulumi.Input['OciCacheUserAuthenticationModeArgs'] authentication_mode: (Updatable) These are the Authentication details of an Oracle Cloud Infrastructure cache user.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) Oracle Cloud Infrastructure cache user compartment ID.
        :param pulumi.Input[_builtins.str] description: (Updatable) Description of Oracle Cloud Infrastructure cache user.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[_builtins.str] name: Oracle Cloud Infrastructure cache user name is required to connect to an Oracle Cloud Infrastructure cache cluster.
        :param pulumi.Input[_builtins.str] status: (Updatable) Oracle Cloud Infrastructure cache user status. ON enables and OFF disables the Oracle Cloud Infrastructure cache user to login to the associated clusters. Default value is ON.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "acl_string", acl_string)
        pulumi.set(__self__, "authentication_mode", authentication_mode)
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "description", description)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if status is not None:
            pulumi.set(__self__, "status", status)

    @_builtins.property
    @pulumi.getter(name="aclString")
    def acl_string(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) ACL string of Oracle Cloud Infrastructure cache user.
        """
        return pulumi.get(self, "acl_string")

    @acl_string.setter
    def acl_string(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "acl_string", value)

    @_builtins.property
    @pulumi.getter(name="authenticationMode")
    def authentication_mode(self) -> pulumi.Input['OciCacheUserAuthenticationModeArgs']:
        """
        (Updatable) These are the Authentication details of an Oracle Cloud Infrastructure cache user.
        """
        return pulumi.get(self, "authentication_mode")

    @authentication_mode.setter
    def authentication_mode(self, value: pulumi.Input['OciCacheUserAuthenticationModeArgs']):
        pulumi.set(self, "authentication_mode", value)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) Oracle Cloud Infrastructure cache user compartment ID.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter
    def description(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) Description of Oracle Cloud Infrastructure cache user.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "description", value)

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
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "freeform_tags", value)

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Oracle Cloud Infrastructure cache user name is required to connect to an Oracle Cloud Infrastructure cache cluster.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def status(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Oracle Cloud Infrastructure cache user status. ON enables and OFF disables the Oracle Cloud Infrastructure cache user to login to the associated clusters. Default value is ON.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "status")

    @status.setter
    def status(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "status", value)


@pulumi.input_type
class _OciCacheUserState:
    def __init__(__self__, *,
                 acl_string: Optional[pulumi.Input[_builtins.str]] = None,
                 authentication_mode: Optional[pulumi.Input['OciCacheUserAuthenticationModeArgs']] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 description: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 state: Optional[pulumi.Input[_builtins.str]] = None,
                 status: Optional[pulumi.Input[_builtins.str]] = None,
                 system_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 time_created: Optional[pulumi.Input[_builtins.str]] = None,
                 time_updated: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering OciCacheUser resources.
        :param pulumi.Input[_builtins.str] acl_string: (Updatable) ACL string of Oracle Cloud Infrastructure cache user.
        :param pulumi.Input['OciCacheUserAuthenticationModeArgs'] authentication_mode: (Updatable) These are the Authentication details of an Oracle Cloud Infrastructure cache user.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) Oracle Cloud Infrastructure cache user compartment ID.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[_builtins.str] description: (Updatable) Description of Oracle Cloud Infrastructure cache user.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[_builtins.str] name: Oracle Cloud Infrastructure cache user name is required to connect to an Oracle Cloud Infrastructure cache cluster.
        :param pulumi.Input[_builtins.str] state: Oracle Cloud Infrastructure Cache user lifecycle state.
        :param pulumi.Input[_builtins.str] status: (Updatable) Oracle Cloud Infrastructure cache user status. ON enables and OFF disables the Oracle Cloud Infrastructure cache user to login to the associated clusters. Default value is ON.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[_builtins.str] time_created: The date and time, when the Oracle Cloud Infrastructure cache user was created.
        :param pulumi.Input[_builtins.str] time_updated: The date and time, when the Oracle Cloud Infrastructure cache user was updated.
        """
        if acl_string is not None:
            pulumi.set(__self__, "acl_string", acl_string)
        if authentication_mode is not None:
            pulumi.set(__self__, "authentication_mode", authentication_mode)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if status is not None:
            pulumi.set(__self__, "status", status)
        if system_tags is not None:
            pulumi.set(__self__, "system_tags", system_tags)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter(name="aclString")
    def acl_string(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) ACL string of Oracle Cloud Infrastructure cache user.
        """
        return pulumi.get(self, "acl_string")

    @acl_string.setter
    def acl_string(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "acl_string", value)

    @_builtins.property
    @pulumi.getter(name="authenticationMode")
    def authentication_mode(self) -> Optional[pulumi.Input['OciCacheUserAuthenticationModeArgs']]:
        """
        (Updatable) These are the Authentication details of an Oracle Cloud Infrastructure cache user.
        """
        return pulumi.get(self, "authentication_mode")

    @authentication_mode.setter
    def authentication_mode(self, value: Optional[pulumi.Input['OciCacheUserAuthenticationModeArgs']]):
        pulumi.set(self, "authentication_mode", value)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Oracle Cloud Infrastructure cache user compartment ID.
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
        (Updatable) Description of Oracle Cloud Infrastructure cache user.
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
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "freeform_tags", value)

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Oracle Cloud Infrastructure cache user name is required to connect to an Oracle Cloud Infrastructure cache cluster.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Oracle Cloud Infrastructure Cache user lifecycle state.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "state", value)

    @_builtins.property
    @pulumi.getter
    def status(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Oracle Cloud Infrastructure cache user status. ON enables and OFF disables the Oracle Cloud Infrastructure cache user to login to the associated clusters. Default value is ON.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "status")

    @status.setter
    def status(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "status", value)

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @system_tags.setter
    def system_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "system_tags", value)

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The date and time, when the Oracle Cloud Infrastructure cache user was created.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_created", value)

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The date and time, when the Oracle Cloud Infrastructure cache user was updated.
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_updated", value)


@pulumi.type_token("oci:Redis/ociCacheUser:OciCacheUser")
class OciCacheUser(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 acl_string: Optional[pulumi.Input[_builtins.str]] = None,
                 authentication_mode: Optional[pulumi.Input[Union['OciCacheUserAuthenticationModeArgs', 'OciCacheUserAuthenticationModeArgsDict']]] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 description: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 status: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Oci Cache User resource in Oracle Cloud Infrastructure Redis service.

        Creates a new Oracle Cloud Infrastructure Cache user. Oracle Cloud Infrastructure Cache user is required to authenticate to Oracle Cloud Infrastructure Cache cluster.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_oci_cache_user = oci.redis.OciCacheUser("test_oci_cache_user",
            acl_string=oci_cache_user_acl_string,
            authentication_mode={
                "authentication_type": oci_cache_user_authentication_mode_authentication_type,
                "hashed_passwords": oci_cache_user_authentication_mode_hashed_passwords,
            },
            compartment_id=compartment_id,
            description=oci_cache_user_description,
            name=oci_cache_user_name,
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            freeform_tags={
                "bar-key": "value",
            },
            status=oci_cache_user_status)
        ```

        ## Import

        OciCacheUsers can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:Redis/ociCacheUser:OciCacheUser test_oci_cache_user "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] acl_string: (Updatable) ACL string of Oracle Cloud Infrastructure cache user.
        :param pulumi.Input[Union['OciCacheUserAuthenticationModeArgs', 'OciCacheUserAuthenticationModeArgsDict']] authentication_mode: (Updatable) These are the Authentication details of an Oracle Cloud Infrastructure cache user.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) Oracle Cloud Infrastructure cache user compartment ID.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[_builtins.str] description: (Updatable) Description of Oracle Cloud Infrastructure cache user.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[_builtins.str] name: Oracle Cloud Infrastructure cache user name is required to connect to an Oracle Cloud Infrastructure cache cluster.
        :param pulumi.Input[_builtins.str] status: (Updatable) Oracle Cloud Infrastructure cache user status. ON enables and OFF disables the Oracle Cloud Infrastructure cache user to login to the associated clusters. Default value is ON.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: OciCacheUserArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Oci Cache User resource in Oracle Cloud Infrastructure Redis service.

        Creates a new Oracle Cloud Infrastructure Cache user. Oracle Cloud Infrastructure Cache user is required to authenticate to Oracle Cloud Infrastructure Cache cluster.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_oci_cache_user = oci.redis.OciCacheUser("test_oci_cache_user",
            acl_string=oci_cache_user_acl_string,
            authentication_mode={
                "authentication_type": oci_cache_user_authentication_mode_authentication_type,
                "hashed_passwords": oci_cache_user_authentication_mode_hashed_passwords,
            },
            compartment_id=compartment_id,
            description=oci_cache_user_description,
            name=oci_cache_user_name,
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            freeform_tags={
                "bar-key": "value",
            },
            status=oci_cache_user_status)
        ```

        ## Import

        OciCacheUsers can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:Redis/ociCacheUser:OciCacheUser test_oci_cache_user "id"
        ```

        :param str resource_name: The name of the resource.
        :param OciCacheUserArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(OciCacheUserArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 acl_string: Optional[pulumi.Input[_builtins.str]] = None,
                 authentication_mode: Optional[pulumi.Input[Union['OciCacheUserAuthenticationModeArgs', 'OciCacheUserAuthenticationModeArgsDict']]] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 description: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 status: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = OciCacheUserArgs.__new__(OciCacheUserArgs)

            if acl_string is None and not opts.urn:
                raise TypeError("Missing required property 'acl_string'")
            __props__.__dict__["acl_string"] = acl_string
            if authentication_mode is None and not opts.urn:
                raise TypeError("Missing required property 'authentication_mode'")
            __props__.__dict__["authentication_mode"] = authentication_mode
            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            if description is None and not opts.urn:
                raise TypeError("Missing required property 'description'")
            __props__.__dict__["description"] = description
            __props__.__dict__["freeform_tags"] = freeform_tags
            __props__.__dict__["name"] = name
            __props__.__dict__["status"] = status
            __props__.__dict__["state"] = None
            __props__.__dict__["system_tags"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
        super(OciCacheUser, __self__).__init__(
            'oci:Redis/ociCacheUser:OciCacheUser',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            acl_string: Optional[pulumi.Input[_builtins.str]] = None,
            authentication_mode: Optional[pulumi.Input[Union['OciCacheUserAuthenticationModeArgs', 'OciCacheUserAuthenticationModeArgsDict']]] = None,
            compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            description: Optional[pulumi.Input[_builtins.str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            name: Optional[pulumi.Input[_builtins.str]] = None,
            state: Optional[pulumi.Input[_builtins.str]] = None,
            status: Optional[pulumi.Input[_builtins.str]] = None,
            system_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            time_created: Optional[pulumi.Input[_builtins.str]] = None,
            time_updated: Optional[pulumi.Input[_builtins.str]] = None) -> 'OciCacheUser':
        """
        Get an existing OciCacheUser resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] acl_string: (Updatable) ACL string of Oracle Cloud Infrastructure cache user.
        :param pulumi.Input[Union['OciCacheUserAuthenticationModeArgs', 'OciCacheUserAuthenticationModeArgsDict']] authentication_mode: (Updatable) These are the Authentication details of an Oracle Cloud Infrastructure cache user.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) Oracle Cloud Infrastructure cache user compartment ID.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[_builtins.str] description: (Updatable) Description of Oracle Cloud Infrastructure cache user.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[_builtins.str] name: Oracle Cloud Infrastructure cache user name is required to connect to an Oracle Cloud Infrastructure cache cluster.
        :param pulumi.Input[_builtins.str] state: Oracle Cloud Infrastructure Cache user lifecycle state.
        :param pulumi.Input[_builtins.str] status: (Updatable) Oracle Cloud Infrastructure cache user status. ON enables and OFF disables the Oracle Cloud Infrastructure cache user to login to the associated clusters. Default value is ON.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[_builtins.str] time_created: The date and time, when the Oracle Cloud Infrastructure cache user was created.
        :param pulumi.Input[_builtins.str] time_updated: The date and time, when the Oracle Cloud Infrastructure cache user was updated.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _OciCacheUserState.__new__(_OciCacheUserState)

        __props__.__dict__["acl_string"] = acl_string
        __props__.__dict__["authentication_mode"] = authentication_mode
        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["description"] = description
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["name"] = name
        __props__.__dict__["state"] = state
        __props__.__dict__["status"] = status
        __props__.__dict__["system_tags"] = system_tags
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        return OciCacheUser(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="aclString")
    def acl_string(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) ACL string of Oracle Cloud Infrastructure cache user.
        """
        return pulumi.get(self, "acl_string")

    @_builtins.property
    @pulumi.getter(name="authenticationMode")
    def authentication_mode(self) -> pulumi.Output['outputs.OciCacheUserAuthenticationMode']:
        """
        (Updatable) These are the Authentication details of an Oracle Cloud Infrastructure cache user.
        """
        return pulumi.get(self, "authentication_mode")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) Oracle Cloud Infrastructure cache user compartment ID.
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
        (Updatable) Description of Oracle Cloud Infrastructure cache user.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def name(self) -> pulumi.Output[_builtins.str]:
        """
        Oracle Cloud Infrastructure cache user name is required to connect to an Oracle Cloud Infrastructure cache cluster.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter
    def state(self) -> pulumi.Output[_builtins.str]:
        """
        Oracle Cloud Infrastructure Cache user lifecycle state.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter
    def status(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) Oracle Cloud Infrastructure cache user status. ON enables and OFF disables the Oracle Cloud Infrastructure cache user to login to the associated clusters. Default value is ON.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "status")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[_builtins.str]:
        """
        The date and time, when the Oracle Cloud Infrastructure cache user was created.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[_builtins.str]:
        """
        The date and time, when the Oracle Cloud Infrastructure cache user was updated.
        """
        return pulumi.get(self, "time_updated")

