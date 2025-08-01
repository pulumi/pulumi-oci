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

__all__ = ['OdaPrivateEndpointArgs', 'OdaPrivateEndpoint']

@pulumi.input_type
class OdaPrivateEndpointArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[_builtins.str],
                 subnet_id: pulumi.Input[_builtins.str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 description: Optional[pulumi.Input[_builtins.str]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 nsg_ids: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None):
        """
        The set of arguments for constructing a OdaPrivateEndpoint resource.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that the ODA private endpoint belongs to.
        :param pulumi.Input[_builtins.str] subnet_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[_builtins.str] description: (Updatable) Description of the ODA private endpoint.
        :param pulumi.Input[_builtins.str] display_name: (Updatable) User-defined name for the ODA private endpoint. Avoid entering confidential information. You can change this value.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Example: `{"bar-key": "value"}`
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] nsg_ids: (Updatable) List of [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of [network security groups](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm)
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "subnet_id", subnet_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if nsg_ids is not None:
            pulumi.set(__self__, "nsg_ids", nsg_ids)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that the ODA private endpoint belongs to.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> pulumi.Input[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "subnet_id")

    @subnet_id.setter
    def subnet_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "subnet_id", value)

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "defined_tags", value)

    @_builtins.property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Description of the ODA private endpoint.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "description", value)

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) User-defined name for the ODA private endpoint. Avoid entering confidential information. You can change this value.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "display_name", value)

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "freeform_tags", value)

    @_builtins.property
    @pulumi.getter(name="nsgIds")
    def nsg_ids(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) List of [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of [network security groups](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm)
        """
        return pulumi.get(self, "nsg_ids")

    @nsg_ids.setter
    def nsg_ids(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "nsg_ids", value)


@pulumi.input_type
class _OdaPrivateEndpointState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 description: Optional[pulumi.Input[_builtins.str]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 nsg_ids: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 state: Optional[pulumi.Input[_builtins.str]] = None,
                 subnet_id: Optional[pulumi.Input[_builtins.str]] = None,
                 time_created: Optional[pulumi.Input[_builtins.str]] = None,
                 time_updated: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering OdaPrivateEndpoint resources.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that the ODA private endpoint belongs to.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[_builtins.str] description: (Updatable) Description of the ODA private endpoint.
        :param pulumi.Input[_builtins.str] display_name: (Updatable) User-defined name for the ODA private endpoint. Avoid entering confidential information. You can change this value.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Example: `{"bar-key": "value"}`
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] nsg_ids: (Updatable) List of [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of [network security groups](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm)
        :param pulumi.Input[_builtins.str] state: The current state of the ODA private endpoint.
        :param pulumi.Input[_builtins.str] subnet_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] time_created: When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        :param pulumi.Input[_builtins.str] time_updated: When the resource was last updated. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if nsg_ids is not None:
            pulumi.set(__self__, "nsg_ids", nsg_ids)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if subnet_id is not None:
            pulumi.set(__self__, "subnet_id", subnet_id)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that the ODA private endpoint belongs to.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "defined_tags", value)

    @_builtins.property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Description of the ODA private endpoint.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "description", value)

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) User-defined name for the ODA private endpoint. Avoid entering confidential information. You can change this value.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "display_name", value)

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "freeform_tags", value)

    @_builtins.property
    @pulumi.getter(name="nsgIds")
    def nsg_ids(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) List of [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of [network security groups](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm)
        """
        return pulumi.get(self, "nsg_ids")

    @nsg_ids.setter
    def nsg_ids(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "nsg_ids", value)

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The current state of the ODA private endpoint.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "state", value)

    @_builtins.property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "subnet_id")

    @subnet_id.setter
    def subnet_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "subnet_id", value)

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_created", value)

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        When the resource was last updated. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_updated", value)


@pulumi.type_token("oci:Oda/odaPrivateEndpoint:OdaPrivateEndpoint")
class OdaPrivateEndpoint(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 description: Optional[pulumi.Input[_builtins.str]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 nsg_ids: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 subnet_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Oda Private Endpoint resource in Oracle Cloud Infrastructure Digital Assistant service.

        Starts an asynchronous job to create an ODA Private Endpoint.

        To monitor the status of the job, take the `opc-work-request-id` response
        header value and use it to call `GET /workRequests/{workRequestID}`.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_oda_private_endpoint = oci.oda.OdaPrivateEndpoint("test_oda_private_endpoint",
            compartment_id=compartment_id,
            subnet_id=test_subnet["id"],
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            description=oda_private_endpoint_description,
            display_name=oda_private_endpoint_display_name,
            freeform_tags={
                "bar-key": "value",
            },
            nsg_ids=oda_private_endpoint_nsg_ids)
        ```

        ## Import

        OdaPrivateEndpoints can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:Oda/odaPrivateEndpoint:OdaPrivateEndpoint test_oda_private_endpoint "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that the ODA private endpoint belongs to.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[_builtins.str] description: (Updatable) Description of the ODA private endpoint.
        :param pulumi.Input[_builtins.str] display_name: (Updatable) User-defined name for the ODA private endpoint. Avoid entering confidential information. You can change this value.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Example: `{"bar-key": "value"}`
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] nsg_ids: (Updatable) List of [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of [network security groups](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm)
        :param pulumi.Input[_builtins.str] subnet_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: OdaPrivateEndpointArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Oda Private Endpoint resource in Oracle Cloud Infrastructure Digital Assistant service.

        Starts an asynchronous job to create an ODA Private Endpoint.

        To monitor the status of the job, take the `opc-work-request-id` response
        header value and use it to call `GET /workRequests/{workRequestID}`.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_oda_private_endpoint = oci.oda.OdaPrivateEndpoint("test_oda_private_endpoint",
            compartment_id=compartment_id,
            subnet_id=test_subnet["id"],
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            description=oda_private_endpoint_description,
            display_name=oda_private_endpoint_display_name,
            freeform_tags={
                "bar-key": "value",
            },
            nsg_ids=oda_private_endpoint_nsg_ids)
        ```

        ## Import

        OdaPrivateEndpoints can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:Oda/odaPrivateEndpoint:OdaPrivateEndpoint test_oda_private_endpoint "id"
        ```

        :param str resource_name: The name of the resource.
        :param OdaPrivateEndpointArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(OdaPrivateEndpointArgs, pulumi.ResourceOptions, *args, **kwargs)
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
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 nsg_ids: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 subnet_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = OdaPrivateEndpointArgs.__new__(OdaPrivateEndpointArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            __props__.__dict__["description"] = description
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["freeform_tags"] = freeform_tags
            __props__.__dict__["nsg_ids"] = nsg_ids
            if subnet_id is None and not opts.urn:
                raise TypeError("Missing required property 'subnet_id'")
            __props__.__dict__["subnet_id"] = subnet_id
            __props__.__dict__["state"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
        super(OdaPrivateEndpoint, __self__).__init__(
            'oci:Oda/odaPrivateEndpoint:OdaPrivateEndpoint',
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
            display_name: Optional[pulumi.Input[_builtins.str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            nsg_ids: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
            state: Optional[pulumi.Input[_builtins.str]] = None,
            subnet_id: Optional[pulumi.Input[_builtins.str]] = None,
            time_created: Optional[pulumi.Input[_builtins.str]] = None,
            time_updated: Optional[pulumi.Input[_builtins.str]] = None) -> 'OdaPrivateEndpoint':
        """
        Get an existing OdaPrivateEndpoint resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that the ODA private endpoint belongs to.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[_builtins.str] description: (Updatable) Description of the ODA private endpoint.
        :param pulumi.Input[_builtins.str] display_name: (Updatable) User-defined name for the ODA private endpoint. Avoid entering confidential information. You can change this value.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Example: `{"bar-key": "value"}`
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] nsg_ids: (Updatable) List of [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of [network security groups](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm)
        :param pulumi.Input[_builtins.str] state: The current state of the ODA private endpoint.
        :param pulumi.Input[_builtins.str] subnet_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] time_created: When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        :param pulumi.Input[_builtins.str] time_updated: When the resource was last updated. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _OdaPrivateEndpointState.__new__(_OdaPrivateEndpointState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["description"] = description
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["nsg_ids"] = nsg_ids
        __props__.__dict__["state"] = state
        __props__.__dict__["subnet_id"] = subnet_id
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        return OdaPrivateEndpoint(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that the ODA private endpoint belongs to.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) Description of the ODA private endpoint.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) User-defined name for the ODA private endpoint. Avoid entering confidential information. You can change this value.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter(name="nsgIds")
    def nsg_ids(self) -> pulumi.Output[Sequence[_builtins.str]]:
        """
        (Updatable) List of [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of [network security groups](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm)
        """
        return pulumi.get(self, "nsg_ids")

    @_builtins.property
    @pulumi.getter
    def state(self) -> pulumi.Output[_builtins.str]:
        """
        The current state of the ODA private endpoint.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "subnet_id")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[_builtins.str]:
        """
        When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[_builtins.str]:
        """
        When the resource was last updated. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        """
        return pulumi.get(self, "time_updated")

