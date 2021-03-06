# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = ['ZoneArgs', 'Zone']

@pulumi.input_type
class ZoneArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 zone_type: pulumi.Input[str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 external_masters: Optional[pulumi.Input[Sequence[pulumi.Input['ZoneExternalMasterArgs']]]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 scope: Optional[pulumi.Input[str]] = None,
                 view_id: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a Zone resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The OCID of the compartment the resource belongs to.
        :param pulumi.Input[str] zone_type: The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        :param pulumi.Input[Sequence[pulumi.Input['ZoneExternalMasterArgs']]] external_masters: (Updatable) External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        :param pulumi.Input[str] name: The name of the zone.
        :param pulumi.Input[str] scope: Specifies to operate only on resources that have a matching DNS scope. 
               This value will be null for zones in the global DNS and `PRIVATE` when creating a private zone.
        :param pulumi.Input[str] view_id: The OCID of the private view containing the zone. This value will be null for zones in the global DNS, which are publicly resolvable and not part of a private view.
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "zone_type", zone_type)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if external_masters is not None:
            pulumi.set(__self__, "external_masters", external_masters)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if scope is not None:
            pulumi.set(__self__, "scope", scope)
        if view_id is not None:
            pulumi.set(__self__, "view_id", view_id)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        (Updatable) The OCID of the compartment the resource belongs to.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="zoneType")
    def zone_type(self) -> pulumi.Input[str]:
        """
        The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
        """
        return pulumi.get(self, "zone_type")

    @zone_type.setter
    def zone_type(self, value: pulumi.Input[str]):
        pulumi.set(self, "zone_type", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter(name="externalMasters")
    def external_masters(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ZoneExternalMasterArgs']]]]:
        """
        (Updatable) External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
        """
        return pulumi.get(self, "external_masters")

    @external_masters.setter
    def external_masters(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ZoneExternalMasterArgs']]]]):
        pulumi.set(self, "external_masters", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        The name of the zone.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def scope(self) -> Optional[pulumi.Input[str]]:
        """
        Specifies to operate only on resources that have a matching DNS scope. 
        This value will be null for zones in the global DNS and `PRIVATE` when creating a private zone.
        """
        return pulumi.get(self, "scope")

    @scope.setter
    def scope(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "scope", value)

    @property
    @pulumi.getter(name="viewId")
    def view_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the private view containing the zone. This value will be null for zones in the global DNS, which are publicly resolvable and not part of a private view.
        """
        return pulumi.get(self, "view_id")

    @view_id.setter
    def view_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "view_id", value)


@pulumi.input_type
class _ZoneState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 external_masters: Optional[pulumi.Input[Sequence[pulumi.Input['ZoneExternalMasterArgs']]]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 is_protected: Optional[pulumi.Input[bool]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 nameservers: Optional[pulumi.Input[Sequence[pulumi.Input['ZoneNameserverArgs']]]] = None,
                 scope: Optional[pulumi.Input[str]] = None,
                 self: Optional[pulumi.Input[str]] = None,
                 serial: Optional[pulumi.Input[int]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 version: Optional[pulumi.Input[str]] = None,
                 view_id: Optional[pulumi.Input[str]] = None,
                 zone_type: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering Zone resources.
        :param pulumi.Input[str] compartment_id: (Updatable) The OCID of the compartment the resource belongs to.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        :param pulumi.Input[Sequence[pulumi.Input['ZoneExternalMasterArgs']]] external_masters: (Updatable) External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        :param pulumi.Input[bool] is_protected: A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
        :param pulumi.Input[str] name: The name of the zone.
        :param pulumi.Input[Sequence[pulumi.Input['ZoneNameserverArgs']]] nameservers: The authoritative nameservers for the zone.
        :param pulumi.Input[str] scope: Specifies to operate only on resources that have a matching DNS scope. 
               This value will be null for zones in the global DNS and `PRIVATE` when creating a private zone.
        :param pulumi.Input[str] self: The canonical absolute URL of the resource.
        :param pulumi.Input[int] serial: The current serial of the zone. As seen in the zone's SOA record.
        :param pulumi.Input[str] state: The current state of the zone resource.
        :param pulumi.Input[str] time_created: The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        :param pulumi.Input[str] version: Version is the never-repeating, totally-orderable, version of the zone, from which the serial field of the zone's SOA record is derived.
        :param pulumi.Input[str] view_id: The OCID of the private view containing the zone. This value will be null for zones in the global DNS, which are publicly resolvable and not part of a private view.
        :param pulumi.Input[str] zone_type: The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if external_masters is not None:
            pulumi.set(__self__, "external_masters", external_masters)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if is_protected is not None:
            pulumi.set(__self__, "is_protected", is_protected)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if nameservers is not None:
            pulumi.set(__self__, "nameservers", nameservers)
        if scope is not None:
            pulumi.set(__self__, "scope", scope)
        if self is not None:
            pulumi.set(__self__, "self", self)
        if serial is not None:
            pulumi.set(__self__, "serial", serial)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if version is not None:
            pulumi.set(__self__, "version", version)
        if view_id is not None:
            pulumi.set(__self__, "view_id", view_id)
        if zone_type is not None:
            pulumi.set(__self__, "zone_type", zone_type)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The OCID of the compartment the resource belongs to.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter(name="externalMasters")
    def external_masters(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ZoneExternalMasterArgs']]]]:
        """
        (Updatable) External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
        """
        return pulumi.get(self, "external_masters")

    @external_masters.setter
    def external_masters(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ZoneExternalMasterArgs']]]]):
        pulumi.set(self, "external_masters", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter(name="isProtected")
    def is_protected(self) -> Optional[pulumi.Input[bool]]:
        """
        A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
        """
        return pulumi.get(self, "is_protected")

    @is_protected.setter
    def is_protected(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_protected", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        The name of the zone.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def nameservers(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ZoneNameserverArgs']]]]:
        """
        The authoritative nameservers for the zone.
        """
        return pulumi.get(self, "nameservers")

    @nameservers.setter
    def nameservers(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ZoneNameserverArgs']]]]):
        pulumi.set(self, "nameservers", value)

    @property
    @pulumi.getter
    def scope(self) -> Optional[pulumi.Input[str]]:
        """
        Specifies to operate only on resources that have a matching DNS scope. 
        This value will be null for zones in the global DNS and `PRIVATE` when creating a private zone.
        """
        return pulumi.get(self, "scope")

    @scope.setter
    def scope(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "scope", value)

    @property
    @pulumi.getter
    def self(self) -> Optional[pulumi.Input[str]]:
        """
        The canonical absolute URL of the resource.
        """
        return pulumi.get(self, "self")

    @self.setter
    def self(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "self", value)

    @property
    @pulumi.getter
    def serial(self) -> Optional[pulumi.Input[int]]:
        """
        The current serial of the zone. As seen in the zone's SOA record.
        """
        return pulumi.get(self, "serial")

    @serial.setter
    def serial(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "serial", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current state of the zone resource.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter
    def version(self) -> Optional[pulumi.Input[str]]:
        """
        Version is the never-repeating, totally-orderable, version of the zone, from which the serial field of the zone's SOA record is derived.
        """
        return pulumi.get(self, "version")

    @version.setter
    def version(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "version", value)

    @property
    @pulumi.getter(name="viewId")
    def view_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the private view containing the zone. This value will be null for zones in the global DNS, which are publicly resolvable and not part of a private view.
        """
        return pulumi.get(self, "view_id")

    @view_id.setter
    def view_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "view_id", value)

    @property
    @pulumi.getter(name="zoneType")
    def zone_type(self) -> Optional[pulumi.Input[str]]:
        """
        The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
        """
        return pulumi.get(self, "zone_type")

    @zone_type.setter
    def zone_type(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "zone_type", value)


class Zone(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 external_masters: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZoneExternalMasterArgs']]]]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 scope: Optional[pulumi.Input[str]] = None,
                 view_id: Optional[pulumi.Input[str]] = None,
                 zone_type: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Zone resource in Oracle Cloud Infrastructure DNS service.

        Creates a new zone in the specified compartment. Additionally, for Private DNS,
        the `scope` and `viewId` query parameters are required when creating private zones.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_zone = oci.dns.Zone("testZone",
            compartment_id=var["compartment_id"],
            zone_type=var["zone_zone_type"],
            defined_tags=var["zone_defined_tags"],
            external_masters=[oci.dns.ZoneExternalMasterArgs(
                address=var["zone_external_masters_address"],
                port=var["zone_external_masters_port"],
                tsig_key_id=oci_dns_tsig_key["test_tsig_key"]["id"],
            )],
            freeform_tags=var["zone_freeform_tags"],
            scope=var["zone_scope"],
            view_id=oci_dns_view["test_view"]["id"])
        ```

        ## Import

        For legacy Zones that were created without using `scope`, these Zones can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:Dns/zone:Zone test_zone "id"
        ```

         For Zones created using `scope` and `view_id`, these Zones can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:Dns/zone:Zone test_zone "zoneNameOrId/{zoneNameOrId}/scope/{scope}/viewId/{viewId}"
        ```

         skip adding `{view_id}` at the end if Zone was created without `view_id`.

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The OCID of the compartment the resource belongs to.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZoneExternalMasterArgs']]]] external_masters: (Updatable) External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        :param pulumi.Input[str] name: The name of the zone.
        :param pulumi.Input[str] scope: Specifies to operate only on resources that have a matching DNS scope. 
               This value will be null for zones in the global DNS and `PRIVATE` when creating a private zone.
        :param pulumi.Input[str] view_id: The OCID of the private view containing the zone. This value will be null for zones in the global DNS, which are publicly resolvable and not part of a private view.
        :param pulumi.Input[str] zone_type: The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ZoneArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Zone resource in Oracle Cloud Infrastructure DNS service.

        Creates a new zone in the specified compartment. Additionally, for Private DNS,
        the `scope` and `viewId` query parameters are required when creating private zones.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_zone = oci.dns.Zone("testZone",
            compartment_id=var["compartment_id"],
            zone_type=var["zone_zone_type"],
            defined_tags=var["zone_defined_tags"],
            external_masters=[oci.dns.ZoneExternalMasterArgs(
                address=var["zone_external_masters_address"],
                port=var["zone_external_masters_port"],
                tsig_key_id=oci_dns_tsig_key["test_tsig_key"]["id"],
            )],
            freeform_tags=var["zone_freeform_tags"],
            scope=var["zone_scope"],
            view_id=oci_dns_view["test_view"]["id"])
        ```

        ## Import

        For legacy Zones that were created without using `scope`, these Zones can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:Dns/zone:Zone test_zone "id"
        ```

         For Zones created using `scope` and `view_id`, these Zones can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:Dns/zone:Zone test_zone "zoneNameOrId/{zoneNameOrId}/scope/{scope}/viewId/{viewId}"
        ```

         skip adding `{view_id}` at the end if Zone was created without `view_id`.

        :param str resource_name: The name of the resource.
        :param ZoneArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ZoneArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 external_masters: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZoneExternalMasterArgs']]]]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 scope: Optional[pulumi.Input[str]] = None,
                 view_id: Optional[pulumi.Input[str]] = None,
                 zone_type: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        if opts is None:
            opts = pulumi.ResourceOptions()
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.version is None:
            opts.version = _utilities.get_version()
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = ZoneArgs.__new__(ZoneArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            __props__.__dict__["external_masters"] = external_masters
            __props__.__dict__["freeform_tags"] = freeform_tags
            __props__.__dict__["name"] = name
            __props__.__dict__["scope"] = scope
            __props__.__dict__["view_id"] = view_id
            if zone_type is None and not opts.urn:
                raise TypeError("Missing required property 'zone_type'")
            __props__.__dict__["zone_type"] = zone_type
            __props__.__dict__["is_protected"] = None
            __props__.__dict__["nameservers"] = None
            __props__.__dict__["self"] = None
            __props__.__dict__["serial"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["version"] = None
        super(Zone, __self__).__init__(
            'oci:Dns/zone:Zone',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            external_masters: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZoneExternalMasterArgs']]]]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            is_protected: Optional[pulumi.Input[bool]] = None,
            name: Optional[pulumi.Input[str]] = None,
            nameservers: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZoneNameserverArgs']]]]] = None,
            scope: Optional[pulumi.Input[str]] = None,
            self: Optional[pulumi.Input[str]] = None,
            serial: Optional[pulumi.Input[int]] = None,
            state: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            version: Optional[pulumi.Input[str]] = None,
            view_id: Optional[pulumi.Input[str]] = None,
            zone_type: Optional[pulumi.Input[str]] = None) -> 'Zone':
        """
        Get an existing Zone resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The OCID of the compartment the resource belongs to.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZoneExternalMasterArgs']]]] external_masters: (Updatable) External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        :param pulumi.Input[bool] is_protected: A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
        :param pulumi.Input[str] name: The name of the zone.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZoneNameserverArgs']]]] nameservers: The authoritative nameservers for the zone.
        :param pulumi.Input[str] scope: Specifies to operate only on resources that have a matching DNS scope. 
               This value will be null for zones in the global DNS and `PRIVATE` when creating a private zone.
        :param pulumi.Input[str] self: The canonical absolute URL of the resource.
        :param pulumi.Input[int] serial: The current serial of the zone. As seen in the zone's SOA record.
        :param pulumi.Input[str] state: The current state of the zone resource.
        :param pulumi.Input[str] time_created: The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        :param pulumi.Input[str] version: Version is the never-repeating, totally-orderable, version of the zone, from which the serial field of the zone's SOA record is derived.
        :param pulumi.Input[str] view_id: The OCID of the private view containing the zone. This value will be null for zones in the global DNS, which are publicly resolvable and not part of a private view.
        :param pulumi.Input[str] zone_type: The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ZoneState.__new__(_ZoneState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["external_masters"] = external_masters
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["is_protected"] = is_protected
        __props__.__dict__["name"] = name
        __props__.__dict__["nameservers"] = nameservers
        __props__.__dict__["scope"] = scope
        __props__.__dict__["self"] = self
        __props__.__dict__["serial"] = serial
        __props__.__dict__["state"] = state
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["version"] = version
        __props__.__dict__["view_id"] = view_id
        __props__.__dict__["zone_type"] = zone_type
        return Zone(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        (Updatable) The OCID of the compartment the resource belongs to.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="externalMasters")
    def external_masters(self) -> pulumi.Output[Sequence['outputs.ZoneExternalMaster']]:
        """
        (Updatable) External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
        """
        return pulumi.get(self, "external_masters")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="isProtected")
    def is_protected(self) -> pulumi.Output[bool]:
        """
        A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
        """
        return pulumi.get(self, "is_protected")

    @property
    @pulumi.getter
    def name(self) -> pulumi.Output[str]:
        """
        The name of the zone.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def nameservers(self) -> pulumi.Output[Sequence['outputs.ZoneNameserver']]:
        """
        The authoritative nameservers for the zone.
        """
        return pulumi.get(self, "nameservers")

    @property
    @pulumi.getter
    def scope(self) -> pulumi.Output[Optional[str]]:
        """
        Specifies to operate only on resources that have a matching DNS scope. 
        This value will be null for zones in the global DNS and `PRIVATE` when creating a private zone.
        """
        return pulumi.get(self, "scope")

    @property
    @pulumi.getter
    def self(self) -> pulumi.Output[str]:
        """
        The canonical absolute URL of the resource.
        """
        return pulumi.get(self, "self")

    @property
    @pulumi.getter
    def serial(self) -> pulumi.Output[int]:
        """
        The current serial of the zone. As seen in the zone's SOA record.
        """
        return pulumi.get(self, "serial")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current state of the zone resource.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter
    def version(self) -> pulumi.Output[str]:
        """
        Version is the never-repeating, totally-orderable, version of the zone, from which the serial field of the zone's SOA record is derived.
        """
        return pulumi.get(self, "version")

    @property
    @pulumi.getter(name="viewId")
    def view_id(self) -> pulumi.Output[Optional[str]]:
        """
        The OCID of the private view containing the zone. This value will be null for zones in the global DNS, which are publicly resolvable and not part of a private view.
        """
        return pulumi.get(self, "view_id")

    @property
    @pulumi.getter(name="zoneType")
    def zone_type(self) -> pulumi.Output[str]:
        """
        The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
        """
        return pulumi.get(self, "zone_type")

