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

__all__ = ['NetworkSourceArgs', 'NetworkSource']

@pulumi.input_type
class NetworkSourceArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 description: pulumi.Input[str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 public_source_lists: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 services: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 virtual_source_lists: Optional[pulumi.Input[Sequence[pulumi.Input['NetworkSourceVirtualSourceListArgs']]]] = None):
        """
        The set of arguments for constructing a NetworkSource resource.
        :param pulumi.Input[str] compartment_id: The OCID of the tenancy (root compartment) containing the network source object.
        :param pulumi.Input[str] description: (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it's changeable.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] name: The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] public_source_lists: (Updatable) A list of allowed public IP addresses and CIDR ranges.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] services: (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
        :param pulumi.Input[Sequence[pulumi.Input['NetworkSourceVirtualSourceListArgs']]] virtual_source_lists: (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`"vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID", "ipRanges": [ "129.213.39.0/24" ]`
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "description", description)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if public_source_lists is not None:
            pulumi.set(__self__, "public_source_lists", public_source_lists)
        if services is not None:
            pulumi.set(__self__, "services", services)
        if virtual_source_lists is not None:
            pulumi.set(__self__, "virtual_source_lists", virtual_source_lists)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        The OCID of the tenancy (root compartment) containing the network source object.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter
    def description(self) -> pulumi.Input[str]:
        """
        (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it's changeable.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: pulumi.Input[str]):
        pulumi.set(self, "description", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter(name="publicSourceLists")
    def public_source_lists(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        (Updatable) A list of allowed public IP addresses and CIDR ranges.
        """
        return pulumi.get(self, "public_source_lists")

    @public_source_lists.setter
    def public_source_lists(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "public_source_lists", value)

    @property
    @pulumi.getter
    def services(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
        """
        return pulumi.get(self, "services")

    @services.setter
    def services(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "services", value)

    @property
    @pulumi.getter(name="virtualSourceLists")
    def virtual_source_lists(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['NetworkSourceVirtualSourceListArgs']]]]:
        """
        (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`"vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID", "ipRanges": [ "129.213.39.0/24" ]`
        """
        return pulumi.get(self, "virtual_source_lists")

    @virtual_source_lists.setter
    def virtual_source_lists(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['NetworkSourceVirtualSourceListArgs']]]]):
        pulumi.set(self, "virtual_source_lists", value)


@pulumi.input_type
class _NetworkSourceState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 inactive_state: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 public_source_lists: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 services: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 virtual_source_lists: Optional[pulumi.Input[Sequence[pulumi.Input['NetworkSourceVirtualSourceListArgs']]]] = None):
        """
        Input properties used for looking up and filtering NetworkSource resources.
        :param pulumi.Input[str] compartment_id: The OCID of the tenancy (root compartment) containing the network source object.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] description: (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it's changeable.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] inactive_state: The detailed status of INACTIVE lifecycleState.
        :param pulumi.Input[str] name: The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] public_source_lists: (Updatable) A list of allowed public IP addresses and CIDR ranges.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] services: (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
        :param pulumi.Input[str] state: The network source object's current state. After creating a network source, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
        :param pulumi.Input[str] time_created: Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        :param pulumi.Input[Sequence[pulumi.Input['NetworkSourceVirtualSourceListArgs']]] virtual_source_lists: (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`"vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID", "ipRanges": [ "129.213.39.0/24" ]`
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if inactive_state is not None:
            pulumi.set(__self__, "inactive_state", inactive_state)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if public_source_lists is not None:
            pulumi.set(__self__, "public_source_lists", public_source_lists)
        if services is not None:
            pulumi.set(__self__, "services", services)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if virtual_source_lists is not None:
            pulumi.set(__self__, "virtual_source_lists", virtual_source_lists)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the tenancy (root compartment) containing the network source object.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it's changeable.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "description", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter(name="inactiveState")
    def inactive_state(self) -> Optional[pulumi.Input[str]]:
        """
        The detailed status of INACTIVE lifecycleState.
        """
        return pulumi.get(self, "inactive_state")

    @inactive_state.setter
    def inactive_state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "inactive_state", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter(name="publicSourceLists")
    def public_source_lists(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        (Updatable) A list of allowed public IP addresses and CIDR ranges.
        """
        return pulumi.get(self, "public_source_lists")

    @public_source_lists.setter
    def public_source_lists(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "public_source_lists", value)

    @property
    @pulumi.getter
    def services(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
        """
        return pulumi.get(self, "services")

    @services.setter
    def services(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "services", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The network source object's current state. After creating a network source, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="virtualSourceLists")
    def virtual_source_lists(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['NetworkSourceVirtualSourceListArgs']]]]:
        """
        (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`"vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID", "ipRanges": [ "129.213.39.0/24" ]`
        """
        return pulumi.get(self, "virtual_source_lists")

    @virtual_source_lists.setter
    def virtual_source_lists(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['NetworkSourceVirtualSourceListArgs']]]]):
        pulumi.set(self, "virtual_source_lists", value)


class NetworkSource(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 public_source_lists: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 services: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 virtual_source_lists: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['NetworkSourceVirtualSourceListArgs']]]]] = None,
                 __props__=None):
        """
        This resource provides the Network Source resource in Oracle Cloud Infrastructure Identity service.

        Creates a new network source in your tenancy.

        You must specify your tenancy's OCID as the compartment ID in the request object (remember that the tenancy
        is simply the root compartment). Notice that IAM resources (users, groups, compartments, and some policies)
        reside within the tenancy itself, unlike cloud resources such as compute instances, which typically
        reside within compartments inside the tenancy. For information about OCIDs, see
        [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).

        You must also specify a *name* for the network source, which must be unique across all network sources in your
        tenancy, and cannot be changed.
        You can use this name or the OCID when writing policies that apply to the network source. For more information
        about policies, see [How Policies Work](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policies.htm).

        You must also specify a *description* for the network source (although it can be an empty string). It does not
        have to be unique, and you can change it anytime with [UpdateNetworkSource](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/NetworkSource/UpdateNetworkSource).
        After your network resource is created, you can use it in policy to restrict access to only requests made from an allowed
        IP address specified in your network source. For more information, see [Managing Network Sources](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingnetworksources.htm).

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_network_source = oci.identity.NetworkSource("testNetworkSource",
            compartment_id=var["tenancy_ocid"],
            description=var["network_source_description"],
            defined_tags={
                "Operations.CostCenter": "42",
            },
            freeform_tags={
                "Department": "Finance",
            },
            public_source_lists=var["network_source_public_source_list"],
            services=var["network_source_services"],
            virtual_source_lists=var["network_source_virtual_source_list"])
        ```

        ## Import

        NetworkSources can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:Identity/networkSource:NetworkSource test_network_source "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: The OCID of the tenancy (root compartment) containing the network source object.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] description: (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it's changeable.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] name: The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] public_source_lists: (Updatable) A list of allowed public IP addresses and CIDR ranges.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] services: (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['NetworkSourceVirtualSourceListArgs']]]] virtual_source_lists: (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`"vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID", "ipRanges": [ "129.213.39.0/24" ]`
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: NetworkSourceArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Network Source resource in Oracle Cloud Infrastructure Identity service.

        Creates a new network source in your tenancy.

        You must specify your tenancy's OCID as the compartment ID in the request object (remember that the tenancy
        is simply the root compartment). Notice that IAM resources (users, groups, compartments, and some policies)
        reside within the tenancy itself, unlike cloud resources such as compute instances, which typically
        reside within compartments inside the tenancy. For information about OCIDs, see
        [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).

        You must also specify a *name* for the network source, which must be unique across all network sources in your
        tenancy, and cannot be changed.
        You can use this name or the OCID when writing policies that apply to the network source. For more information
        about policies, see [How Policies Work](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policies.htm).

        You must also specify a *description* for the network source (although it can be an empty string). It does not
        have to be unique, and you can change it anytime with [UpdateNetworkSource](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/NetworkSource/UpdateNetworkSource).
        After your network resource is created, you can use it in policy to restrict access to only requests made from an allowed
        IP address specified in your network source. For more information, see [Managing Network Sources](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingnetworksources.htm).

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_network_source = oci.identity.NetworkSource("testNetworkSource",
            compartment_id=var["tenancy_ocid"],
            description=var["network_source_description"],
            defined_tags={
                "Operations.CostCenter": "42",
            },
            freeform_tags={
                "Department": "Finance",
            },
            public_source_lists=var["network_source_public_source_list"],
            services=var["network_source_services"],
            virtual_source_lists=var["network_source_virtual_source_list"])
        ```

        ## Import

        NetworkSources can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:Identity/networkSource:NetworkSource test_network_source "id"
        ```

        :param str resource_name: The name of the resource.
        :param NetworkSourceArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(NetworkSourceArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 public_source_lists: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 services: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 virtual_source_lists: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['NetworkSourceVirtualSourceListArgs']]]]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = NetworkSourceArgs.__new__(NetworkSourceArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            if description is None and not opts.urn:
                raise TypeError("Missing required property 'description'")
            __props__.__dict__["description"] = description
            __props__.__dict__["freeform_tags"] = freeform_tags
            __props__.__dict__["name"] = name
            __props__.__dict__["public_source_lists"] = public_source_lists
            __props__.__dict__["services"] = services
            __props__.__dict__["virtual_source_lists"] = virtual_source_lists
            __props__.__dict__["inactive_state"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["time_created"] = None
        super(NetworkSource, __self__).__init__(
            'oci:Identity/networkSource:NetworkSource',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            description: Optional[pulumi.Input[str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            inactive_state: Optional[pulumi.Input[str]] = None,
            name: Optional[pulumi.Input[str]] = None,
            public_source_lists: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
            services: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
            state: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            virtual_source_lists: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['NetworkSourceVirtualSourceListArgs']]]]] = None) -> 'NetworkSource':
        """
        Get an existing NetworkSource resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: The OCID of the tenancy (root compartment) containing the network source object.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] description: (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it's changeable.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] inactive_state: The detailed status of INACTIVE lifecycleState.
        :param pulumi.Input[str] name: The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] public_source_lists: (Updatable) A list of allowed public IP addresses and CIDR ranges.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] services: (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
        :param pulumi.Input[str] state: The network source object's current state. After creating a network source, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
        :param pulumi.Input[str] time_created: Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['NetworkSourceVirtualSourceListArgs']]]] virtual_source_lists: (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`"vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID", "ipRanges": [ "129.213.39.0/24" ]`
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _NetworkSourceState.__new__(_NetworkSourceState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["description"] = description
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["inactive_state"] = inactive_state
        __props__.__dict__["name"] = name
        __props__.__dict__["public_source_lists"] = public_source_lists
        __props__.__dict__["services"] = services
        __props__.__dict__["state"] = state
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["virtual_source_lists"] = virtual_source_lists
        return NetworkSource(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        The OCID of the tenancy (root compartment) containing the network source object.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> pulumi.Output[str]:
        """
        (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it's changeable.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="inactiveState")
    def inactive_state(self) -> pulumi.Output[str]:
        """
        The detailed status of INACTIVE lifecycleState.
        """
        return pulumi.get(self, "inactive_state")

    @property
    @pulumi.getter
    def name(self) -> pulumi.Output[str]:
        """
        The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="publicSourceLists")
    def public_source_lists(self) -> pulumi.Output[Sequence[str]]:
        """
        (Updatable) A list of allowed public IP addresses and CIDR ranges.
        """
        return pulumi.get(self, "public_source_lists")

    @property
    @pulumi.getter
    def services(self) -> pulumi.Output[Sequence[str]]:
        """
        (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
        """
        return pulumi.get(self, "services")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The network source object's current state. After creating a network source, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="virtualSourceLists")
    def virtual_source_lists(self) -> pulumi.Output[Sequence['outputs.NetworkSourceVirtualSourceList']]:
        """
        (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`"vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID", "ipRanges": [ "129.213.39.0/24" ]`
        """
        return pulumi.get(self, "virtual_source_lists")
