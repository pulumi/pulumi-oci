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

__all__ = ['VirtualServiceArgs', 'VirtualService']

@pulumi.input_type
class VirtualServiceArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 mesh_id: pulumi.Input[str],
                 default_routing_policy: Optional[pulumi.Input['VirtualServiceDefaultRoutingPolicyArgs']] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 hosts: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 mtls: Optional[pulumi.Input['VirtualServiceMtlsArgs']] = None,
                 name: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a VirtualService resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        :param pulumi.Input[str] mesh_id: The OCID of the service mesh in which this virtual service is created.
        :param pulumi.Input['VirtualServiceDefaultRoutingPolicyArgs'] default_routing_policy: (Updatable) Routing policy for the virtual service.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] description: (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[Sequence[pulumi.Input[str]]] hosts: (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", "*.example.com", "*.com". Can be omitted if the virtual service will only have TCP virtual deployments.
        :param pulumi.Input['VirtualServiceMtlsArgs'] mtls: (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
        :param pulumi.Input[str] name: A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "mesh_id", mesh_id)
        if default_routing_policy is not None:
            pulumi.set(__self__, "default_routing_policy", default_routing_policy)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if hosts is not None:
            pulumi.set(__self__, "hosts", hosts)
        if mtls is not None:
            pulumi.set(__self__, "mtls", mtls)
        if name is not None:
            pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="meshId")
    def mesh_id(self) -> pulumi.Input[str]:
        """
        The OCID of the service mesh in which this virtual service is created.
        """
        return pulumi.get(self, "mesh_id")

    @mesh_id.setter
    def mesh_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "mesh_id", value)

    @property
    @pulumi.getter(name="defaultRoutingPolicy")
    def default_routing_policy(self) -> Optional[pulumi.Input['VirtualServiceDefaultRoutingPolicyArgs']]:
        """
        (Updatable) Routing policy for the virtual service.
        """
        return pulumi.get(self, "default_routing_policy")

    @default_routing_policy.setter
    def default_routing_policy(self, value: Optional[pulumi.Input['VirtualServiceDefaultRoutingPolicyArgs']]):
        pulumi.set(self, "default_routing_policy", value)

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
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "description", value)

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
    def hosts(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", "*.example.com", "*.com". Can be omitted if the virtual service will only have TCP virtual deployments.
        """
        return pulumi.get(self, "hosts")

    @hosts.setter
    def hosts(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "hosts", value)

    @property
    @pulumi.getter
    def mtls(self) -> Optional[pulumi.Input['VirtualServiceMtlsArgs']]:
        """
        (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
        """
        return pulumi.get(self, "mtls")

    @mtls.setter
    def mtls(self, value: Optional[pulumi.Input['VirtualServiceMtlsArgs']]):
        pulumi.set(self, "mtls", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)


@pulumi.input_type
class _VirtualServiceState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 default_routing_policy: Optional[pulumi.Input['VirtualServiceDefaultRoutingPolicyArgs']] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 hosts: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 lifecycle_details: Optional[pulumi.Input[str]] = None,
                 mesh_id: Optional[pulumi.Input[str]] = None,
                 mtls: Optional[pulumi.Input['VirtualServiceMtlsArgs']] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 system_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering VirtualService resources.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        :param pulumi.Input['VirtualServiceDefaultRoutingPolicyArgs'] default_routing_policy: (Updatable) Routing policy for the virtual service.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] description: (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[Sequence[pulumi.Input[str]]] hosts: (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", "*.example.com", "*.com". Can be omitted if the virtual service will only have TCP virtual deployments.
        :param pulumi.Input[str] lifecycle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
        :param pulumi.Input[str] mesh_id: The OCID of the service mesh in which this virtual service is created.
        :param pulumi.Input['VirtualServiceMtlsArgs'] mtls: (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
        :param pulumi.Input[str] name: A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
        :param pulumi.Input[str] state: The current state of the Resource.
        :param pulumi.Input[Mapping[str, Any]] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[str] time_created: The time when this resource was created in an RFC3339 formatted datetime string.
        :param pulumi.Input[str] time_updated: The time when this resource was updated in an RFC3339 formatted datetime string.
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if default_routing_policy is not None:
            pulumi.set(__self__, "default_routing_policy", default_routing_policy)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if hosts is not None:
            pulumi.set(__self__, "hosts", hosts)
        if lifecycle_details is not None:
            pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if mesh_id is not None:
            pulumi.set(__self__, "mesh_id", mesh_id)
        if mtls is not None:
            pulumi.set(__self__, "mtls", mtls)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if system_tags is not None:
            pulumi.set(__self__, "system_tags", system_tags)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="defaultRoutingPolicy")
    def default_routing_policy(self) -> Optional[pulumi.Input['VirtualServiceDefaultRoutingPolicyArgs']]:
        """
        (Updatable) Routing policy for the virtual service.
        """
        return pulumi.get(self, "default_routing_policy")

    @default_routing_policy.setter
    def default_routing_policy(self, value: Optional[pulumi.Input['VirtualServiceDefaultRoutingPolicyArgs']]):
        pulumi.set(self, "default_routing_policy", value)

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
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "description", value)

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
    def hosts(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", "*.example.com", "*.com". Can be omitted if the virtual service will only have TCP virtual deployments.
        """
        return pulumi.get(self, "hosts")

    @hosts.setter
    def hosts(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "hosts", value)

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> Optional[pulumi.Input[str]]:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @lifecycle_details.setter
    def lifecycle_details(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "lifecycle_details", value)

    @property
    @pulumi.getter(name="meshId")
    def mesh_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the service mesh in which this virtual service is created.
        """
        return pulumi.get(self, "mesh_id")

    @mesh_id.setter
    def mesh_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "mesh_id", value)

    @property
    @pulumi.getter
    def mtls(self) -> Optional[pulumi.Input['VirtualServiceMtlsArgs']]:
        """
        (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
        """
        return pulumi.get(self, "mtls")

    @mtls.setter
    def mtls(self, value: Optional[pulumi.Input['VirtualServiceMtlsArgs']]):
        pulumi.set(self, "mtls", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current state of the Resource.
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
        The time when this resource was created in an RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[str]]:
        """
        The time when this resource was updated in an RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_updated", value)


class VirtualService(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 default_routing_policy: Optional[pulumi.Input[pulumi.InputType['VirtualServiceDefaultRoutingPolicyArgs']]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 hosts: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 mesh_id: Optional[pulumi.Input[str]] = None,
                 mtls: Optional[pulumi.Input[pulumi.InputType['VirtualServiceMtlsArgs']]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Virtual Service resource in Oracle Cloud Infrastructure Service Mesh service.

        Creates a new VirtualService.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_virtual_service = oci.service_mesh.VirtualService("testVirtualService",
            compartment_id=var["compartment_id"],
            mesh_id=oci_service_mesh_mesh["test_mesh"]["id"],
            default_routing_policy=oci.service_mesh.VirtualServiceDefaultRoutingPolicyArgs(
                type=var["virtual_service_default_routing_policy_type"],
            ),
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            description=var["virtual_service_description"],
            freeform_tags={
                "bar-key": "value",
            },
            hosts=var["virtual_service_hosts"],
            mtls=oci.service_mesh.VirtualServiceMtlsArgs(
                mode=var["virtual_service_mtls_mode"],
                maximum_validity=var["virtual_service_mtls_maximum_validity"],
            ))
        ```

        ## Import

        VirtualServices can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:ServiceMesh/virtualService:VirtualService test_virtual_service "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        :param pulumi.Input[pulumi.InputType['VirtualServiceDefaultRoutingPolicyArgs']] default_routing_policy: (Updatable) Routing policy for the virtual service.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] description: (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[Sequence[pulumi.Input[str]]] hosts: (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", "*.example.com", "*.com". Can be omitted if the virtual service will only have TCP virtual deployments.
        :param pulumi.Input[str] mesh_id: The OCID of the service mesh in which this virtual service is created.
        :param pulumi.Input[pulumi.InputType['VirtualServiceMtlsArgs']] mtls: (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
        :param pulumi.Input[str] name: A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: VirtualServiceArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Virtual Service resource in Oracle Cloud Infrastructure Service Mesh service.

        Creates a new VirtualService.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_virtual_service = oci.service_mesh.VirtualService("testVirtualService",
            compartment_id=var["compartment_id"],
            mesh_id=oci_service_mesh_mesh["test_mesh"]["id"],
            default_routing_policy=oci.service_mesh.VirtualServiceDefaultRoutingPolicyArgs(
                type=var["virtual_service_default_routing_policy_type"],
            ),
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            description=var["virtual_service_description"],
            freeform_tags={
                "bar-key": "value",
            },
            hosts=var["virtual_service_hosts"],
            mtls=oci.service_mesh.VirtualServiceMtlsArgs(
                mode=var["virtual_service_mtls_mode"],
                maximum_validity=var["virtual_service_mtls_maximum_validity"],
            ))
        ```

        ## Import

        VirtualServices can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:ServiceMesh/virtualService:VirtualService test_virtual_service "id"
        ```

        :param str resource_name: The name of the resource.
        :param VirtualServiceArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(VirtualServiceArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 default_routing_policy: Optional[pulumi.Input[pulumi.InputType['VirtualServiceDefaultRoutingPolicyArgs']]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 hosts: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 mesh_id: Optional[pulumi.Input[str]] = None,
                 mtls: Optional[pulumi.Input[pulumi.InputType['VirtualServiceMtlsArgs']]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = VirtualServiceArgs.__new__(VirtualServiceArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["default_routing_policy"] = default_routing_policy
            __props__.__dict__["defined_tags"] = defined_tags
            __props__.__dict__["description"] = description
            __props__.__dict__["freeform_tags"] = freeform_tags
            __props__.__dict__["hosts"] = hosts
            if mesh_id is None and not opts.urn:
                raise TypeError("Missing required property 'mesh_id'")
            __props__.__dict__["mesh_id"] = mesh_id
            __props__.__dict__["mtls"] = mtls
            __props__.__dict__["name"] = name
            __props__.__dict__["lifecycle_details"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["system_tags"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
        super(VirtualService, __self__).__init__(
            'oci:ServiceMesh/virtualService:VirtualService',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            default_routing_policy: Optional[pulumi.Input[pulumi.InputType['VirtualServiceDefaultRoutingPolicyArgs']]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            description: Optional[pulumi.Input[str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            hosts: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
            lifecycle_details: Optional[pulumi.Input[str]] = None,
            mesh_id: Optional[pulumi.Input[str]] = None,
            mtls: Optional[pulumi.Input[pulumi.InputType['VirtualServiceMtlsArgs']]] = None,
            name: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            system_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_updated: Optional[pulumi.Input[str]] = None) -> 'VirtualService':
        """
        Get an existing VirtualService resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        :param pulumi.Input[pulumi.InputType['VirtualServiceDefaultRoutingPolicyArgs']] default_routing_policy: (Updatable) Routing policy for the virtual service.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] description: (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[Sequence[pulumi.Input[str]]] hosts: (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", "*.example.com", "*.com". Can be omitted if the virtual service will only have TCP virtual deployments.
        :param pulumi.Input[str] lifecycle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
        :param pulumi.Input[str] mesh_id: The OCID of the service mesh in which this virtual service is created.
        :param pulumi.Input[pulumi.InputType['VirtualServiceMtlsArgs']] mtls: (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
        :param pulumi.Input[str] name: A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
        :param pulumi.Input[str] state: The current state of the Resource.
        :param pulumi.Input[Mapping[str, Any]] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[str] time_created: The time when this resource was created in an RFC3339 formatted datetime string.
        :param pulumi.Input[str] time_updated: The time when this resource was updated in an RFC3339 formatted datetime string.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _VirtualServiceState.__new__(_VirtualServiceState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["default_routing_policy"] = default_routing_policy
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["description"] = description
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["hosts"] = hosts
        __props__.__dict__["lifecycle_details"] = lifecycle_details
        __props__.__dict__["mesh_id"] = mesh_id
        __props__.__dict__["mtls"] = mtls
        __props__.__dict__["name"] = name
        __props__.__dict__["state"] = state
        __props__.__dict__["system_tags"] = system_tags
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        return VirtualService(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="defaultRoutingPolicy")
    def default_routing_policy(self) -> pulumi.Output['outputs.VirtualServiceDefaultRoutingPolicy']:
        """
        (Updatable) Routing policy for the virtual service.
        """
        return pulumi.get(self, "default_routing_policy")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> pulumi.Output[str]:
        """
        (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def hosts(self) -> pulumi.Output[Sequence[str]]:
        """
        (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", "*.example.com", "*.com". Can be omitted if the virtual service will only have TCP virtual deployments.
        """
        return pulumi.get(self, "hosts")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> pulumi.Output[str]:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="meshId")
    def mesh_id(self) -> pulumi.Output[str]:
        """
        The OCID of the service mesh in which this virtual service is created.
        """
        return pulumi.get(self, "mesh_id")

    @property
    @pulumi.getter
    def mtls(self) -> pulumi.Output['outputs.VirtualServiceMtls']:
        """
        (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
        """
        return pulumi.get(self, "mtls")

    @property
    @pulumi.getter
    def name(self) -> pulumi.Output[str]:
        """
        A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current state of the Resource.
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
        The time when this resource was created in an RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[str]:
        """
        The time when this resource was updated in an RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")
