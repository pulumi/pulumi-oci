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

__all__ = [
    'GetIngressGatewayResult',
    'AwaitableGetIngressGatewayResult',
    'get_ingress_gateway',
    'get_ingress_gateway_output',
]

@pulumi.output_type
class GetIngressGatewayResult:
    """
    A collection of values returned by getIngressGateway.
    """
    def __init__(__self__, access_loggings=None, compartment_id=None, defined_tags=None, description=None, freeform_tags=None, hosts=None, id=None, ingress_gateway_id=None, lifecycle_details=None, mesh_id=None, mtls=None, name=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if access_loggings and not isinstance(access_loggings, list):
            raise TypeError("Expected argument 'access_loggings' to be a list")
        pulumi.set(__self__, "access_loggings", access_loggings)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if hosts and not isinstance(hosts, list):
            raise TypeError("Expected argument 'hosts' to be a list")
        pulumi.set(__self__, "hosts", hosts)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if ingress_gateway_id and not isinstance(ingress_gateway_id, str):
            raise TypeError("Expected argument 'ingress_gateway_id' to be a str")
        pulumi.set(__self__, "ingress_gateway_id", ingress_gateway_id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if mesh_id and not isinstance(mesh_id, str):
            raise TypeError("Expected argument 'mesh_id' to be a str")
        pulumi.set(__self__, "mesh_id", mesh_id)
        if mtls and not isinstance(mtls, list):
            raise TypeError("Expected argument 'mtls' to be a list")
        pulumi.set(__self__, "mtls", mtls)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="accessLoggings")
    def access_loggings(self) -> Sequence['outputs.GetIngressGatewayAccessLoggingResult']:
        """
        This configuration determines if logging is enabled and where the logs will be output.
        """
        return pulumi.get(self, "access_loggings")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def hosts(self) -> Sequence['outputs.GetIngressGatewayHostResult']:
        """
        Array of hostnames and their listener configuration that this gateway will bind to.
        """
        return pulumi.get(self, "hosts")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="ingressGatewayId")
    def ingress_gateway_id(self) -> str:
        return pulumi.get(self, "ingress_gateway_id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="meshId")
    def mesh_id(self) -> str:
        """
        The OCID of the service mesh in which this ingress gateway is created.
        """
        return pulumi.get(self, "mesh_id")

    @property
    @pulumi.getter
    def mtls(self) -> Sequence['outputs.GetIngressGatewayMtlResult']:
        """
        Mutual TLS settings used when sending requests to virtual services within the mesh.
        """
        return pulumi.get(self, "mtls")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the Resource.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time when this resource was created in an RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time when this resource was updated in an RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetIngressGatewayResult(GetIngressGatewayResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetIngressGatewayResult(
            access_loggings=self.access_loggings,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            freeform_tags=self.freeform_tags,
            hosts=self.hosts,
            id=self.id,
            ingress_gateway_id=self.ingress_gateway_id,
            lifecycle_details=self.lifecycle_details,
            mesh_id=self.mesh_id,
            mtls=self.mtls,
            name=self.name,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_ingress_gateway(ingress_gateway_id: Optional[str] = None,
                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetIngressGatewayResult:
    """
    This data source provides details about a specific Ingress Gateway resource in Oracle Cloud Infrastructure Service Mesh service.

    Gets an IngressGateway by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_ingress_gateway = oci.ServiceMesh.get_ingress_gateway(ingress_gateway_id=oci_service_mesh_ingress_gateway["test_ingress_gateway"]["id"])
    ```


    :param str ingress_gateway_id: Unique IngressGateway identifier.
    """
    __args__ = dict()
    __args__['ingressGatewayId'] = ingress_gateway_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ServiceMesh/getIngressGateway:getIngressGateway', __args__, opts=opts, typ=GetIngressGatewayResult).value

    return AwaitableGetIngressGatewayResult(
        access_loggings=__ret__.access_loggings,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        description=__ret__.description,
        freeform_tags=__ret__.freeform_tags,
        hosts=__ret__.hosts,
        id=__ret__.id,
        ingress_gateway_id=__ret__.ingress_gateway_id,
        lifecycle_details=__ret__.lifecycle_details,
        mesh_id=__ret__.mesh_id,
        mtls=__ret__.mtls,
        name=__ret__.name,
        state=__ret__.state,
        system_tags=__ret__.system_tags,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)


@_utilities.lift_output_func(get_ingress_gateway)
def get_ingress_gateway_output(ingress_gateway_id: Optional[pulumi.Input[str]] = None,
                               opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetIngressGatewayResult]:
    """
    This data source provides details about a specific Ingress Gateway resource in Oracle Cloud Infrastructure Service Mesh service.

    Gets an IngressGateway by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_ingress_gateway = oci.ServiceMesh.get_ingress_gateway(ingress_gateway_id=oci_service_mesh_ingress_gateway["test_ingress_gateway"]["id"])
    ```


    :param str ingress_gateway_id: Unique IngressGateway identifier.
    """
    ...