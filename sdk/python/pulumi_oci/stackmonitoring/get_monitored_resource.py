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
    'GetMonitoredResourceResult',
    'AwaitableGetMonitoredResourceResult',
    'get_monitored_resource',
    'get_monitored_resource_output',
]

@pulumi.output_type
class GetMonitoredResourceResult:
    """
    A collection of values returned by getMonitoredResource.
    """
    def __init__(__self__, aliases=None, compartment_id=None, credentials=None, database_connection_details=None, defined_tags=None, display_name=None, external_resource_id=None, freeform_tags=None, host_name=None, id=None, management_agent_id=None, monitored_resource_id=None, name=None, properties=None, resource_time_zone=None, state=None, system_tags=None, tenant_id=None, time_created=None, time_updated=None, type=None):
        if aliases and not isinstance(aliases, list):
            raise TypeError("Expected argument 'aliases' to be a list")
        pulumi.set(__self__, "aliases", aliases)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if credentials and not isinstance(credentials, list):
            raise TypeError("Expected argument 'credentials' to be a list")
        pulumi.set(__self__, "credentials", credentials)
        if database_connection_details and not isinstance(database_connection_details, list):
            raise TypeError("Expected argument 'database_connection_details' to be a list")
        pulumi.set(__self__, "database_connection_details", database_connection_details)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if external_resource_id and not isinstance(external_resource_id, str):
            raise TypeError("Expected argument 'external_resource_id' to be a str")
        pulumi.set(__self__, "external_resource_id", external_resource_id)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if host_name and not isinstance(host_name, str):
            raise TypeError("Expected argument 'host_name' to be a str")
        pulumi.set(__self__, "host_name", host_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if management_agent_id and not isinstance(management_agent_id, str):
            raise TypeError("Expected argument 'management_agent_id' to be a str")
        pulumi.set(__self__, "management_agent_id", management_agent_id)
        if monitored_resource_id and not isinstance(monitored_resource_id, str):
            raise TypeError("Expected argument 'monitored_resource_id' to be a str")
        pulumi.set(__self__, "monitored_resource_id", monitored_resource_id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if properties and not isinstance(properties, list):
            raise TypeError("Expected argument 'properties' to be a list")
        pulumi.set(__self__, "properties", properties)
        if resource_time_zone and not isinstance(resource_time_zone, str):
            raise TypeError("Expected argument 'resource_time_zone' to be a str")
        pulumi.set(__self__, "resource_time_zone", resource_time_zone)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if tenant_id and not isinstance(tenant_id, str):
            raise TypeError("Expected argument 'tenant_id' to be a str")
        pulumi.set(__self__, "tenant_id", tenant_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if type and not isinstance(type, str):
            raise TypeError("Expected argument 'type' to be a str")
        pulumi.set(__self__, "type", type)

    @property
    @pulumi.getter
    def aliases(self) -> Sequence['outputs.GetMonitoredResourceAliasResult']:
        """
        Monitored Resource Alias Credential Details
        """
        return pulumi.get(self, "aliases")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def credentials(self) -> Sequence['outputs.GetMonitoredResourceCredentialResult']:
        """
        Monitored Resource Credential Details
        """
        return pulumi.get(self, "credentials")

    @property
    @pulumi.getter(name="databaseConnectionDetails")
    def database_connection_details(self) -> Sequence['outputs.GetMonitoredResourceDatabaseConnectionDetailResult']:
        """
        Connection details to connect to the database. HostName, protocol, and port should be specified.
        """
        return pulumi.get(self, "database_connection_details")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        Monitored resource display name.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="externalResourceId")
    def external_resource_id(self) -> str:
        return pulumi.get(self, "external_resource_id")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="hostName")
    def host_name(self) -> str:
        """
        Monitored resource host name.
        """
        return pulumi.get(self, "host_name")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="managementAgentId")
    def management_agent_id(self) -> str:
        """
        Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "management_agent_id")

    @property
    @pulumi.getter(name="monitoredResourceId")
    def monitored_resource_id(self) -> str:
        return pulumi.get(self, "monitored_resource_id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        property name
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def properties(self) -> Sequence['outputs.GetMonitoredResourcePropertyResult']:
        """
        List of monitored resource properties
        """
        return pulumi.get(self, "properties")

    @property
    @pulumi.getter(name="resourceTimeZone")
    def resource_time_zone(self) -> str:
        """
        Time zone in the form of tz database canonical zone ID.
        """
        return pulumi.get(self, "resource_time_zone")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        Lifecycle state of the monitored resource.
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
    @pulumi.getter(name="tenantId")
    def tenant_id(self) -> str:
        """
        Tenancy Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        """
        return pulumi.get(self, "tenant_id")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the the resource was created. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the the resource was updated. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter
    def type(self) -> str:
        """
        Monitored resource type
        """
        return pulumi.get(self, "type")


class AwaitableGetMonitoredResourceResult(GetMonitoredResourceResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetMonitoredResourceResult(
            aliases=self.aliases,
            compartment_id=self.compartment_id,
            credentials=self.credentials,
            database_connection_details=self.database_connection_details,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            external_resource_id=self.external_resource_id,
            freeform_tags=self.freeform_tags,
            host_name=self.host_name,
            id=self.id,
            management_agent_id=self.management_agent_id,
            monitored_resource_id=self.monitored_resource_id,
            name=self.name,
            properties=self.properties,
            resource_time_zone=self.resource_time_zone,
            state=self.state,
            system_tags=self.system_tags,
            tenant_id=self.tenant_id,
            time_created=self.time_created,
            time_updated=self.time_updated,
            type=self.type)


def get_monitored_resource(monitored_resource_id: Optional[str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetMonitoredResourceResult:
    """
    This data source provides details about a specific Monitored Resource resource in Oracle Cloud Infrastructure Stack Monitoring service.

    Gets a monitored resource by identifier

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_monitored_resource = oci.StackMonitoring.get_monitored_resource(monitored_resource_id=oci_stack_monitoring_monitored_resource["test_monitored_resource"]["id"])
    ```


    :param str monitored_resource_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored resource.
    """
    __args__ = dict()
    __args__['monitoredResourceId'] = monitored_resource_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:StackMonitoring/getMonitoredResource:getMonitoredResource', __args__, opts=opts, typ=GetMonitoredResourceResult).value

    return AwaitableGetMonitoredResourceResult(
        aliases=__ret__.aliases,
        compartment_id=__ret__.compartment_id,
        credentials=__ret__.credentials,
        database_connection_details=__ret__.database_connection_details,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        external_resource_id=__ret__.external_resource_id,
        freeform_tags=__ret__.freeform_tags,
        host_name=__ret__.host_name,
        id=__ret__.id,
        management_agent_id=__ret__.management_agent_id,
        monitored_resource_id=__ret__.monitored_resource_id,
        name=__ret__.name,
        properties=__ret__.properties,
        resource_time_zone=__ret__.resource_time_zone,
        state=__ret__.state,
        system_tags=__ret__.system_tags,
        tenant_id=__ret__.tenant_id,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated,
        type=__ret__.type)


@_utilities.lift_output_func(get_monitored_resource)
def get_monitored_resource_output(monitored_resource_id: Optional[pulumi.Input[str]] = None,
                                  opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetMonitoredResourceResult]:
    """
    This data source provides details about a specific Monitored Resource resource in Oracle Cloud Infrastructure Stack Monitoring service.

    Gets a monitored resource by identifier

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_monitored_resource = oci.StackMonitoring.get_monitored_resource(monitored_resource_id=oci_stack_monitoring_monitored_resource["test_monitored_resource"]["id"])
    ```


    :param str monitored_resource_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored resource.
    """
    ...