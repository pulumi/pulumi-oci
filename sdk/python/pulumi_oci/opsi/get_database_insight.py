# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs

__all__ = [
    'GetDatabaseInsightResult',
    'AwaitableGetDatabaseInsightResult',
    'get_database_insight',
    'get_database_insight_output',
]

@pulumi.output_type
class GetDatabaseInsightResult:
    """
    A collection of values returned by getDatabaseInsight.
    """
    def __init__(__self__, compartment_id=None, connection_credential_details=None, connection_details=None, credential_details=None, database_connection_status_details=None, database_display_name=None, database_id=None, database_insight_id=None, database_name=None, database_resource_type=None, database_type=None, database_version=None, defined_tags=None, deployment_type=None, enterprise_manager_bridge_id=None, enterprise_manager_entity_display_name=None, enterprise_manager_entity_identifier=None, enterprise_manager_entity_name=None, enterprise_manager_entity_type=None, enterprise_manager_identifier=None, entity_source=None, exadata_insight_id=None, freeform_tags=None, id=None, lifecycle_details=None, opsi_private_endpoint_id=None, processor_count=None, service_name=None, state=None, status=None, system_tags=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if connection_credential_details and not isinstance(connection_credential_details, list):
            raise TypeError("Expected argument 'connection_credential_details' to be a list")
        pulumi.set(__self__, "connection_credential_details", connection_credential_details)
        if connection_details and not isinstance(connection_details, list):
            raise TypeError("Expected argument 'connection_details' to be a list")
        pulumi.set(__self__, "connection_details", connection_details)
        if credential_details and not isinstance(credential_details, list):
            raise TypeError("Expected argument 'credential_details' to be a list")
        pulumi.set(__self__, "credential_details", credential_details)
        if database_connection_status_details and not isinstance(database_connection_status_details, str):
            raise TypeError("Expected argument 'database_connection_status_details' to be a str")
        pulumi.set(__self__, "database_connection_status_details", database_connection_status_details)
        if database_display_name and not isinstance(database_display_name, str):
            raise TypeError("Expected argument 'database_display_name' to be a str")
        pulumi.set(__self__, "database_display_name", database_display_name)
        if database_id and not isinstance(database_id, str):
            raise TypeError("Expected argument 'database_id' to be a str")
        pulumi.set(__self__, "database_id", database_id)
        if database_insight_id and not isinstance(database_insight_id, str):
            raise TypeError("Expected argument 'database_insight_id' to be a str")
        pulumi.set(__self__, "database_insight_id", database_insight_id)
        if database_name and not isinstance(database_name, str):
            raise TypeError("Expected argument 'database_name' to be a str")
        pulumi.set(__self__, "database_name", database_name)
        if database_resource_type and not isinstance(database_resource_type, str):
            raise TypeError("Expected argument 'database_resource_type' to be a str")
        pulumi.set(__self__, "database_resource_type", database_resource_type)
        if database_type and not isinstance(database_type, str):
            raise TypeError("Expected argument 'database_type' to be a str")
        pulumi.set(__self__, "database_type", database_type)
        if database_version and not isinstance(database_version, str):
            raise TypeError("Expected argument 'database_version' to be a str")
        pulumi.set(__self__, "database_version", database_version)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if deployment_type and not isinstance(deployment_type, str):
            raise TypeError("Expected argument 'deployment_type' to be a str")
        pulumi.set(__self__, "deployment_type", deployment_type)
        if enterprise_manager_bridge_id and not isinstance(enterprise_manager_bridge_id, str):
            raise TypeError("Expected argument 'enterprise_manager_bridge_id' to be a str")
        pulumi.set(__self__, "enterprise_manager_bridge_id", enterprise_manager_bridge_id)
        if enterprise_manager_entity_display_name and not isinstance(enterprise_manager_entity_display_name, str):
            raise TypeError("Expected argument 'enterprise_manager_entity_display_name' to be a str")
        pulumi.set(__self__, "enterprise_manager_entity_display_name", enterprise_manager_entity_display_name)
        if enterprise_manager_entity_identifier and not isinstance(enterprise_manager_entity_identifier, str):
            raise TypeError("Expected argument 'enterprise_manager_entity_identifier' to be a str")
        pulumi.set(__self__, "enterprise_manager_entity_identifier", enterprise_manager_entity_identifier)
        if enterprise_manager_entity_name and not isinstance(enterprise_manager_entity_name, str):
            raise TypeError("Expected argument 'enterprise_manager_entity_name' to be a str")
        pulumi.set(__self__, "enterprise_manager_entity_name", enterprise_manager_entity_name)
        if enterprise_manager_entity_type and not isinstance(enterprise_manager_entity_type, str):
            raise TypeError("Expected argument 'enterprise_manager_entity_type' to be a str")
        pulumi.set(__self__, "enterprise_manager_entity_type", enterprise_manager_entity_type)
        if enterprise_manager_identifier and not isinstance(enterprise_manager_identifier, str):
            raise TypeError("Expected argument 'enterprise_manager_identifier' to be a str")
        pulumi.set(__self__, "enterprise_manager_identifier", enterprise_manager_identifier)
        if entity_source and not isinstance(entity_source, str):
            raise TypeError("Expected argument 'entity_source' to be a str")
        pulumi.set(__self__, "entity_source", entity_source)
        if exadata_insight_id and not isinstance(exadata_insight_id, str):
            raise TypeError("Expected argument 'exadata_insight_id' to be a str")
        pulumi.set(__self__, "exadata_insight_id", exadata_insight_id)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if opsi_private_endpoint_id and not isinstance(opsi_private_endpoint_id, str):
            raise TypeError("Expected argument 'opsi_private_endpoint_id' to be a str")
        pulumi.set(__self__, "opsi_private_endpoint_id", opsi_private_endpoint_id)
        if processor_count and not isinstance(processor_count, int):
            raise TypeError("Expected argument 'processor_count' to be a int")
        pulumi.set(__self__, "processor_count", processor_count)
        if service_name and not isinstance(service_name, str):
            raise TypeError("Expected argument 'service_name' to be a str")
        pulumi.set(__self__, "service_name", service_name)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if status and not isinstance(status, str):
            raise TypeError("Expected argument 'status' to be a str")
        pulumi.set(__self__, "status", status)
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
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        Compartment identifier of the database
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="connectionCredentialDetails")
    def connection_credential_details(self) -> Sequence['outputs.GetDatabaseInsightConnectionCredentialDetailResult']:
        """
        User credential details to connect to the database. This is supplied via the External Database Service.
        """
        return pulumi.get(self, "connection_credential_details")

    @property
    @pulumi.getter(name="connectionDetails")
    def connection_details(self) -> Sequence['outputs.GetDatabaseInsightConnectionDetailResult']:
        """
        Connection details to connect to the database. HostName, protocol, and port should be specified.
        """
        return pulumi.get(self, "connection_details")

    @property
    @pulumi.getter(name="credentialDetails")
    def credential_details(self) -> Sequence['outputs.GetDatabaseInsightCredentialDetailResult']:
        """
        User credential details to connect to the database.
        """
        return pulumi.get(self, "credential_details")

    @property
    @pulumi.getter(name="databaseConnectionStatusDetails")
    def database_connection_status_details(self) -> str:
        """
        A message describing the status of the database connection of this resource. For example, it can be used to provide actionable information about the permission and content validity of the database connection.
        """
        return pulumi.get(self, "database_connection_status_details")

    @property
    @pulumi.getter(name="databaseDisplayName")
    def database_display_name(self) -> str:
        """
        Display name of database
        """
        return pulumi.get(self, "database_display_name")

    @property
    @pulumi.getter(name="databaseId")
    def database_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
        """
        return pulumi.get(self, "database_id")

    @property
    @pulumi.getter(name="databaseInsightId")
    def database_insight_id(self) -> str:
        return pulumi.get(self, "database_insight_id")

    @property
    @pulumi.getter(name="databaseName")
    def database_name(self) -> str:
        """
        Name of database
        """
        return pulumi.get(self, "database_name")

    @property
    @pulumi.getter(name="databaseResourceType")
    def database_resource_type(self) -> str:
        """
        Oracle Cloud Infrastructure database resource type
        """
        return pulumi.get(self, "database_resource_type")

    @property
    @pulumi.getter(name="databaseType")
    def database_type(self) -> str:
        """
        Operations Insights internal representation of the database type.
        """
        return pulumi.get(self, "database_type")

    @property
    @pulumi.getter(name="databaseVersion")
    def database_version(self) -> str:
        """
        The version of the database.
        """
        return pulumi.get(self, "database_version")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="deploymentType")
    def deployment_type(self) -> str:
        return pulumi.get(self, "deployment_type")

    @property
    @pulumi.getter(name="enterpriseManagerBridgeId")
    def enterprise_manager_bridge_id(self) -> str:
        """
        OPSI Enterprise Manager Bridge OCID
        """
        return pulumi.get(self, "enterprise_manager_bridge_id")

    @property
    @pulumi.getter(name="enterpriseManagerEntityDisplayName")
    def enterprise_manager_entity_display_name(self) -> str:
        """
        Enterprise Manager Entity Display Name
        """
        return pulumi.get(self, "enterprise_manager_entity_display_name")

    @property
    @pulumi.getter(name="enterpriseManagerEntityIdentifier")
    def enterprise_manager_entity_identifier(self) -> str:
        """
        Enterprise Manager Entity Unique Identifier
        """
        return pulumi.get(self, "enterprise_manager_entity_identifier")

    @property
    @pulumi.getter(name="enterpriseManagerEntityName")
    def enterprise_manager_entity_name(self) -> str:
        """
        Enterprise Manager Entity Name
        """
        return pulumi.get(self, "enterprise_manager_entity_name")

    @property
    @pulumi.getter(name="enterpriseManagerEntityType")
    def enterprise_manager_entity_type(self) -> str:
        """
        Enterprise Manager Entity Type
        """
        return pulumi.get(self, "enterprise_manager_entity_type")

    @property
    @pulumi.getter(name="enterpriseManagerIdentifier")
    def enterprise_manager_identifier(self) -> str:
        """
        Enterprise Manager Unqiue Identifier
        """
        return pulumi.get(self, "enterprise_manager_identifier")

    @property
    @pulumi.getter(name="entitySource")
    def entity_source(self) -> str:
        """
        Source of the database entity.
        """
        return pulumi.get(self, "entity_source")

    @property
    @pulumi.getter(name="exadataInsightId")
    def exadata_insight_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata insight.
        """
        return pulumi.get(self, "exadata_insight_id")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        Database insight identifier
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="opsiPrivateEndpointId")
    def opsi_private_endpoint_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the OPSI private endpoint
        """
        return pulumi.get(self, "opsi_private_endpoint_id")

    @property
    @pulumi.getter(name="processorCount")
    def processor_count(self) -> int:
        """
        Processor count. This is the OCPU count for Autonomous Database and CPU core count for other database types.
        """
        return pulumi.get(self, "processor_count")

    @property
    @pulumi.getter(name="serviceName")
    def service_name(self) -> str:
        """
        Database service name used for connection requests.
        """
        return pulumi.get(self, "service_name")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the database.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter
    def status(self) -> str:
        """
        Indicates the status of a database insight in Operations Insights
        """
        return pulumi.get(self, "status")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the the database insight was first enabled. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the database insight was updated. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetDatabaseInsightResult(GetDatabaseInsightResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDatabaseInsightResult(
            compartment_id=self.compartment_id,
            connection_credential_details=self.connection_credential_details,
            connection_details=self.connection_details,
            credential_details=self.credential_details,
            database_connection_status_details=self.database_connection_status_details,
            database_display_name=self.database_display_name,
            database_id=self.database_id,
            database_insight_id=self.database_insight_id,
            database_name=self.database_name,
            database_resource_type=self.database_resource_type,
            database_type=self.database_type,
            database_version=self.database_version,
            defined_tags=self.defined_tags,
            deployment_type=self.deployment_type,
            enterprise_manager_bridge_id=self.enterprise_manager_bridge_id,
            enterprise_manager_entity_display_name=self.enterprise_manager_entity_display_name,
            enterprise_manager_entity_identifier=self.enterprise_manager_entity_identifier,
            enterprise_manager_entity_name=self.enterprise_manager_entity_name,
            enterprise_manager_entity_type=self.enterprise_manager_entity_type,
            enterprise_manager_identifier=self.enterprise_manager_identifier,
            entity_source=self.entity_source,
            exadata_insight_id=self.exadata_insight_id,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            opsi_private_endpoint_id=self.opsi_private_endpoint_id,
            processor_count=self.processor_count,
            service_name=self.service_name,
            state=self.state,
            status=self.status,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_database_insight(database_insight_id: Optional[str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDatabaseInsightResult:
    """
    This data source provides details about a specific Database Insight resource in Oracle Cloud Infrastructure Opsi service.

    Gets details of a database insight.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_database_insight = oci.Opsi.get_database_insight(database_insight_id=oci_opsi_database_insight["test_database_insight"]["id"])
    ```


    :param str database_insight_id: Unique database insight identifier
    """
    __args__ = dict()
    __args__['databaseInsightId'] = database_insight_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:Opsi/getDatabaseInsight:getDatabaseInsight', __args__, opts=opts, typ=GetDatabaseInsightResult).value

    return AwaitableGetDatabaseInsightResult(
        compartment_id=__ret__.compartment_id,
        connection_credential_details=__ret__.connection_credential_details,
        connection_details=__ret__.connection_details,
        credential_details=__ret__.credential_details,
        database_connection_status_details=__ret__.database_connection_status_details,
        database_display_name=__ret__.database_display_name,
        database_id=__ret__.database_id,
        database_insight_id=__ret__.database_insight_id,
        database_name=__ret__.database_name,
        database_resource_type=__ret__.database_resource_type,
        database_type=__ret__.database_type,
        database_version=__ret__.database_version,
        defined_tags=__ret__.defined_tags,
        deployment_type=__ret__.deployment_type,
        enterprise_manager_bridge_id=__ret__.enterprise_manager_bridge_id,
        enterprise_manager_entity_display_name=__ret__.enterprise_manager_entity_display_name,
        enterprise_manager_entity_identifier=__ret__.enterprise_manager_entity_identifier,
        enterprise_manager_entity_name=__ret__.enterprise_manager_entity_name,
        enterprise_manager_entity_type=__ret__.enterprise_manager_entity_type,
        enterprise_manager_identifier=__ret__.enterprise_manager_identifier,
        entity_source=__ret__.entity_source,
        exadata_insight_id=__ret__.exadata_insight_id,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        lifecycle_details=__ret__.lifecycle_details,
        opsi_private_endpoint_id=__ret__.opsi_private_endpoint_id,
        processor_count=__ret__.processor_count,
        service_name=__ret__.service_name,
        state=__ret__.state,
        status=__ret__.status,
        system_tags=__ret__.system_tags,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)


@_utilities.lift_output_func(get_database_insight)
def get_database_insight_output(database_insight_id: Optional[pulumi.Input[str]] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetDatabaseInsightResult]:
    """
    This data source provides details about a specific Database Insight resource in Oracle Cloud Infrastructure Opsi service.

    Gets details of a database insight.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_database_insight = oci.Opsi.get_database_insight(database_insight_id=oci_opsi_database_insight["test_database_insight"]["id"])
    ```


    :param str database_insight_id: Unique database insight identifier
    """
    ...
