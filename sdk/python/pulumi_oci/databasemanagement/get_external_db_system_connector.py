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

__all__ = [
    'GetExternalDbSystemConnectorResult',
    'AwaitableGetExternalDbSystemConnectorResult',
    'get_external_db_system_connector',
    'get_external_db_system_connector_output',
]

@pulumi.output_type
class GetExternalDbSystemConnectorResult:
    """
    A collection of values returned by getExternalDbSystemConnector.
    """
    def __init__(__self__, agent_id=None, compartment_id=None, connection_failure_message=None, connection_infos=None, connection_status=None, connector_type=None, defined_tags=None, display_name=None, external_db_system_connector_id=None, external_db_system_id=None, freeform_tags=None, id=None, lifecycle_details=None, state=None, system_tags=None, time_connection_status_last_updated=None, time_created=None, time_updated=None):
        if agent_id and not isinstance(agent_id, str):
            raise TypeError("Expected argument 'agent_id' to be a str")
        pulumi.set(__self__, "agent_id", agent_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if connection_failure_message and not isinstance(connection_failure_message, str):
            raise TypeError("Expected argument 'connection_failure_message' to be a str")
        pulumi.set(__self__, "connection_failure_message", connection_failure_message)
        if connection_infos and not isinstance(connection_infos, list):
            raise TypeError("Expected argument 'connection_infos' to be a list")
        pulumi.set(__self__, "connection_infos", connection_infos)
        if connection_status and not isinstance(connection_status, str):
            raise TypeError("Expected argument 'connection_status' to be a str")
        pulumi.set(__self__, "connection_status", connection_status)
        if connector_type and not isinstance(connector_type, str):
            raise TypeError("Expected argument 'connector_type' to be a str")
        pulumi.set(__self__, "connector_type", connector_type)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if external_db_system_connector_id and not isinstance(external_db_system_connector_id, str):
            raise TypeError("Expected argument 'external_db_system_connector_id' to be a str")
        pulumi.set(__self__, "external_db_system_connector_id", external_db_system_connector_id)
        if external_db_system_id and not isinstance(external_db_system_id, str):
            raise TypeError("Expected argument 'external_db_system_id' to be a str")
        pulumi.set(__self__, "external_db_system_id", external_db_system_id)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_connection_status_last_updated and not isinstance(time_connection_status_last_updated, str):
            raise TypeError("Expected argument 'time_connection_status_last_updated' to be a str")
        pulumi.set(__self__, "time_connection_status_last_updated", time_connection_status_last_updated)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter(name="agentId")
    def agent_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system connector.
        """
        return pulumi.get(self, "agent_id")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="connectionFailureMessage")
    def connection_failure_message(self) -> _builtins.str:
        """
        The error message indicating the reason for connection failure or `null` if the connection was successful.
        """
        return pulumi.get(self, "connection_failure_message")

    @_builtins.property
    @pulumi.getter(name="connectionInfos")
    def connection_infos(self) -> Sequence['outputs.GetExternalDbSystemConnectorConnectionInfoResult']:
        """
        The connection details required to connect to an external DB system component.
        """
        return pulumi.get(self, "connection_infos")

    @_builtins.property
    @pulumi.getter(name="connectionStatus")
    def connection_status(self) -> _builtins.str:
        """
        The status of connectivity to the external DB system component.
        """
        return pulumi.get(self, "connection_status")

    @_builtins.property
    @pulumi.getter(name="connectorType")
    def connector_type(self) -> _builtins.str:
        """
        The type of connector.
        """
        return pulumi.get(self, "connector_type")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        The user-friendly name for the external connector. The name does not have to be unique.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="externalDbSystemConnectorId")
    def external_db_system_connector_id(self) -> _builtins.str:
        return pulumi.get(self, "external_db_system_connector_id")

    @_builtins.property
    @pulumi.getter(name="externalDbSystemId")
    def external_db_system_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the connector is a part of.
        """
        return pulumi.get(self, "external_db_system_id")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system connector.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        Additional information about the current lifecycle state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current lifecycle state of the external DB system connector.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeConnectionStatusLastUpdated")
    def time_connection_status_last_updated(self) -> _builtins.str:
        """
        The date and time the connectionStatus of the external DB system connector was last updated.
        """
        return pulumi.get(self, "time_connection_status_last_updated")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the external DB system connector was created.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The date and time the external DB system connector was last updated.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetExternalDbSystemConnectorResult(GetExternalDbSystemConnectorResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetExternalDbSystemConnectorResult(
            agent_id=self.agent_id,
            compartment_id=self.compartment_id,
            connection_failure_message=self.connection_failure_message,
            connection_infos=self.connection_infos,
            connection_status=self.connection_status,
            connector_type=self.connector_type,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            external_db_system_connector_id=self.external_db_system_connector_id,
            external_db_system_id=self.external_db_system_id,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            state=self.state,
            system_tags=self.system_tags,
            time_connection_status_last_updated=self.time_connection_status_last_updated,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_external_db_system_connector(external_db_system_connector_id: Optional[_builtins.str] = None,
                                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetExternalDbSystemConnectorResult:
    """
    This data source provides details about a specific External Db System Connector resource in Oracle Cloud Infrastructure Database Management service.

    Gets the details for the external connector specified by `externalDbSystemConnectorId`.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_external_db_system_connector = oci.DatabaseManagement.get_external_db_system_connector(external_db_system_connector_id=test_external_db_system_connector_oci_database_management_external_db_system_connector["id"])
    ```


    :param _builtins.str external_db_system_connector_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
    """
    __args__ = dict()
    __args__['externalDbSystemConnectorId'] = external_db_system_connector_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DatabaseManagement/getExternalDbSystemConnector:getExternalDbSystemConnector', __args__, opts=opts, typ=GetExternalDbSystemConnectorResult).value

    return AwaitableGetExternalDbSystemConnectorResult(
        agent_id=pulumi.get(__ret__, 'agent_id'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        connection_failure_message=pulumi.get(__ret__, 'connection_failure_message'),
        connection_infos=pulumi.get(__ret__, 'connection_infos'),
        connection_status=pulumi.get(__ret__, 'connection_status'),
        connector_type=pulumi.get(__ret__, 'connector_type'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        external_db_system_connector_id=pulumi.get(__ret__, 'external_db_system_connector_id'),
        external_db_system_id=pulumi.get(__ret__, 'external_db_system_id'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_connection_status_last_updated=pulumi.get(__ret__, 'time_connection_status_last_updated'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_external_db_system_connector_output(external_db_system_connector_id: Optional[pulumi.Input[_builtins.str]] = None,
                                            opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetExternalDbSystemConnectorResult]:
    """
    This data source provides details about a specific External Db System Connector resource in Oracle Cloud Infrastructure Database Management service.

    Gets the details for the external connector specified by `externalDbSystemConnectorId`.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_external_db_system_connector = oci.DatabaseManagement.get_external_db_system_connector(external_db_system_connector_id=test_external_db_system_connector_oci_database_management_external_db_system_connector["id"])
    ```


    :param _builtins.str external_db_system_connector_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
    """
    __args__ = dict()
    __args__['externalDbSystemConnectorId'] = external_db_system_connector_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DatabaseManagement/getExternalDbSystemConnector:getExternalDbSystemConnector', __args__, opts=opts, typ=GetExternalDbSystemConnectorResult)
    return __ret__.apply(lambda __response__: GetExternalDbSystemConnectorResult(
        agent_id=pulumi.get(__response__, 'agent_id'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        connection_failure_message=pulumi.get(__response__, 'connection_failure_message'),
        connection_infos=pulumi.get(__response__, 'connection_infos'),
        connection_status=pulumi.get(__response__, 'connection_status'),
        connector_type=pulumi.get(__response__, 'connector_type'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        display_name=pulumi.get(__response__, 'display_name'),
        external_db_system_connector_id=pulumi.get(__response__, 'external_db_system_connector_id'),
        external_db_system_id=pulumi.get(__response__, 'external_db_system_id'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_connection_status_last_updated=pulumi.get(__response__, 'time_connection_status_last_updated'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
