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

__all__ = [
    'GetConnectionsResult',
    'AwaitableGetConnectionsResult',
    'get_connections',
    'get_connections_output',
]

@pulumi.output_type
class GetConnectionsResult:
    """
    A collection of values returned by getConnections.
    """
    def __init__(__self__, compartment_id=None, connection_collections=None, connection_type=None, display_name=None, filters=None, id=None, project_id=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if connection_collections and not isinstance(connection_collections, list):
            raise TypeError("Expected argument 'connection_collections' to be a list")
        pulumi.set(__self__, "connection_collections", connection_collections)
        if connection_type and not isinstance(connection_type, str):
            raise TypeError("Expected argument 'connection_type' to be a str")
        pulumi.set(__self__, "connection_type", connection_type)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[str]:
        """
        The OCID of the compartment containing the connection.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="connectionCollections")
    def connection_collections(self) -> Sequence['outputs.GetConnectionsConnectionCollectionResult']:
        """
        The list of connection_collection.
        """
        return pulumi.get(self, "connection_collections")

    @property
    @pulumi.getter(name="connectionType")
    def connection_type(self) -> Optional[str]:
        """
        The type of connection.
        """
        return pulumi.get(self, "connection_type")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        Connection display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetConnectionsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> Optional[str]:
        """
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="projectId")
    def project_id(self) -> Optional[str]:
        """
        The OCID of the DevOps project.
        """
        return pulumi.get(self, "project_id")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the connection.
        """
        return pulumi.get(self, "state")


class AwaitableGetConnectionsResult(GetConnectionsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetConnectionsResult(
            compartment_id=self.compartment_id,
            connection_collections=self.connection_collections,
            connection_type=self.connection_type,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            project_id=self.project_id,
            state=self.state)


def get_connections(compartment_id: Optional[str] = None,
                    connection_type: Optional[str] = None,
                    display_name: Optional[str] = None,
                    filters: Optional[Sequence[pulumi.InputType['GetConnectionsFilterArgs']]] = None,
                    id: Optional[str] = None,
                    project_id: Optional[str] = None,
                    state: Optional[str] = None,
                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetConnectionsResult:
    """
    This data source provides the list of Connections in Oracle Cloud Infrastructure Devops service.

    Returns a list of connections.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_connections = oci.DevOps.get_connections(compartment_id=var["compartment_id"],
        connection_type=var["connection_connection_type"],
        display_name=var["connection_display_name"],
        id=var["connection_id"],
        project_id=oci_devops_project["test_project"]["id"],
        state=var["connection_state"])
    ```


    :param str compartment_id: The OCID of the compartment in which to list resources.
    :param str connection_type: A filter to return only resources that match the given connection type.
    :param str display_name: A filter to return only resources that match the entire display name given.
    :param str id: Unique identifier or OCID for listing a single resource by ID.
    :param str project_id: unique project identifier
    :param str state: A filter to return only connections that matches the given lifecycle state.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['connectionType'] = connection_type
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['projectId'] = project_id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DevOps/getConnections:getConnections', __args__, opts=opts, typ=GetConnectionsResult).value

    return AwaitableGetConnectionsResult(
        compartment_id=__ret__.compartment_id,
        connection_collections=__ret__.connection_collections,
        connection_type=__ret__.connection_type,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        project_id=__ret__.project_id,
        state=__ret__.state)


@_utilities.lift_output_func(get_connections)
def get_connections_output(compartment_id: Optional[pulumi.Input[Optional[str]]] = None,
                           connection_type: Optional[pulumi.Input[Optional[str]]] = None,
                           display_name: Optional[pulumi.Input[Optional[str]]] = None,
                           filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetConnectionsFilterArgs']]]]] = None,
                           id: Optional[pulumi.Input[Optional[str]]] = None,
                           project_id: Optional[pulumi.Input[Optional[str]]] = None,
                           state: Optional[pulumi.Input[Optional[str]]] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetConnectionsResult]:
    """
    This data source provides the list of Connections in Oracle Cloud Infrastructure Devops service.

    Returns a list of connections.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_connections = oci.DevOps.get_connections(compartment_id=var["compartment_id"],
        connection_type=var["connection_connection_type"],
        display_name=var["connection_display_name"],
        id=var["connection_id"],
        project_id=oci_devops_project["test_project"]["id"],
        state=var["connection_state"])
    ```


    :param str compartment_id: The OCID of the compartment in which to list resources.
    :param str connection_type: A filter to return only resources that match the given connection type.
    :param str display_name: A filter to return only resources that match the entire display name given.
    :param str id: Unique identifier or OCID for listing a single resource by ID.
    :param str project_id: unique project identifier
    :param str state: A filter to return only connections that matches the given lifecycle state.
    """
    ...