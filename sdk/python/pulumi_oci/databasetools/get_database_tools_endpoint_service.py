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

__all__ = [
    'GetDatabaseToolsEndpointServiceResult',
    'AwaitableGetDatabaseToolsEndpointServiceResult',
    'get_database_tools_endpoint_service',
    'get_database_tools_endpoint_service_output',
]

@pulumi.output_type
class GetDatabaseToolsEndpointServiceResult:
    """
    A collection of values returned by getDatabaseToolsEndpointService.
    """
    def __init__(__self__, compartment_id=None, database_tools_endpoint_service_id=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, id=None, lifecycle_details=None, name=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if database_tools_endpoint_service_id and not isinstance(database_tools_endpoint_service_id, str):
            raise TypeError("Expected argument 'database_tools_endpoint_service_id' to be a str")
        pulumi.set(__self__, "database_tools_endpoint_service_id", database_tools_endpoint_service_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
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

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools Endpoint Service.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="databaseToolsEndpointServiceId")
    def database_tools_endpoint_service_id(self) -> _builtins.str:
        return pulumi.get(self, "database_tools_endpoint_service_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        A description of the Database Tools Endpoint Service.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        A unique, non-changeable resource name.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the Database Tools Endpoint Service.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The time the Database Tools Endpoint Service was created. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The time the Database Tools Endpoint Service was updated. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetDatabaseToolsEndpointServiceResult(GetDatabaseToolsEndpointServiceResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDatabaseToolsEndpointServiceResult(
            compartment_id=self.compartment_id,
            database_tools_endpoint_service_id=self.database_tools_endpoint_service_id,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            name=self.name,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_database_tools_endpoint_service(database_tools_endpoint_service_id: Optional[_builtins.str] = None,
                                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDatabaseToolsEndpointServiceResult:
    """
    This data source provides details about a specific Database Tools Endpoint Service resource in Oracle Cloud Infrastructure Database Tools service.

    Gets details for the specified Database Tools endpoint service.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_database_tools_endpoint_service = oci.DatabaseTools.get_database_tools_endpoint_service(database_tools_endpoint_service_id=test_database_tools_endpoint_service_oci_database_tools_database_tools_endpoint_service["id"])
    ```


    :param _builtins.str database_tools_endpoint_service_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Database Tools Endpoint Service.
    """
    __args__ = dict()
    __args__['databaseToolsEndpointServiceId'] = database_tools_endpoint_service_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DatabaseTools/getDatabaseToolsEndpointService:getDatabaseToolsEndpointService', __args__, opts=opts, typ=GetDatabaseToolsEndpointServiceResult).value

    return AwaitableGetDatabaseToolsEndpointServiceResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        database_tools_endpoint_service_id=pulumi.get(__ret__, 'database_tools_endpoint_service_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        name=pulumi.get(__ret__, 'name'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_database_tools_endpoint_service_output(database_tools_endpoint_service_id: Optional[pulumi.Input[_builtins.str]] = None,
                                               opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDatabaseToolsEndpointServiceResult]:
    """
    This data source provides details about a specific Database Tools Endpoint Service resource in Oracle Cloud Infrastructure Database Tools service.

    Gets details for the specified Database Tools endpoint service.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_database_tools_endpoint_service = oci.DatabaseTools.get_database_tools_endpoint_service(database_tools_endpoint_service_id=test_database_tools_endpoint_service_oci_database_tools_database_tools_endpoint_service["id"])
    ```


    :param _builtins.str database_tools_endpoint_service_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Database Tools Endpoint Service.
    """
    __args__ = dict()
    __args__['databaseToolsEndpointServiceId'] = database_tools_endpoint_service_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DatabaseTools/getDatabaseToolsEndpointService:getDatabaseToolsEndpointService', __args__, opts=opts, typ=GetDatabaseToolsEndpointServiceResult)
    return __ret__.apply(lambda __response__: GetDatabaseToolsEndpointServiceResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        database_tools_endpoint_service_id=pulumi.get(__response__, 'database_tools_endpoint_service_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        name=pulumi.get(__response__, 'name'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
