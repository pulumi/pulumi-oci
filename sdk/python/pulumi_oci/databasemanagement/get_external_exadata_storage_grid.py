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
    'GetExternalExadataStorageGridResult',
    'AwaitableGetExternalExadataStorageGridResult',
    'get_external_exadata_storage_grid',
    'get_external_exadata_storage_grid_output',
]

@pulumi.output_type
class GetExternalExadataStorageGridResult:
    """
    A collection of values returned by getExternalExadataStorageGrid.
    """
    def __init__(__self__, additional_details=None, defined_tags=None, display_name=None, exadata_infrastructure_id=None, external_exadata_storage_grid_id=None, freeform_tags=None, id=None, internal_id=None, lifecycle_details=None, resource_type=None, server_count=None, state=None, status=None, storage_servers=None, system_tags=None, time_created=None, time_updated=None, version=None):
        if additional_details and not isinstance(additional_details, dict):
            raise TypeError("Expected argument 'additional_details' to be a dict")
        pulumi.set(__self__, "additional_details", additional_details)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if exadata_infrastructure_id and not isinstance(exadata_infrastructure_id, str):
            raise TypeError("Expected argument 'exadata_infrastructure_id' to be a str")
        pulumi.set(__self__, "exadata_infrastructure_id", exadata_infrastructure_id)
        if external_exadata_storage_grid_id and not isinstance(external_exadata_storage_grid_id, str):
            raise TypeError("Expected argument 'external_exadata_storage_grid_id' to be a str")
        pulumi.set(__self__, "external_exadata_storage_grid_id", external_exadata_storage_grid_id)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if internal_id and not isinstance(internal_id, str):
            raise TypeError("Expected argument 'internal_id' to be a str")
        pulumi.set(__self__, "internal_id", internal_id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if resource_type and not isinstance(resource_type, str):
            raise TypeError("Expected argument 'resource_type' to be a str")
        pulumi.set(__self__, "resource_type", resource_type)
        if server_count and not isinstance(server_count, float):
            raise TypeError("Expected argument 'server_count' to be a float")
        pulumi.set(__self__, "server_count", server_count)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if status and not isinstance(status, str):
            raise TypeError("Expected argument 'status' to be a str")
        pulumi.set(__self__, "status", status)
        if storage_servers and not isinstance(storage_servers, list):
            raise TypeError("Expected argument 'storage_servers' to be a list")
        pulumi.set(__self__, "storage_servers", storage_servers)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if version and not isinstance(version, str):
            raise TypeError("Expected argument 'version' to be a str")
        pulumi.set(__self__, "version", version)

    @_builtins.property
    @pulumi.getter(name="additionalDetails")
    def additional_details(self) -> Mapping[str, _builtins.str]:
        """
        The additional details of the resource defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "additional_details")

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
        The name of the Exadata resource. English letters, numbers, "-", "_" and "." only.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="exadataInfrastructureId")
    def exadata_infrastructure_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
        """
        return pulumi.get(self, "exadata_infrastructure_id")

    @_builtins.property
    @pulumi.getter(name="externalExadataStorageGridId")
    def external_exadata_storage_grid_id(self) -> _builtins.str:
        return pulumi.get(self, "external_exadata_storage_grid_id")

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
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="internalId")
    def internal_id(self) -> _builtins.str:
        """
        The internal ID of the Exadata resource.
        """
        return pulumi.get(self, "internal_id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        The details of the lifecycle state of the Exadata resource.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="resourceType")
    def resource_type(self) -> _builtins.str:
        """
        The type of Exadata resource.
        """
        return pulumi.get(self, "resource_type")

    @_builtins.property
    @pulumi.getter(name="serverCount")
    def server_count(self) -> _builtins.float:
        """
        The number of Exadata storage servers in the Exadata infrastructure.
        """
        return pulumi.get(self, "server_count")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current lifecycle state of the database resource.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter
    def status(self) -> _builtins.str:
        """
        The status of the Exadata resource.
        """
        return pulumi.get(self, "status")

    @_builtins.property
    @pulumi.getter(name="storageServers")
    def storage_servers(self) -> Sequence['outputs.GetExternalExadataStorageGridStorageServerResult']:
        """
        A list of monitored Exadata storage servers.
        """
        return pulumi.get(self, "storage_servers")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The timestamp of the creation of the Exadata resource.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The timestamp of the last update of the Exadata resource.
        """
        return pulumi.get(self, "time_updated")

    @_builtins.property
    @pulumi.getter
    def version(self) -> _builtins.str:
        """
        The version of the Exadata resource.
        """
        return pulumi.get(self, "version")


class AwaitableGetExternalExadataStorageGridResult(GetExternalExadataStorageGridResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetExternalExadataStorageGridResult(
            additional_details=self.additional_details,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            exadata_infrastructure_id=self.exadata_infrastructure_id,
            external_exadata_storage_grid_id=self.external_exadata_storage_grid_id,
            freeform_tags=self.freeform_tags,
            id=self.id,
            internal_id=self.internal_id,
            lifecycle_details=self.lifecycle_details,
            resource_type=self.resource_type,
            server_count=self.server_count,
            state=self.state,
            status=self.status,
            storage_servers=self.storage_servers,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated,
            version=self.version)


def get_external_exadata_storage_grid(external_exadata_storage_grid_id: Optional[_builtins.str] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetExternalExadataStorageGridResult:
    """
    This data source provides details about a specific External Exadata Storage Grid resource in Oracle Cloud Infrastructure Database Management service.

    Gets the details for the Exadata storage server grid specified by exadataStorageGridId.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_external_exadata_storage_grid = oci.DatabaseManagement.get_external_exadata_storage_grid(external_exadata_storage_grid_id=test_external_exadata_storage_grid_oci_database_management_external_exadata_storage_grid["id"])
    ```


    :param _builtins.str external_exadata_storage_grid_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage grid.
    """
    __args__ = dict()
    __args__['externalExadataStorageGridId'] = external_exadata_storage_grid_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DatabaseManagement/getExternalExadataStorageGrid:getExternalExadataStorageGrid', __args__, opts=opts, typ=GetExternalExadataStorageGridResult).value

    return AwaitableGetExternalExadataStorageGridResult(
        additional_details=pulumi.get(__ret__, 'additional_details'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        exadata_infrastructure_id=pulumi.get(__ret__, 'exadata_infrastructure_id'),
        external_exadata_storage_grid_id=pulumi.get(__ret__, 'external_exadata_storage_grid_id'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        internal_id=pulumi.get(__ret__, 'internal_id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        resource_type=pulumi.get(__ret__, 'resource_type'),
        server_count=pulumi.get(__ret__, 'server_count'),
        state=pulumi.get(__ret__, 'state'),
        status=pulumi.get(__ret__, 'status'),
        storage_servers=pulumi.get(__ret__, 'storage_servers'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'),
        version=pulumi.get(__ret__, 'version'))
def get_external_exadata_storage_grid_output(external_exadata_storage_grid_id: Optional[pulumi.Input[_builtins.str]] = None,
                                             opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetExternalExadataStorageGridResult]:
    """
    This data source provides details about a specific External Exadata Storage Grid resource in Oracle Cloud Infrastructure Database Management service.

    Gets the details for the Exadata storage server grid specified by exadataStorageGridId.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_external_exadata_storage_grid = oci.DatabaseManagement.get_external_exadata_storage_grid(external_exadata_storage_grid_id=test_external_exadata_storage_grid_oci_database_management_external_exadata_storage_grid["id"])
    ```


    :param _builtins.str external_exadata_storage_grid_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage grid.
    """
    __args__ = dict()
    __args__['externalExadataStorageGridId'] = external_exadata_storage_grid_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DatabaseManagement/getExternalExadataStorageGrid:getExternalExadataStorageGrid', __args__, opts=opts, typ=GetExternalExadataStorageGridResult)
    return __ret__.apply(lambda __response__: GetExternalExadataStorageGridResult(
        additional_details=pulumi.get(__response__, 'additional_details'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        display_name=pulumi.get(__response__, 'display_name'),
        exadata_infrastructure_id=pulumi.get(__response__, 'exadata_infrastructure_id'),
        external_exadata_storage_grid_id=pulumi.get(__response__, 'external_exadata_storage_grid_id'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        internal_id=pulumi.get(__response__, 'internal_id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        resource_type=pulumi.get(__response__, 'resource_type'),
        server_count=pulumi.get(__response__, 'server_count'),
        state=pulumi.get(__response__, 'state'),
        status=pulumi.get(__response__, 'status'),
        storage_servers=pulumi.get(__response__, 'storage_servers'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated'),
        version=pulumi.get(__response__, 'version')))
