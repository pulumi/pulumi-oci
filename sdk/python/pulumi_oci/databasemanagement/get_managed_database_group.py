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
    'GetManagedDatabaseGroupResult',
    'AwaitableGetManagedDatabaseGroupResult',
    'get_managed_database_group',
    'get_managed_database_group_output',
]

@pulumi.output_type
class GetManagedDatabaseGroupResult:
    """
    A collection of values returned by getManagedDatabaseGroup.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, description=None, freeform_tags=None, id=None, managed_database_group_id=None, managed_databases=None, name=None, state=None, system_tags=None, time_created=None, time_updated=None):
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
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if managed_database_group_id and not isinstance(managed_database_group_id, str):
            raise TypeError("Expected argument 'managed_database_group_id' to be a str")
        pulumi.set(__self__, "managed_database_group_id", managed_database_group_id)
        if managed_databases and not isinstance(managed_databases, list):
            raise TypeError("Expected argument 'managed_databases' to be a list")
        pulumi.set(__self__, "managed_databases", managed_databases)
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
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database resides.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        The information specified by the user about the Managed Database Group.
        """
        return pulumi.get(self, "description")

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
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="managedDatabaseGroupId")
    def managed_database_group_id(self) -> _builtins.str:
        return pulumi.get(self, "managed_database_group_id")

    @_builtins.property
    @pulumi.getter(name="managedDatabases")
    def managed_databases(self) -> Sequence['outputs.GetManagedDatabaseGroupManagedDatabaseResult']:
        """
        A list of Managed Databases in the Managed Database Group.
        """
        return pulumi.get(self, "managed_databases")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name of the Managed Database Group.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current lifecycle state of the Managed Database Group.
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
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the Managed Database Group was created.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The date and time the Managed Database Group was last updated.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetManagedDatabaseGroupResult(GetManagedDatabaseGroupResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagedDatabaseGroupResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            freeform_tags=self.freeform_tags,
            id=self.id,
            managed_database_group_id=self.managed_database_group_id,
            managed_databases=self.managed_databases,
            name=self.name,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_managed_database_group(managed_database_group_id: Optional[_builtins.str] = None,
                               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagedDatabaseGroupResult:
    """
    This data source provides details about a specific Managed Database Group resource in Oracle Cloud Infrastructure Database Management service.

    Gets the details for the Managed Database Group specified by managedDatabaseGroupId.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database_group = oci.DatabaseManagement.get_managed_database_group(managed_database_group_id=test_managed_database_group_oci_database_management_managed_database_group["id"])
    ```


    :param _builtins.str managed_database_group_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
    """
    __args__ = dict()
    __args__['managedDatabaseGroupId'] = managed_database_group_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DatabaseManagement/getManagedDatabaseGroup:getManagedDatabaseGroup', __args__, opts=opts, typ=GetManagedDatabaseGroupResult).value

    return AwaitableGetManagedDatabaseGroupResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        managed_database_group_id=pulumi.get(__ret__, 'managed_database_group_id'),
        managed_databases=pulumi.get(__ret__, 'managed_databases'),
        name=pulumi.get(__ret__, 'name'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_managed_database_group_output(managed_database_group_id: Optional[pulumi.Input[_builtins.str]] = None,
                                      opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetManagedDatabaseGroupResult]:
    """
    This data source provides details about a specific Managed Database Group resource in Oracle Cloud Infrastructure Database Management service.

    Gets the details for the Managed Database Group specified by managedDatabaseGroupId.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database_group = oci.DatabaseManagement.get_managed_database_group(managed_database_group_id=test_managed_database_group_oci_database_management_managed_database_group["id"])
    ```


    :param _builtins.str managed_database_group_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
    """
    __args__ = dict()
    __args__['managedDatabaseGroupId'] = managed_database_group_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DatabaseManagement/getManagedDatabaseGroup:getManagedDatabaseGroup', __args__, opts=opts, typ=GetManagedDatabaseGroupResult)
    return __ret__.apply(lambda __response__: GetManagedDatabaseGroupResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        managed_database_group_id=pulumi.get(__response__, 'managed_database_group_id'),
        managed_databases=pulumi.get(__response__, 'managed_databases'),
        name=pulumi.get(__response__, 'name'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
