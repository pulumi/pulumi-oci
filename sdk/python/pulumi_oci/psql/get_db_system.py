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
    'GetDbSystemResult',
    'AwaitableGetDbSystemResult',
    'get_db_system',
    'get_db_system_output',
]

@pulumi.output_type
class GetDbSystemResult:
    """
    A collection of values returned by getDbSystem.
    """
    def __init__(__self__, admin_username=None, apply_config=None, compartment_id=None, config_id=None, credentials=None, db_system_id=None, db_version=None, defined_tags=None, description=None, display_name=None, excluded_fields=None, freeform_tags=None, id=None, instance_count=None, instance_memory_size_in_gbs=None, instance_ocpu_count=None, instances=None, instances_details=None, lifecycle_details=None, management_policies=None, network_details=None, patch_operations=None, shape=None, sources=None, state=None, storage_details=None, system_tags=None, system_type=None, time_created=None, time_updated=None):
        if admin_username and not isinstance(admin_username, str):
            raise TypeError("Expected argument 'admin_username' to be a str")
        pulumi.set(__self__, "admin_username", admin_username)
        if apply_config and not isinstance(apply_config, str):
            raise TypeError("Expected argument 'apply_config' to be a str")
        pulumi.set(__self__, "apply_config", apply_config)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if config_id and not isinstance(config_id, str):
            raise TypeError("Expected argument 'config_id' to be a str")
        pulumi.set(__self__, "config_id", config_id)
        if credentials and not isinstance(credentials, list):
            raise TypeError("Expected argument 'credentials' to be a list")
        pulumi.set(__self__, "credentials", credentials)
        if db_system_id and not isinstance(db_system_id, str):
            raise TypeError("Expected argument 'db_system_id' to be a str")
        pulumi.set(__self__, "db_system_id", db_system_id)
        if db_version and not isinstance(db_version, str):
            raise TypeError("Expected argument 'db_version' to be a str")
        pulumi.set(__self__, "db_version", db_version)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if excluded_fields and not isinstance(excluded_fields, str):
            raise TypeError("Expected argument 'excluded_fields' to be a str")
        pulumi.set(__self__, "excluded_fields", excluded_fields)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if instance_count and not isinstance(instance_count, int):
            raise TypeError("Expected argument 'instance_count' to be a int")
        pulumi.set(__self__, "instance_count", instance_count)
        if instance_memory_size_in_gbs and not isinstance(instance_memory_size_in_gbs, int):
            raise TypeError("Expected argument 'instance_memory_size_in_gbs' to be a int")
        pulumi.set(__self__, "instance_memory_size_in_gbs", instance_memory_size_in_gbs)
        if instance_ocpu_count and not isinstance(instance_ocpu_count, int):
            raise TypeError("Expected argument 'instance_ocpu_count' to be a int")
        pulumi.set(__self__, "instance_ocpu_count", instance_ocpu_count)
        if instances and not isinstance(instances, list):
            raise TypeError("Expected argument 'instances' to be a list")
        pulumi.set(__self__, "instances", instances)
        if instances_details and not isinstance(instances_details, list):
            raise TypeError("Expected argument 'instances_details' to be a list")
        pulumi.set(__self__, "instances_details", instances_details)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if management_policies and not isinstance(management_policies, list):
            raise TypeError("Expected argument 'management_policies' to be a list")
        pulumi.set(__self__, "management_policies", management_policies)
        if network_details and not isinstance(network_details, list):
            raise TypeError("Expected argument 'network_details' to be a list")
        pulumi.set(__self__, "network_details", network_details)
        if patch_operations and not isinstance(patch_operations, list):
            raise TypeError("Expected argument 'patch_operations' to be a list")
        pulumi.set(__self__, "patch_operations", patch_operations)
        if shape and not isinstance(shape, str):
            raise TypeError("Expected argument 'shape' to be a str")
        pulumi.set(__self__, "shape", shape)
        if sources and not isinstance(sources, list):
            raise TypeError("Expected argument 'sources' to be a list")
        pulumi.set(__self__, "sources", sources)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if storage_details and not isinstance(storage_details, list):
            raise TypeError("Expected argument 'storage_details' to be a list")
        pulumi.set(__self__, "storage_details", storage_details)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if system_type and not isinstance(system_type, str):
            raise TypeError("Expected argument 'system_type' to be a str")
        pulumi.set(__self__, "system_type", system_type)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter(name="adminUsername")
    def admin_username(self) -> _builtins.str:
        """
        The database system administrator username.
        """
        return pulumi.get(self, "admin_username")

    @_builtins.property
    @pulumi.getter(name="applyConfig")
    def apply_config(self) -> _builtins.str:
        return pulumi.get(self, "apply_config")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        target compartment to place a new backup
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="configId")
    def config_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the configuration associated with the database system.
        """
        return pulumi.get(self, "config_id")

    @_builtins.property
    @pulumi.getter
    def credentials(self) -> Sequence['outputs.GetDbSystemCredentialResult']:
        return pulumi.get(self, "credentials")

    @_builtins.property
    @pulumi.getter(name="dbSystemId")
    def db_system_id(self) -> _builtins.str:
        return pulumi.get(self, "db_system_id")

    @_builtins.property
    @pulumi.getter(name="dbVersion")
    def db_version(self) -> _builtins.str:
        """
        The major and minor versions of the database system software.
        """
        return pulumi.get(self, "db_version")

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
        Description of the database instance node.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly display name for the database instance node. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="excludedFields")
    def excluded_fields(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "excluded_fields")

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
        A unique identifier for the database instance node. Immutable on creation.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="instanceCount")
    def instance_count(self) -> _builtins.int:
        """
        Count of instances, or nodes, in the database system.
        """
        return pulumi.get(self, "instance_count")

    @_builtins.property
    @pulumi.getter(name="instanceMemorySizeInGbs")
    def instance_memory_size_in_gbs(self) -> _builtins.int:
        """
        The total amount of memory available to each database instance node, in gigabytes.
        """
        return pulumi.get(self, "instance_memory_size_in_gbs")

    @_builtins.property
    @pulumi.getter(name="instanceOcpuCount")
    def instance_ocpu_count(self) -> _builtins.int:
        """
        The total number of OCPUs available to each database instance node.
        """
        return pulumi.get(self, "instance_ocpu_count")

    @_builtins.property
    @pulumi.getter
    def instances(self) -> Sequence['outputs.GetDbSystemInstanceResult']:
        """
        The list of instances, or nodes, in the database system.
        """
        return pulumi.get(self, "instances")

    @_builtins.property
    @pulumi.getter(name="instancesDetails")
    def instances_details(self) -> Sequence['outputs.GetDbSystemInstancesDetailResult']:
        return pulumi.get(self, "instances_details")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="managementPolicies")
    def management_policies(self) -> Sequence['outputs.GetDbSystemManagementPolicyResult']:
        """
        PostgreSQL database system management policy.
        """
        return pulumi.get(self, "management_policies")

    @_builtins.property
    @pulumi.getter(name="networkDetails")
    def network_details(self) -> Sequence['outputs.GetDbSystemNetworkDetailResult']:
        """
        Network details for the database system.
        """
        return pulumi.get(self, "network_details")

    @_builtins.property
    @pulumi.getter(name="patchOperations")
    def patch_operations(self) -> Sequence['outputs.GetDbSystemPatchOperationResult']:
        return pulumi.get(self, "patch_operations")

    @_builtins.property
    @pulumi.getter
    def shape(self) -> _builtins.str:
        """
        The name of the shape for the database instance. Example: `VM.Standard.E4.Flex`
        """
        return pulumi.get(self, "shape")

    @_builtins.property
    @pulumi.getter
    def sources(self) -> Sequence['outputs.GetDbSystemSourceResult']:
        """
        The source used to restore the database system.
        """
        return pulumi.get(self, "sources")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the database system.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="storageDetails")
    def storage_details(self) -> Sequence['outputs.GetDbSystemStorageDetailResult']:
        """
        Storage details of the database system.
        """
        return pulumi.get(self, "storage_details")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="systemType")
    def system_type(self) -> _builtins.str:
        """
        Type of the database system.
        """
        return pulumi.get(self, "system_type")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time that the database system was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The date and time that the database system was updated, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetDbSystemResult(GetDbSystemResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDbSystemResult(
            admin_username=self.admin_username,
            apply_config=self.apply_config,
            compartment_id=self.compartment_id,
            config_id=self.config_id,
            credentials=self.credentials,
            db_system_id=self.db_system_id,
            db_version=self.db_version,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            excluded_fields=self.excluded_fields,
            freeform_tags=self.freeform_tags,
            id=self.id,
            instance_count=self.instance_count,
            instance_memory_size_in_gbs=self.instance_memory_size_in_gbs,
            instance_ocpu_count=self.instance_ocpu_count,
            instances=self.instances,
            instances_details=self.instances_details,
            lifecycle_details=self.lifecycle_details,
            management_policies=self.management_policies,
            network_details=self.network_details,
            patch_operations=self.patch_operations,
            shape=self.shape,
            sources=self.sources,
            state=self.state,
            storage_details=self.storage_details,
            system_tags=self.system_tags,
            system_type=self.system_type,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_db_system(db_system_id: Optional[_builtins.str] = None,
                  excluded_fields: Optional[_builtins.str] = None,
                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDbSystemResult:
    """
    This data source provides details about a specific Db System resource in Oracle Cloud Infrastructure Psql service.

    Gets a database system by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_db_system = oci.Psql.get_db_system(db_system_id=test_db_system_oci_psql_db_system["id"],
        excluded_fields=db_system_excluded_fields)
    ```


    :param _builtins.str db_system_id: A unique identifier for the database system.
    :param _builtins.str excluded_fields: A filter to exclude database configuration when this query parameter is set to OverrideDbConfig.
    """
    __args__ = dict()
    __args__['dbSystemId'] = db_system_id
    __args__['excludedFields'] = excluded_fields
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Psql/getDbSystem:getDbSystem', __args__, opts=opts, typ=GetDbSystemResult).value

    return AwaitableGetDbSystemResult(
        admin_username=pulumi.get(__ret__, 'admin_username'),
        apply_config=pulumi.get(__ret__, 'apply_config'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        config_id=pulumi.get(__ret__, 'config_id'),
        credentials=pulumi.get(__ret__, 'credentials'),
        db_system_id=pulumi.get(__ret__, 'db_system_id'),
        db_version=pulumi.get(__ret__, 'db_version'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        excluded_fields=pulumi.get(__ret__, 'excluded_fields'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        instance_count=pulumi.get(__ret__, 'instance_count'),
        instance_memory_size_in_gbs=pulumi.get(__ret__, 'instance_memory_size_in_gbs'),
        instance_ocpu_count=pulumi.get(__ret__, 'instance_ocpu_count'),
        instances=pulumi.get(__ret__, 'instances'),
        instances_details=pulumi.get(__ret__, 'instances_details'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        management_policies=pulumi.get(__ret__, 'management_policies'),
        network_details=pulumi.get(__ret__, 'network_details'),
        patch_operations=pulumi.get(__ret__, 'patch_operations'),
        shape=pulumi.get(__ret__, 'shape'),
        sources=pulumi.get(__ret__, 'sources'),
        state=pulumi.get(__ret__, 'state'),
        storage_details=pulumi.get(__ret__, 'storage_details'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        system_type=pulumi.get(__ret__, 'system_type'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_db_system_output(db_system_id: Optional[pulumi.Input[_builtins.str]] = None,
                         excluded_fields: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                         opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDbSystemResult]:
    """
    This data source provides details about a specific Db System resource in Oracle Cloud Infrastructure Psql service.

    Gets a database system by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_db_system = oci.Psql.get_db_system(db_system_id=test_db_system_oci_psql_db_system["id"],
        excluded_fields=db_system_excluded_fields)
    ```


    :param _builtins.str db_system_id: A unique identifier for the database system.
    :param _builtins.str excluded_fields: A filter to exclude database configuration when this query parameter is set to OverrideDbConfig.
    """
    __args__ = dict()
    __args__['dbSystemId'] = db_system_id
    __args__['excludedFields'] = excluded_fields
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Psql/getDbSystem:getDbSystem', __args__, opts=opts, typ=GetDbSystemResult)
    return __ret__.apply(lambda __response__: GetDbSystemResult(
        admin_username=pulumi.get(__response__, 'admin_username'),
        apply_config=pulumi.get(__response__, 'apply_config'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        config_id=pulumi.get(__response__, 'config_id'),
        credentials=pulumi.get(__response__, 'credentials'),
        db_system_id=pulumi.get(__response__, 'db_system_id'),
        db_version=pulumi.get(__response__, 'db_version'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        excluded_fields=pulumi.get(__response__, 'excluded_fields'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        instance_count=pulumi.get(__response__, 'instance_count'),
        instance_memory_size_in_gbs=pulumi.get(__response__, 'instance_memory_size_in_gbs'),
        instance_ocpu_count=pulumi.get(__response__, 'instance_ocpu_count'),
        instances=pulumi.get(__response__, 'instances'),
        instances_details=pulumi.get(__response__, 'instances_details'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        management_policies=pulumi.get(__response__, 'management_policies'),
        network_details=pulumi.get(__response__, 'network_details'),
        patch_operations=pulumi.get(__response__, 'patch_operations'),
        shape=pulumi.get(__response__, 'shape'),
        sources=pulumi.get(__response__, 'sources'),
        state=pulumi.get(__response__, 'state'),
        storage_details=pulumi.get(__response__, 'storage_details'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        system_type=pulumi.get(__response__, 'system_type'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
