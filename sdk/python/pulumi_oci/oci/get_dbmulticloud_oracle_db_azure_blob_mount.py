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
    'GetDbmulticloudOracleDbAzureBlobMountResult',
    'AwaitableGetDbmulticloudOracleDbAzureBlobMountResult',
    'get_dbmulticloud_oracle_db_azure_blob_mount',
    'get_dbmulticloud_oracle_db_azure_blob_mount_output',
]

@pulumi.output_type
class GetDbmulticloudOracleDbAzureBlobMountResult:
    """
    A collection of values returned by getDbmulticloudOracleDbAzureBlobMount.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, last_modification=None, lifecycle_state_details=None, mount_path=None, oracle_db_azure_blob_container_id=None, oracle_db_azure_blob_mount_id=None, oracle_db_azure_connector_id=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if last_modification and not isinstance(last_modification, str):
            raise TypeError("Expected argument 'last_modification' to be a str")
        pulumi.set(__self__, "last_modification", last_modification)
        if lifecycle_state_details and not isinstance(lifecycle_state_details, str):
            raise TypeError("Expected argument 'lifecycle_state_details' to be a str")
        pulumi.set(__self__, "lifecycle_state_details", lifecycle_state_details)
        if mount_path and not isinstance(mount_path, str):
            raise TypeError("Expected argument 'mount_path' to be a str")
        pulumi.set(__self__, "mount_path", mount_path)
        if oracle_db_azure_blob_container_id and not isinstance(oracle_db_azure_blob_container_id, str):
            raise TypeError("Expected argument 'oracle_db_azure_blob_container_id' to be a str")
        pulumi.set(__self__, "oracle_db_azure_blob_container_id", oracle_db_azure_blob_container_id)
        if oracle_db_azure_blob_mount_id and not isinstance(oracle_db_azure_blob_mount_id, str):
            raise TypeError("Expected argument 'oracle_db_azure_blob_mount_id' to be a str")
        pulumi.set(__self__, "oracle_db_azure_blob_mount_id", oracle_db_azure_blob_mount_id)
        if oracle_db_azure_connector_id and not isinstance(oracle_db_azure_connector_id, str):
            raise TypeError("Expected argument 'oracle_db_azure_connector_id' to be a str")
        pulumi.set(__self__, "oracle_db_azure_connector_id", oracle_db_azure_connector_id)
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
        The OCID of the compartment that contains Oracle DB Azure Blob Mount resource.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        Oracle DB Azure Blob Mount name.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The OCID for the new Oracle DB Azure Blob Mount resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lastModification")
    def last_modification(self) -> _builtins.str:
        """
        Description of the latest modification of the Oracle DB Azure Blob Mount Resource.
        """
        return pulumi.get(self, "last_modification")

    @_builtins.property
    @pulumi.getter(name="lifecycleStateDetails")
    def lifecycle_state_details(self) -> _builtins.str:
        """
        Description of the current lifecycle state in more detail.
        """
        return pulumi.get(self, "lifecycle_state_details")

    @_builtins.property
    @pulumi.getter(name="mountPath")
    def mount_path(self) -> _builtins.str:
        """
        Azure Container mount path.
        """
        return pulumi.get(self, "mount_path")

    @_builtins.property
    @pulumi.getter(name="oracleDbAzureBlobContainerId")
    def oracle_db_azure_blob_container_id(self) -> _builtins.str:
        """
        The OCID of the Oracle DB Azure Blob Container Resource.
        """
        return pulumi.get(self, "oracle_db_azure_blob_container_id")

    @_builtins.property
    @pulumi.getter(name="oracleDbAzureBlobMountId")
    def oracle_db_azure_blob_mount_id(self) -> _builtins.str:
        return pulumi.get(self, "oracle_db_azure_blob_mount_id")

    @_builtins.property
    @pulumi.getter(name="oracleDbAzureConnectorId")
    def oracle_db_azure_connector_id(self) -> _builtins.str:
        """
        The OCID of the Oracle DB Azure Connector Resource.
        """
        return pulumi.get(self, "oracle_db_azure_connector_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current lifecycle state of the Azure Arc Agent Resource.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        Time when the Oracle DB Azure Blob Mount was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        Time when the Oracle DB Azure Blob Mount was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetDbmulticloudOracleDbAzureBlobMountResult(GetDbmulticloudOracleDbAzureBlobMountResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDbmulticloudOracleDbAzureBlobMountResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            last_modification=self.last_modification,
            lifecycle_state_details=self.lifecycle_state_details,
            mount_path=self.mount_path,
            oracle_db_azure_blob_container_id=self.oracle_db_azure_blob_container_id,
            oracle_db_azure_blob_mount_id=self.oracle_db_azure_blob_mount_id,
            oracle_db_azure_connector_id=self.oracle_db_azure_connector_id,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_dbmulticloud_oracle_db_azure_blob_mount(oracle_db_azure_blob_mount_id: Optional[_builtins.str] = None,
                                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDbmulticloudOracleDbAzureBlobMountResult:
    """
    This data source provides details about a specific Oracle Db Azure Blob Mount resource in Oracle Cloud Infrastructure Dbmulticloud service.

    Get Oracle DB Azure Blob Mount Details form a particular Container Resource ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_oracle_db_azure_blob_mount = oci.oci.get_dbmulticloud_oracle_db_azure_blob_mount(oracle_db_azure_blob_mount_id=test_oracle_db_azure_blob_mount_oci_dbmulticloud_oracle_db_azure_blob_mount["id"])
    ```


    :param _builtins.str oracle_db_azure_blob_mount_id: The ID of the Azure Container Resource.
    """
    __args__ = dict()
    __args__['oracleDbAzureBlobMountId'] = oracle_db_azure_blob_mount_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:oci/getDbmulticloudOracleDbAzureBlobMount:getDbmulticloudOracleDbAzureBlobMount', __args__, opts=opts, typ=GetDbmulticloudOracleDbAzureBlobMountResult).value

    return AwaitableGetDbmulticloudOracleDbAzureBlobMountResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        last_modification=pulumi.get(__ret__, 'last_modification'),
        lifecycle_state_details=pulumi.get(__ret__, 'lifecycle_state_details'),
        mount_path=pulumi.get(__ret__, 'mount_path'),
        oracle_db_azure_blob_container_id=pulumi.get(__ret__, 'oracle_db_azure_blob_container_id'),
        oracle_db_azure_blob_mount_id=pulumi.get(__ret__, 'oracle_db_azure_blob_mount_id'),
        oracle_db_azure_connector_id=pulumi.get(__ret__, 'oracle_db_azure_connector_id'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_dbmulticloud_oracle_db_azure_blob_mount_output(oracle_db_azure_blob_mount_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                       opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDbmulticloudOracleDbAzureBlobMountResult]:
    """
    This data source provides details about a specific Oracle Db Azure Blob Mount resource in Oracle Cloud Infrastructure Dbmulticloud service.

    Get Oracle DB Azure Blob Mount Details form a particular Container Resource ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_oracle_db_azure_blob_mount = oci.oci.get_dbmulticloud_oracle_db_azure_blob_mount(oracle_db_azure_blob_mount_id=test_oracle_db_azure_blob_mount_oci_dbmulticloud_oracle_db_azure_blob_mount["id"])
    ```


    :param _builtins.str oracle_db_azure_blob_mount_id: The ID of the Azure Container Resource.
    """
    __args__ = dict()
    __args__['oracleDbAzureBlobMountId'] = oracle_db_azure_blob_mount_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:oci/getDbmulticloudOracleDbAzureBlobMount:getDbmulticloudOracleDbAzureBlobMount', __args__, opts=opts, typ=GetDbmulticloudOracleDbAzureBlobMountResult)
    return __ret__.apply(lambda __response__: GetDbmulticloudOracleDbAzureBlobMountResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        last_modification=pulumi.get(__response__, 'last_modification'),
        lifecycle_state_details=pulumi.get(__response__, 'lifecycle_state_details'),
        mount_path=pulumi.get(__response__, 'mount_path'),
        oracle_db_azure_blob_container_id=pulumi.get(__response__, 'oracle_db_azure_blob_container_id'),
        oracle_db_azure_blob_mount_id=pulumi.get(__response__, 'oracle_db_azure_blob_mount_id'),
        oracle_db_azure_connector_id=pulumi.get(__response__, 'oracle_db_azure_connector_id'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
