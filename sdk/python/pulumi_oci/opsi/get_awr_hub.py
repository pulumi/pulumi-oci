# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetAwrHubResult',
    'AwaitableGetAwrHubResult',
    'get_awr_hub',
    'get_awr_hub_output',
]

@pulumi.output_type
class GetAwrHubResult:
    """
    A collection of values returned by getAwrHub.
    """
    def __init__(__self__, awr_hub_id=None, awr_mailbox_url=None, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, lifecycle_details=None, object_storage_bucket_name=None, operations_insights_warehouse_id=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if awr_hub_id and not isinstance(awr_hub_id, str):
            raise TypeError("Expected argument 'awr_hub_id' to be a str")
        pulumi.set(__self__, "awr_hub_id", awr_hub_id)
        if awr_mailbox_url and not isinstance(awr_mailbox_url, str):
            raise TypeError("Expected argument 'awr_mailbox_url' to be a str")
        pulumi.set(__self__, "awr_mailbox_url", awr_mailbox_url)
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
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if object_storage_bucket_name and not isinstance(object_storage_bucket_name, str):
            raise TypeError("Expected argument 'object_storage_bucket_name' to be a str")
        pulumi.set(__self__, "object_storage_bucket_name", object_storage_bucket_name)
        if operations_insights_warehouse_id and not isinstance(operations_insights_warehouse_id, str):
            raise TypeError("Expected argument 'operations_insights_warehouse_id' to be a str")
        pulumi.set(__self__, "operations_insights_warehouse_id", operations_insights_warehouse_id)
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
    @pulumi.getter(name="awrHubId")
    def awr_hub_id(self) -> str:
        return pulumi.get(self, "awr_hub_id")

    @property
    @pulumi.getter(name="awrMailboxUrl")
    def awr_mailbox_url(self) -> str:
        """
        Mailbox URL required for AWR hub and AWR source setup.
        """
        return pulumi.get(self, "awr_mailbox_url")

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
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        User-friedly name of AWR Hub that does not have to be unique.
        """
        return pulumi.get(self, "display_name")

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
        AWR Hub OCID
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
    @pulumi.getter(name="objectStorageBucketName")
    def object_storage_bucket_name(self) -> str:
        """
        Object Storage Bucket Name
        """
        return pulumi.get(self, "object_storage_bucket_name")

    @property
    @pulumi.getter(name="operationsInsightsWarehouseId")
    def operations_insights_warehouse_id(self) -> str:
        """
        OPSI Warehouse OCID
        """
        return pulumi.get(self, "operations_insights_warehouse_id")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        Possible lifecycle states
        """
        return pulumi.get(self, "state")

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
        The time at which the resource was first created. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time at which the resource was last updated. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetAwrHubResult(GetAwrHubResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAwrHubResult(
            awr_hub_id=self.awr_hub_id,
            awr_mailbox_url=self.awr_mailbox_url,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            object_storage_bucket_name=self.object_storage_bucket_name,
            operations_insights_warehouse_id=self.operations_insights_warehouse_id,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_awr_hub(awr_hub_id: Optional[str] = None,
                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAwrHubResult:
    """
    This data source provides details about a specific Awr Hub resource in Oracle Cloud Infrastructure Opsi service.

    Gets details of an AWR hub.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_awr_hub = oci.Opsi.get_awr_hub(awr_hub_id=oci_opsi_awr_hub["test_awr_hub"]["id"])
    ```


    :param str awr_hub_id: Unique Awr Hub identifier
    """
    __args__ = dict()
    __args__['awrHubId'] = awr_hub_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Opsi/getAwrHub:getAwrHub', __args__, opts=opts, typ=GetAwrHubResult).value

    return AwaitableGetAwrHubResult(
        awr_hub_id=__ret__.awr_hub_id,
        awr_mailbox_url=__ret__.awr_mailbox_url,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        lifecycle_details=__ret__.lifecycle_details,
        object_storage_bucket_name=__ret__.object_storage_bucket_name,
        operations_insights_warehouse_id=__ret__.operations_insights_warehouse_id,
        state=__ret__.state,
        system_tags=__ret__.system_tags,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)


@_utilities.lift_output_func(get_awr_hub)
def get_awr_hub_output(awr_hub_id: Optional[pulumi.Input[str]] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetAwrHubResult]:
    """
    This data source provides details about a specific Awr Hub resource in Oracle Cloud Infrastructure Opsi service.

    Gets details of an AWR hub.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_awr_hub = oci.Opsi.get_awr_hub(awr_hub_id=oci_opsi_awr_hub["test_awr_hub"]["id"])
    ```


    :param str awr_hub_id: Unique Awr Hub identifier
    """
    ...