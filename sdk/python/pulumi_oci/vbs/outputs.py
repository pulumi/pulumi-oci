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
    'GetInstVbsInstancesFilterResult',
    'GetInstVbsInstancesVbsInstanceSummaryCollectionResult',
    'GetInstVbsInstancesVbsInstanceSummaryCollectionItemResult',
]

@pulumi.output_type
class GetInstVbsInstancesFilterResult(dict):
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: A filter to return only resources that match the entire name given.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to return only resources that match the entire name given.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")


@pulumi.output_type
class GetInstVbsInstancesVbsInstanceSummaryCollectionResult(dict):
    def __init__(__self__, *,
                 items: Sequence['outputs.GetInstVbsInstancesVbsInstanceSummaryCollectionItemResult']):
        pulumi.set(__self__, "items", items)

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetInstVbsInstancesVbsInstanceSummaryCollectionItemResult']:
        return pulumi.get(self, "items")


@pulumi.output_type
class GetInstVbsInstancesVbsInstanceSummaryCollectionItemResult(dict):
    def __init__(__self__, *,
                 compartment_id: str,
                 defined_tags: Mapping[str, Any],
                 display_name: str,
                 freeform_tags: Mapping[str, Any],
                 id: str,
                 idcs_access_token: str,
                 is_resource_usage_agreement_granted: bool,
                 lifecyle_details: str,
                 name: str,
                 resource_compartment_id: str,
                 state: str,
                 system_tags: Mapping[str, Any],
                 time_created: str,
                 time_updated: str,
                 vbs_access_url: str):
        """
        :param str compartment_id: The ID of the compartment in which to list resources.
        :param Mapping[str, Any] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param str display_name: Service instance display name
        :param Mapping[str, Any] freeform_tags: Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param str id: unique VbsInstance identifier
        :param bool is_resource_usage_agreement_granted: Whether the VBS service instance owner explicitly approved VBS to create and use resources in the customer tenancy
        :param str lifecyle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        :param str name: A filter to return only resources that match the entire name given.
        :param str resource_compartment_id: Compartment where VBS may create additional resources for the service instance
        :param str state: A filter to return only resources their lifecycleState matches the given lifecycleState.
        :param Mapping[str, Any] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param str time_created: The time the the VbsInstance was created. An RFC3339 formatted datetime string
        :param str time_updated: The time the VbsInstance was updated. An RFC3339 formatted datetime string
        :param str vbs_access_url: Public web URL for accessing the VBS service instance
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "idcs_access_token", idcs_access_token)
        pulumi.set(__self__, "is_resource_usage_agreement_granted", is_resource_usage_agreement_granted)
        pulumi.set(__self__, "lifecyle_details", lifecyle_details)
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "resource_compartment_id", resource_compartment_id)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "system_tags", system_tags)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_updated", time_updated)
        pulumi.set(__self__, "vbs_access_url", vbs_access_url)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The ID of the compartment in which to list resources.
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
        Service instance display name
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
        unique VbsInstance identifier
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="idcsAccessToken")
    def idcs_access_token(self) -> str:
        return pulumi.get(self, "idcs_access_token")

    @property
    @pulumi.getter(name="isResourceUsageAgreementGranted")
    def is_resource_usage_agreement_granted(self) -> bool:
        """
        Whether the VBS service instance owner explicitly approved VBS to create and use resources in the customer tenancy
        """
        return pulumi.get(self, "is_resource_usage_agreement_granted")

    @property
    @pulumi.getter(name="lifecyleDetails")
    def lifecyle_details(self) -> str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecyle_details")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to return only resources that match the entire name given.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="resourceCompartmentId")
    def resource_compartment_id(self) -> str:
        """
        Compartment where VBS may create additional resources for the service instance
        """
        return pulumi.get(self, "resource_compartment_id")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        A filter to return only resources their lifecycleState matches the given lifecycleState.
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
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the the VbsInstance was created. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the VbsInstance was updated. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter(name="vbsAccessUrl")
    def vbs_access_url(self) -> str:
        """
        Public web URL for accessing the VBS service instance
        """
        return pulumi.get(self, "vbs_access_url")

