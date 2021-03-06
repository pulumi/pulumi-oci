# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetOdaInstancesFilterResult',
    'GetOdaInstancesOdaInstanceResult',
]

@pulumi.output_type
class GetOdaInstancesFilterResult(dict):
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
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
class GetOdaInstancesOdaInstanceResult(dict):
    def __init__(__self__, *,
                 compartment_id: str,
                 connector_url: str,
                 defined_tags: Mapping[str, Any],
                 description: str,
                 display_name: str,
                 freeform_tags: Mapping[str, Any],
                 id: str,
                 lifecycle_sub_state: str,
                 shape_name: str,
                 state: str,
                 state_message: str,
                 time_created: str,
                 time_updated: str,
                 web_app_url: str):
        """
        :param str compartment_id: List the Digital Assistant instances that belong to this compartment.
        :param str connector_url: URL for the connector's endpoint.
        :param Mapping[str, Any] defined_tags: Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        :param str description: Description of the Digital Assistant instance.
        :param str display_name: List only the information for the Digital Assistant instance with this user-friendly name. These names don't have to be unique and may change.  Example: `My new resource`
        :param Mapping[str, Any] freeform_tags: Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param str id: Unique immutable identifier that was assigned when the instance was created.
        :param str lifecycle_sub_state: The current sub-state of the Digital Assistant instance.
        :param str shape_name: Shape or size of the instance.
        :param str state: List only the Digital Assistant instances that are in this lifecycle state.
        :param str state_message: A message that describes the current state in more detail. For example, actionable information about an instance that's in the `FAILED` state.
        :param str time_created: When the Digital Assistant instance was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        :param str time_updated: When the Digital Assistance instance was last updated. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        :param str web_app_url: URL for the Digital Assistant web application that's associated with the instance.
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "connector_url", connector_url)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "description", description)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "lifecycle_sub_state", lifecycle_sub_state)
        pulumi.set(__self__, "shape_name", shape_name)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "state_message", state_message)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_updated", time_updated)
        pulumi.set(__self__, "web_app_url", web_app_url)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        List the Digital Assistant instances that belong to this compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="connectorUrl")
    def connector_url(self) -> str:
        """
        URL for the connector's endpoint.
        """
        return pulumi.get(self, "connector_url")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Description of the Digital Assistant instance.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        List only the information for the Digital Assistant instance with this user-friendly name. These names don't have to be unique and may change.  Example: `My new resource`
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
        Unique immutable identifier that was assigned when the instance was created.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lifecycleSubState")
    def lifecycle_sub_state(self) -> str:
        """
        The current sub-state of the Digital Assistant instance.
        """
        return pulumi.get(self, "lifecycle_sub_state")

    @property
    @pulumi.getter(name="shapeName")
    def shape_name(self) -> str:
        """
        Shape or size of the instance.
        """
        return pulumi.get(self, "shape_name")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        List only the Digital Assistant instances that are in this lifecycle state.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="stateMessage")
    def state_message(self) -> str:
        """
        A message that describes the current state in more detail. For example, actionable information about an instance that's in the `FAILED` state.
        """
        return pulumi.get(self, "state_message")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        When the Digital Assistant instance was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        When the Digital Assistance instance was last updated. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter(name="webAppUrl")
    def web_app_url(self) -> str:
        """
        URL for the Digital Assistant web application that's associated with the instance.
        """
        return pulumi.get(self, "web_app_url")


