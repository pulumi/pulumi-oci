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
    'GetFleetResult',
    'AwaitableGetFleetResult',
    'get_fleet',
    'get_fleet_output',
]

@pulumi.output_type
class GetFleetResult:
    """
    A collection of values returned by getFleet.
    """
    def __init__(__self__, compartment_id=None, credentials=None, defined_tags=None, description=None, details=None, display_name=None, environment_type=None, fleet_id=None, freeform_tags=None, id=None, is_target_auto_confirm=None, lifecycle_details=None, notification_preferences=None, parent_fleet_id=None, products=None, properties=None, resource_region=None, resource_selections=None, resources=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if credentials and not isinstance(credentials, list):
            raise TypeError("Expected argument 'credentials' to be a list")
        pulumi.set(__self__, "credentials", credentials)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if details and not isinstance(details, list):
            raise TypeError("Expected argument 'details' to be a list")
        pulumi.set(__self__, "details", details)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if environment_type and not isinstance(environment_type, str):
            raise TypeError("Expected argument 'environment_type' to be a str")
        pulumi.set(__self__, "environment_type", environment_type)
        if fleet_id and not isinstance(fleet_id, str):
            raise TypeError("Expected argument 'fleet_id' to be a str")
        pulumi.set(__self__, "fleet_id", fleet_id)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_target_auto_confirm and not isinstance(is_target_auto_confirm, bool):
            raise TypeError("Expected argument 'is_target_auto_confirm' to be a bool")
        pulumi.set(__self__, "is_target_auto_confirm", is_target_auto_confirm)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if notification_preferences and not isinstance(notification_preferences, list):
            raise TypeError("Expected argument 'notification_preferences' to be a list")
        pulumi.set(__self__, "notification_preferences", notification_preferences)
        if parent_fleet_id and not isinstance(parent_fleet_id, str):
            raise TypeError("Expected argument 'parent_fleet_id' to be a str")
        pulumi.set(__self__, "parent_fleet_id", parent_fleet_id)
        if products and not isinstance(products, list):
            raise TypeError("Expected argument 'products' to be a list")
        pulumi.set(__self__, "products", products)
        if properties and not isinstance(properties, list):
            raise TypeError("Expected argument 'properties' to be a list")
        pulumi.set(__self__, "properties", properties)
        if resource_region and not isinstance(resource_region, str):
            raise TypeError("Expected argument 'resource_region' to be a str")
        pulumi.set(__self__, "resource_region", resource_region)
        if resource_selections and not isinstance(resource_selections, list):
            raise TypeError("Expected argument 'resource_selections' to be a list")
        pulumi.set(__self__, "resource_selections", resource_selections)
        if resources and not isinstance(resources, list):
            raise TypeError("Expected argument 'resources' to be a list")
        pulumi.set(__self__, "resources", resources)
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
        Compartment Identifier[OCID].
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def credentials(self) -> Sequence['outputs.GetFleetCredentialResult']:
        """
        Credentials associated with the Fleet.
        """
        return pulumi.get(self, "credentials")

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
        A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter
    def details(self) -> Sequence['outputs.GetFleetDetailResult']:
        """
        Fleet Type
        """
        return pulumi.get(self, "details")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="environmentType")
    def environment_type(self) -> _builtins.str:
        """
        Environment Type associated with the Fleet. Applicable for ENVIRONMENT fleet types.
        """
        return pulumi.get(self, "environment_type")

    @_builtins.property
    @pulumi.getter(name="fleetId")
    def fleet_id(self) -> _builtins.str:
        return pulumi.get(self, "fleet_id")

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
        The OCID of the resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isTargetAutoConfirm")
    def is_target_auto_confirm(self) -> _builtins.bool:
        """
        A value that represents if auto-confirming of the targets can be enabled. This will allow targets to be auto-confirmed in the fleet without manual intervention.
        """
        return pulumi.get(self, "is_target_auto_confirm")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="notificationPreferences")
    def notification_preferences(self) -> Sequence['outputs.GetFleetNotificationPreferenceResult']:
        """
        Notification Preferences associated with the Fleet.
        """
        return pulumi.get(self, "notification_preferences")

    @_builtins.property
    @pulumi.getter(name="parentFleetId")
    def parent_fleet_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet that would be the parent for this fleet.
        """
        return pulumi.get(self, "parent_fleet_id")

    @_builtins.property
    @pulumi.getter
    def products(self) -> Sequence[_builtins.str]:
        """
        Products associated with the Fleet.
        """
        return pulumi.get(self, "products")

    @_builtins.property
    @pulumi.getter
    def properties(self) -> Sequence['outputs.GetFleetPropertyResult']:
        """
        Properties associated with the Fleet.
        """
        return pulumi.get(self, "properties")

    @_builtins.property
    @pulumi.getter(name="resourceRegion")
    def resource_region(self) -> _builtins.str:
        """
        Associated region
        """
        return pulumi.get(self, "resource_region")

    @_builtins.property
    @pulumi.getter(name="resourceSelections")
    def resource_selections(self) -> Sequence['outputs.GetFleetResourceSelectionResult']:
        """
        Resource Selection Type
        """
        return pulumi.get(self, "resource_selections")

    @_builtins.property
    @pulumi.getter
    def resources(self) -> Sequence['outputs.GetFleetResourceResult']:
        """
        Resources associated with the Fleet if resourceSelectionType is MANUAL.
        """
        return pulumi.get(self, "resources")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The lifecycle state of the Fleet.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The time this resource was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The time this resource was last updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetFleetResult(GetFleetResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetFleetResult(
            compartment_id=self.compartment_id,
            credentials=self.credentials,
            defined_tags=self.defined_tags,
            description=self.description,
            details=self.details,
            display_name=self.display_name,
            environment_type=self.environment_type,
            fleet_id=self.fleet_id,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_target_auto_confirm=self.is_target_auto_confirm,
            lifecycle_details=self.lifecycle_details,
            notification_preferences=self.notification_preferences,
            parent_fleet_id=self.parent_fleet_id,
            products=self.products,
            properties=self.properties,
            resource_region=self.resource_region,
            resource_selections=self.resource_selections,
            resources=self.resources,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_fleet(fleet_id: Optional[_builtins.str] = None,
              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetFleetResult:
    """
    This data source provides details about a specific Fleet resource in Oracle Cloud Infrastructure Fleet Apps Management service.

    Get the details of a fleet in Fleet Application Management.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fleet = oci.FleetAppsManagement.get_fleet(fleet_id=test_fleet_oci_fleet_apps_management_fleet["id"])
    ```


    :param _builtins.str fleet_id: Unique Fleet identifier.
    """
    __args__ = dict()
    __args__['fleetId'] = fleet_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:FleetAppsManagement/getFleet:getFleet', __args__, opts=opts, typ=GetFleetResult).value

    return AwaitableGetFleetResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        credentials=pulumi.get(__ret__, 'credentials'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        details=pulumi.get(__ret__, 'details'),
        display_name=pulumi.get(__ret__, 'display_name'),
        environment_type=pulumi.get(__ret__, 'environment_type'),
        fleet_id=pulumi.get(__ret__, 'fleet_id'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        is_target_auto_confirm=pulumi.get(__ret__, 'is_target_auto_confirm'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        notification_preferences=pulumi.get(__ret__, 'notification_preferences'),
        parent_fleet_id=pulumi.get(__ret__, 'parent_fleet_id'),
        products=pulumi.get(__ret__, 'products'),
        properties=pulumi.get(__ret__, 'properties'),
        resource_region=pulumi.get(__ret__, 'resource_region'),
        resource_selections=pulumi.get(__ret__, 'resource_selections'),
        resources=pulumi.get(__ret__, 'resources'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_fleet_output(fleet_id: Optional[pulumi.Input[_builtins.str]] = None,
                     opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetFleetResult]:
    """
    This data source provides details about a specific Fleet resource in Oracle Cloud Infrastructure Fleet Apps Management service.

    Get the details of a fleet in Fleet Application Management.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fleet = oci.FleetAppsManagement.get_fleet(fleet_id=test_fleet_oci_fleet_apps_management_fleet["id"])
    ```


    :param _builtins.str fleet_id: Unique Fleet identifier.
    """
    __args__ = dict()
    __args__['fleetId'] = fleet_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:FleetAppsManagement/getFleet:getFleet', __args__, opts=opts, typ=GetFleetResult)
    return __ret__.apply(lambda __response__: GetFleetResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        credentials=pulumi.get(__response__, 'credentials'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        details=pulumi.get(__response__, 'details'),
        display_name=pulumi.get(__response__, 'display_name'),
        environment_type=pulumi.get(__response__, 'environment_type'),
        fleet_id=pulumi.get(__response__, 'fleet_id'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        is_target_auto_confirm=pulumi.get(__response__, 'is_target_auto_confirm'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        notification_preferences=pulumi.get(__response__, 'notification_preferences'),
        parent_fleet_id=pulumi.get(__response__, 'parent_fleet_id'),
        products=pulumi.get(__response__, 'products'),
        properties=pulumi.get(__response__, 'properties'),
        resource_region=pulumi.get(__response__, 'resource_region'),
        resource_selections=pulumi.get(__response__, 'resource_selections'),
        resources=pulumi.get(__response__, 'resources'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
