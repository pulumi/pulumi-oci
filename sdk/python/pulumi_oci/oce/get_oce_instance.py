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
    'GetOceInstanceResult',
    'AwaitableGetOceInstanceResult',
    'get_oce_instance',
    'get_oce_instance_output',
]

@pulumi.output_type
class GetOceInstanceResult:
    """
    A collection of values returned by getOceInstance.
    """
    def __init__(__self__, add_on_features=None, admin_email=None, compartment_id=None, defined_tags=None, description=None, freeform_tags=None, guid=None, id=None, idcs_access_token=None, idcs_tenancy=None, instance_access_type=None, instance_license_type=None, instance_usage_type=None, lifecycle_details=None, name=None, object_storage_namespace=None, oce_instance_id=None, service=None, state=None, state_message=None, system_tags=None, tenancy_id=None, tenancy_name=None, time_created=None, time_updated=None, upgrade_schedule=None, waf_primary_domain=None):
        if add_on_features and not isinstance(add_on_features, list):
            raise TypeError("Expected argument 'add_on_features' to be a list")
        pulumi.set(__self__, "add_on_features", add_on_features)
        if admin_email and not isinstance(admin_email, str):
            raise TypeError("Expected argument 'admin_email' to be a str")
        pulumi.set(__self__, "admin_email", admin_email)
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
        if guid and not isinstance(guid, str):
            raise TypeError("Expected argument 'guid' to be a str")
        pulumi.set(__self__, "guid", guid)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if idcs_access_token and not isinstance(idcs_access_token, str):
            raise TypeError("Expected argument 'idcs_access_token' to be a str")
        pulumi.set(__self__, "idcs_access_token", idcs_access_token)
        if idcs_tenancy and not isinstance(idcs_tenancy, str):
            raise TypeError("Expected argument 'idcs_tenancy' to be a str")
        pulumi.set(__self__, "idcs_tenancy", idcs_tenancy)
        if instance_access_type and not isinstance(instance_access_type, str):
            raise TypeError("Expected argument 'instance_access_type' to be a str")
        pulumi.set(__self__, "instance_access_type", instance_access_type)
        if instance_license_type and not isinstance(instance_license_type, str):
            raise TypeError("Expected argument 'instance_license_type' to be a str")
        pulumi.set(__self__, "instance_license_type", instance_license_type)
        if instance_usage_type and not isinstance(instance_usage_type, str):
            raise TypeError("Expected argument 'instance_usage_type' to be a str")
        pulumi.set(__self__, "instance_usage_type", instance_usage_type)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if object_storage_namespace and not isinstance(object_storage_namespace, str):
            raise TypeError("Expected argument 'object_storage_namespace' to be a str")
        pulumi.set(__self__, "object_storage_namespace", object_storage_namespace)
        if oce_instance_id and not isinstance(oce_instance_id, str):
            raise TypeError("Expected argument 'oce_instance_id' to be a str")
        pulumi.set(__self__, "oce_instance_id", oce_instance_id)
        if service and not isinstance(service, dict):
            raise TypeError("Expected argument 'service' to be a dict")
        pulumi.set(__self__, "service", service)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if state_message and not isinstance(state_message, str):
            raise TypeError("Expected argument 'state_message' to be a str")
        pulumi.set(__self__, "state_message", state_message)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if tenancy_id and not isinstance(tenancy_id, str):
            raise TypeError("Expected argument 'tenancy_id' to be a str")
        pulumi.set(__self__, "tenancy_id", tenancy_id)
        if tenancy_name and not isinstance(tenancy_name, str):
            raise TypeError("Expected argument 'tenancy_name' to be a str")
        pulumi.set(__self__, "tenancy_name", tenancy_name)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if upgrade_schedule and not isinstance(upgrade_schedule, str):
            raise TypeError("Expected argument 'upgrade_schedule' to be a str")
        pulumi.set(__self__, "upgrade_schedule", upgrade_schedule)
        if waf_primary_domain and not isinstance(waf_primary_domain, str):
            raise TypeError("Expected argument 'waf_primary_domain' to be a str")
        pulumi.set(__self__, "waf_primary_domain", waf_primary_domain)

    @property
    @pulumi.getter(name="addOnFeatures")
    def add_on_features(self) -> Sequence[str]:
        """
        a list of add-on features for the ocm instance
        """
        return pulumi.get(self, "add_on_features")

    @property
    @pulumi.getter(name="adminEmail")
    def admin_email(self) -> str:
        """
        Admin Email for Notification
        """
        return pulumi.get(self, "admin_email")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        Compartment Identifier
        """
        return pulumi.get(self, "compartment_id")

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
        OceInstance description, can be updated
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def guid(self) -> str:
        """
        Unique GUID identifier that is immutable on creation
        """
        return pulumi.get(self, "guid")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        Unique identifier that is immutable on creation
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="idcsAccessToken")
    def idcs_access_token(self) -> str:
        return pulumi.get(self, "idcs_access_token")

    @property
    @pulumi.getter(name="idcsTenancy")
    def idcs_tenancy(self) -> str:
        """
        IDCS Tenancy Identifier
        """
        return pulumi.get(self, "idcs_tenancy")

    @property
    @pulumi.getter(name="instanceAccessType")
    def instance_access_type(self) -> str:
        """
        Flag indicating whether the instance access is private or public
        """
        return pulumi.get(self, "instance_access_type")

    @property
    @pulumi.getter(name="instanceLicenseType")
    def instance_license_type(self) -> str:
        """
        Flag indicating whether the instance license is new cloud or bring your own license
        """
        return pulumi.get(self, "instance_license_type")

    @property
    @pulumi.getter(name="instanceUsageType")
    def instance_usage_type(self) -> str:
        """
        Instance type based on its usage
        """
        return pulumi.get(self, "instance_usage_type")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        Details of the current state of the instance lifecycle
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        OceInstance Name
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="objectStorageNamespace")
    def object_storage_namespace(self) -> str:
        """
        Object Storage Namespace of tenancy
        """
        return pulumi.get(self, "object_storage_namespace")

    @property
    @pulumi.getter(name="oceInstanceId")
    def oce_instance_id(self) -> str:
        return pulumi.get(self, "oce_instance_id")

    @property
    @pulumi.getter
    def service(self) -> Mapping[str, Any]:
        """
        SERVICE data. Example: `{"service": {"IDCS": "value"}}`
        """
        return pulumi.get(self, "service")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the instance lifecycle.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="stateMessage")
    def state_message(self) -> str:
        """
        An message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "state_message")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="tenancyId")
    def tenancy_id(self) -> str:
        """
        Tenancy Identifier
        """
        return pulumi.get(self, "tenancy_id")

    @property
    @pulumi.getter(name="tenancyName")
    def tenancy_name(self) -> str:
        """
        Tenancy Name
        """
        return pulumi.get(self, "tenancy_name")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the the OceInstance was created. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the OceInstance was updated. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter(name="upgradeSchedule")
    def upgrade_schedule(self) -> str:
        """
        Upgrade schedule type representing service to be upgraded immediately whenever latest version is released or delay upgrade of the service to previous released version
        """
        return pulumi.get(self, "upgrade_schedule")

    @property
    @pulumi.getter(name="wafPrimaryDomain")
    def waf_primary_domain(self) -> str:
        """
        Web Application Firewall(WAF) primary domain
        """
        return pulumi.get(self, "waf_primary_domain")


class AwaitableGetOceInstanceResult(GetOceInstanceResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetOceInstanceResult(
            add_on_features=self.add_on_features,
            admin_email=self.admin_email,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            freeform_tags=self.freeform_tags,
            guid=self.guid,
            id=self.id,
            idcs_access_token=self.idcs_access_token,
            idcs_tenancy=self.idcs_tenancy,
            instance_access_type=self.instance_access_type,
            instance_license_type=self.instance_license_type,
            instance_usage_type=self.instance_usage_type,
            lifecycle_details=self.lifecycle_details,
            name=self.name,
            object_storage_namespace=self.object_storage_namespace,
            oce_instance_id=self.oce_instance_id,
            service=self.service,
            state=self.state,
            state_message=self.state_message,
            system_tags=self.system_tags,
            tenancy_id=self.tenancy_id,
            tenancy_name=self.tenancy_name,
            time_created=self.time_created,
            time_updated=self.time_updated,
            upgrade_schedule=self.upgrade_schedule,
            waf_primary_domain=self.waf_primary_domain)


def get_oce_instance(oce_instance_id: Optional[str] = None,
                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetOceInstanceResult:
    """
    This data source provides details about a specific Oce Instance resource in Oracle Cloud Infrastructure Content and Experience service.

    Gets a OceInstance by identifier

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_oce_instance = oci.Oce.get_oce_instance(oce_instance_id=oci_oce_oce_instance["test_oce_instance"]["id"])
    ```


    :param str oce_instance_id: unique OceInstance identifier
    """
    __args__ = dict()
    __args__['oceInstanceId'] = oce_instance_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Oce/getOceInstance:getOceInstance', __args__, opts=opts, typ=GetOceInstanceResult).value

    return AwaitableGetOceInstanceResult(
        add_on_features=__ret__.add_on_features,
        admin_email=__ret__.admin_email,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        description=__ret__.description,
        freeform_tags=__ret__.freeform_tags,
        guid=__ret__.guid,
        id=__ret__.id,
        idcs_access_token=__ret__.idcs_access_token,
        idcs_tenancy=__ret__.idcs_tenancy,
        instance_access_type=__ret__.instance_access_type,
        instance_license_type=__ret__.instance_license_type,
        instance_usage_type=__ret__.instance_usage_type,
        lifecycle_details=__ret__.lifecycle_details,
        name=__ret__.name,
        object_storage_namespace=__ret__.object_storage_namespace,
        oce_instance_id=__ret__.oce_instance_id,
        service=__ret__.service,
        state=__ret__.state,
        state_message=__ret__.state_message,
        system_tags=__ret__.system_tags,
        tenancy_id=__ret__.tenancy_id,
        tenancy_name=__ret__.tenancy_name,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated,
        upgrade_schedule=__ret__.upgrade_schedule,
        waf_primary_domain=__ret__.waf_primary_domain)


@_utilities.lift_output_func(get_oce_instance)
def get_oce_instance_output(oce_instance_id: Optional[pulumi.Input[str]] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetOceInstanceResult]:
    """
    This data source provides details about a specific Oce Instance resource in Oracle Cloud Infrastructure Content and Experience service.

    Gets a OceInstance by identifier

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_oce_instance = oci.Oce.get_oce_instance(oce_instance_id=oci_oce_oce_instance["test_oce_instance"]["id"])
    ```


    :param str oce_instance_id: unique OceInstance identifier
    """
    ...