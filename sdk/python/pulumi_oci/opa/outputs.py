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
    'GetOpaInstancesFilterResult',
    'GetOpaInstancesOpaInstanceCollectionResult',
    'GetOpaInstancesOpaInstanceCollectionItemResult',
]

@pulumi.output_type
class GetOpaInstancesFilterResult(dict):
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
class GetOpaInstancesOpaInstanceCollectionResult(dict):
    def __init__(__self__, *,
                 items: Sequence['outputs.GetOpaInstancesOpaInstanceCollectionItemResult']):
        pulumi.set(__self__, "items", items)

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetOpaInstancesOpaInstanceCollectionItemResult']:
        return pulumi.get(self, "items")


@pulumi.output_type
class GetOpaInstancesOpaInstanceCollectionItemResult(dict):
    def __init__(__self__, *,
                 compartment_id: str,
                 consumption_model: str,
                 defined_tags: Mapping[str, Any],
                 description: str,
                 display_name: str,
                 freeform_tags: Mapping[str, Any],
                 id: str,
                 idcs_at: str,
                 identity_app_display_name: str,
                 identity_app_guid: str,
                 identity_app_opc_service_instance_guid: str,
                 identity_domain_url: str,
                 instance_url: str,
                 is_breakglass_enabled: bool,
                 metering_type: str,
                 shape_name: str,
                 state: str,
                 system_tags: Mapping[str, Any],
                 time_created: str,
                 time_updated: str):
        """
        :param str compartment_id: The ID of the compartment in which to list resources.
        :param str consumption_model: The entitlement used for billing purposes
        :param Mapping[str, Any] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param str description: Description of the Process Automation instance.
        :param str display_name: A filter to return only resources that match the entire display name given.
        :param Mapping[str, Any] freeform_tags: Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param str id: unique OpaInstance identifier
        :param str identity_app_display_name: This property specifies the name of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
        :param str identity_app_guid: This property specifies the GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user role mappings to grant access to this OPA instance for users within the identity domain.
        :param str identity_app_opc_service_instance_guid: This property specifies the OPC Service Instance GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
        :param str identity_domain_url: This property specifies the domain url of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
        :param str instance_url: OPA Instance URL
        :param bool is_breakglass_enabled: indicates if breakGlass is enabled for the opa instance.
        :param str metering_type: MeteringType Identifier
        :param str shape_name: Shape of the instance.
        :param str state: A filter to return only resources their lifecycleState matches the given lifecycleState.
        :param Mapping[str, Any] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param str time_created: The time when OpaInstance was created. An RFC3339 formatted datetime string
        :param str time_updated: The time the OpaInstance was updated. An RFC3339 formatted datetime string
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "consumption_model", consumption_model)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "description", description)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "idcs_at", idcs_at)
        pulumi.set(__self__, "identity_app_display_name", identity_app_display_name)
        pulumi.set(__self__, "identity_app_guid", identity_app_guid)
        pulumi.set(__self__, "identity_app_opc_service_instance_guid", identity_app_opc_service_instance_guid)
        pulumi.set(__self__, "identity_domain_url", identity_domain_url)
        pulumi.set(__self__, "instance_url", instance_url)
        pulumi.set(__self__, "is_breakglass_enabled", is_breakglass_enabled)
        pulumi.set(__self__, "metering_type", metering_type)
        pulumi.set(__self__, "shape_name", shape_name)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "system_tags", system_tags)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The ID of the compartment in which to list resources.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="consumptionModel")
    def consumption_model(self) -> str:
        """
        The entitlement used for billing purposes
        """
        return pulumi.get(self, "consumption_model")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Description of the Process Automation instance.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A filter to return only resources that match the entire display name given.
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
        unique OpaInstance identifier
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="idcsAt")
    def idcs_at(self) -> str:
        return pulumi.get(self, "idcs_at")

    @property
    @pulumi.getter(name="identityAppDisplayName")
    def identity_app_display_name(self) -> str:
        """
        This property specifies the name of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
        """
        return pulumi.get(self, "identity_app_display_name")

    @property
    @pulumi.getter(name="identityAppGuid")
    def identity_app_guid(self) -> str:
        """
        This property specifies the GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user role mappings to grant access to this OPA instance for users within the identity domain.
        """
        return pulumi.get(self, "identity_app_guid")

    @property
    @pulumi.getter(name="identityAppOpcServiceInstanceGuid")
    def identity_app_opc_service_instance_guid(self) -> str:
        """
        This property specifies the OPC Service Instance GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
        """
        return pulumi.get(self, "identity_app_opc_service_instance_guid")

    @property
    @pulumi.getter(name="identityDomainUrl")
    def identity_domain_url(self) -> str:
        """
        This property specifies the domain url of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
        """
        return pulumi.get(self, "identity_domain_url")

    @property
    @pulumi.getter(name="instanceUrl")
    def instance_url(self) -> str:
        """
        OPA Instance URL
        """
        return pulumi.get(self, "instance_url")

    @property
    @pulumi.getter(name="isBreakglassEnabled")
    def is_breakglass_enabled(self) -> bool:
        """
        indicates if breakGlass is enabled for the opa instance.
        """
        return pulumi.get(self, "is_breakglass_enabled")

    @property
    @pulumi.getter(name="meteringType")
    def metering_type(self) -> str:
        """
        MeteringType Identifier
        """
        return pulumi.get(self, "metering_type")

    @property
    @pulumi.getter(name="shapeName")
    def shape_name(self) -> str:
        """
        Shape of the instance.
        """
        return pulumi.get(self, "shape_name")

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
        The time when OpaInstance was created. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the OpaInstance was updated. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_updated")

