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
    'SecurityAttributeValidator',
    'GetSecurityAttributeNamespacesFilterResult',
    'GetSecurityAttributeNamespacesSecurityAttributeNamespaceResult',
    'GetSecurityAttributeValidatorResult',
    'GetSecurityAttributesFilterResult',
    'GetSecurityAttributesSecurityAttributeResult',
    'GetSecurityAttributesSecurityAttributeValidatorResult',
]

@pulumi.output_type
class SecurityAttributeValidator(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "validatorType":
            suggest = "validator_type"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in SecurityAttributeValidator. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        SecurityAttributeValidator.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        SecurityAttributeValidator.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 validator_type: _builtins.str,
                 values: Optional[Sequence[_builtins.str]] = None):
        """
        :param _builtins.str validator_type: (Updatable) Specifies the type of validation: a static value (no validation) or a list.
        :param Sequence[_builtins.str] values: (Updatable) The list of allowed values for a security attribute value. 
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "validator_type", validator_type)
        if values is not None:
            pulumi.set(__self__, "values", values)

    @_builtins.property
    @pulumi.getter(name="validatorType")
    def validator_type(self) -> _builtins.str:
        """
        (Updatable) Specifies the type of validation: a static value (no validation) or a list.
        """
        return pulumi.get(self, "validator_type")

    @_builtins.property
    @pulumi.getter
    def values(self) -> Optional[Sequence[_builtins.str]]:
        """
        (Updatable) The list of allowed values for a security attribute value. 


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "values")


@pulumi.output_type
class GetSecurityAttributeNamespacesFilterResult(dict):
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        """
        :param _builtins.str name: A filter to return only resources that match the entire display name given.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        A filter to return only resources that match the entire display name given.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")


@pulumi.output_type
class GetSecurityAttributeNamespacesSecurityAttributeNamespaceResult(dict):
    def __init__(__self__, *,
                 compartment_id: _builtins.str,
                 defined_tags: Mapping[str, _builtins.str],
                 description: _builtins.str,
                 freeform_tags: Mapping[str, _builtins.str],
                 id: _builtins.str,
                 is_retired: _builtins.bool,
                 modes: Sequence[_builtins.str],
                 name: _builtins.str,
                 state: _builtins.str,
                 system_tags: Mapping[str, _builtins.str],
                 time_created: _builtins.str):
        """
        :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        :param Mapping[str, _builtins.str] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param _builtins.str description: A description you create for the security attribute namespace to help you identify it.
        :param Mapping[str, _builtins.str] freeform_tags: Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param _builtins.str id: The OCID of the security attribute namespace.
        :param _builtins.bool is_retired: Indicates whether the security attribute namespace is retired. See [Managing Security Attribute Namespaces](https://docs.cloud.oracle.com/iaas/Content/zero-trust-packet-routing/managing-security-attribute-namespaces.htm).
        :param Sequence[_builtins.str] modes: Indicates possible modes the security attributes in this namespace can be set to. This is not accepted from the user. Currently the supported values are enforce and audit.
        :param _builtins.str name: A filter to return only resources that match the entire display name given.
        :param _builtins.str state: A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
        :param Mapping[str, _builtins.str] system_tags: System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param _builtins.str time_created: Date and time the security attribute namespace was created, in the format defined by RFC3339. Example: `2016-08-25T21:10:29.600Z`
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "description", description)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "is_retired", is_retired)
        pulumi.set(__self__, "modes", modes)
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "system_tags", system_tags)
        pulumi.set(__self__, "time_created", time_created)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
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
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        A description you create for the security attribute namespace to help you identify it.
        """
        return pulumi.get(self, "description")

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
        The OCID of the security attribute namespace.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isRetired")
    def is_retired(self) -> _builtins.bool:
        """
        Indicates whether the security attribute namespace is retired. See [Managing Security Attribute Namespaces](https://docs.cloud.oracle.com/iaas/Content/zero-trust-packet-routing/managing-security-attribute-namespaces.htm).
        """
        return pulumi.get(self, "is_retired")

    @_builtins.property
    @pulumi.getter
    def modes(self) -> Sequence[_builtins.str]:
        """
        Indicates possible modes the security attributes in this namespace can be set to. This is not accepted from the user. Currently the supported values are enforce and audit.
        """
        return pulumi.get(self, "modes")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        A filter to return only resources that match the entire display name given.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
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
        Date and time the security attribute namespace was created, in the format defined by RFC3339. Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")


@pulumi.output_type
class GetSecurityAttributeValidatorResult(dict):
    def __init__(__self__, *,
                 validator_type: _builtins.str,
                 values: Sequence[_builtins.str]):
        """
        :param _builtins.str validator_type: Specifies the type of validation: a static value (no validation) or a list.
        :param Sequence[_builtins.str] values: The list of allowed values for a security attribute value.
        """
        pulumi.set(__self__, "validator_type", validator_type)
        pulumi.set(__self__, "values", values)

    @_builtins.property
    @pulumi.getter(name="validatorType")
    def validator_type(self) -> _builtins.str:
        """
        Specifies the type of validation: a static value (no validation) or a list.
        """
        return pulumi.get(self, "validator_type")

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        """
        The list of allowed values for a security attribute value.
        """
        return pulumi.get(self, "values")


@pulumi.output_type
class GetSecurityAttributesFilterResult(dict):
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        """
        :param _builtins.str name: The name assigned to the security attribute during creation. This is the security attribute key. The name must be unique within the security attribute namespace and cannot be changed.
        :param Sequence[_builtins.str] values: The list of allowed values for a security attribute value.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name assigned to the security attribute during creation. This is the security attribute key. The name must be unique within the security attribute namespace and cannot be changed.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        """
        The list of allowed values for a security attribute value.
        """
        return pulumi.get(self, "values")

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")


@pulumi.output_type
class GetSecurityAttributesSecurityAttributeResult(dict):
    def __init__(__self__, *,
                 compartment_id: _builtins.str,
                 description: _builtins.str,
                 id: _builtins.str,
                 is_retired: _builtins.bool,
                 name: _builtins.str,
                 security_attribute_namespace_id: _builtins.str,
                 security_attribute_namespace_name: _builtins.str,
                 state: _builtins.str,
                 time_created: _builtins.str,
                 type: _builtins.str,
                 validators: Sequence['outputs.GetSecurityAttributesSecurityAttributeValidatorResult']):
        """
        :param _builtins.str compartment_id: The OCID of the compartment that contains the security attribute definition.
        :param _builtins.str description: The description you assign to the security attribute.
        :param _builtins.str id: The OCID of the security attribute definition.
        :param _builtins.bool is_retired: Indicates whether the security attribute is retired. See [Managing Security Attribute Namespaces](https://docs.cloud.oracle.com/iaas/Content/zero-trust-packet-routing/managing-security-attribute-namespaces.htm).
        :param _builtins.str name: The name assigned to the security attribute during creation. This is the security attribute key. The name must be unique within the security attribute namespace and cannot be changed.
        :param _builtins.str security_attribute_namespace_id: The OCID of the security attribute namespace.
        :param _builtins.str security_attribute_namespace_name: The name of the security attribute namespace that contains the security attribute.
        :param _builtins.str state: A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
        :param _builtins.str time_created: Date and time the security attribute was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        :param _builtins.str type: The data type of the security attribute.
        :param Sequence['GetSecurityAttributesSecurityAttributeValidatorArgs'] validators: Validates a security attribute value. Each validator performs validation steps in addition to the standard validation for security attribute values. For more information, see [Limits on Security Attributes](https://docs.cloud.oracle.com/iaas/Content/zero-trust-packet-routing/overview.htm).
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "description", description)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "is_retired", is_retired)
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "security_attribute_namespace_id", security_attribute_namespace_id)
        pulumi.set(__self__, "security_attribute_namespace_name", security_attribute_namespace_name)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "type", type)
        pulumi.set(__self__, "validators", validators)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment that contains the security attribute definition.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        The description you assign to the security attribute.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The OCID of the security attribute definition.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isRetired")
    def is_retired(self) -> _builtins.bool:
        """
        Indicates whether the security attribute is retired. See [Managing Security Attribute Namespaces](https://docs.cloud.oracle.com/iaas/Content/zero-trust-packet-routing/managing-security-attribute-namespaces.htm).
        """
        return pulumi.get(self, "is_retired")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name assigned to the security attribute during creation. This is the security attribute key. The name must be unique within the security attribute namespace and cannot be changed.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="securityAttributeNamespaceId")
    def security_attribute_namespace_id(self) -> _builtins.str:
        """
        The OCID of the security attribute namespace.
        """
        return pulumi.get(self, "security_attribute_namespace_id")

    @_builtins.property
    @pulumi.getter(name="securityAttributeNamespaceName")
    def security_attribute_namespace_name(self) -> _builtins.str:
        """
        The name of the security attribute namespace that contains the security attribute.
        """
        return pulumi.get(self, "security_attribute_namespace_name")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        Date and time the security attribute was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter
    def type(self) -> _builtins.str:
        """
        The data type of the security attribute.
        """
        return pulumi.get(self, "type")

    @_builtins.property
    @pulumi.getter
    def validators(self) -> Sequence['outputs.GetSecurityAttributesSecurityAttributeValidatorResult']:
        """
        Validates a security attribute value. Each validator performs validation steps in addition to the standard validation for security attribute values. For more information, see [Limits on Security Attributes](https://docs.cloud.oracle.com/iaas/Content/zero-trust-packet-routing/overview.htm).
        """
        return pulumi.get(self, "validators")


@pulumi.output_type
class GetSecurityAttributesSecurityAttributeValidatorResult(dict):
    def __init__(__self__, *,
                 validator_type: _builtins.str,
                 values: Sequence[_builtins.str]):
        """
        :param _builtins.str validator_type: Specifies the type of validation: a static value (no validation) or a list.
        :param Sequence[_builtins.str] values: The list of allowed values for a security attribute value.
        """
        pulumi.set(__self__, "validator_type", validator_type)
        pulumi.set(__self__, "values", values)

    @_builtins.property
    @pulumi.getter(name="validatorType")
    def validator_type(self) -> _builtins.str:
        """
        Specifies the type of validation: a static value (no validation) or a list.
        """
        return pulumi.get(self, "validator_type")

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        """
        The list of allowed values for a security attribute value.
        """
        return pulumi.get(self, "values")


