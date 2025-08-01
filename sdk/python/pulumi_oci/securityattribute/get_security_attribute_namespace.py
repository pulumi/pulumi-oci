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
    'GetSecurityAttributeNamespaceResult',
    'AwaitableGetSecurityAttributeNamespaceResult',
    'get_security_attribute_namespace',
    'get_security_attribute_namespace_output',
]

@pulumi.output_type
class GetSecurityAttributeNamespaceResult:
    """
    A collection of values returned by getSecurityAttributeNamespace.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, description=None, freeform_tags=None, id=None, is_retired=None, modes=None, name=None, security_attribute_namespace_id=None, state=None, system_tags=None, time_created=None):
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
        if is_retired and not isinstance(is_retired, bool):
            raise TypeError("Expected argument 'is_retired' to be a bool")
        pulumi.set(__self__, "is_retired", is_retired)
        if modes and not isinstance(modes, list):
            raise TypeError("Expected argument 'modes' to be a list")
        pulumi.set(__self__, "modes", modes)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if security_attribute_namespace_id and not isinstance(security_attribute_namespace_id, str):
            raise TypeError("Expected argument 'security_attribute_namespace_id' to be a str")
        pulumi.set(__self__, "security_attribute_namespace_id", security_attribute_namespace_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment that contains the security attribute namespace.
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
        Description of the Security Attribute Namespace.
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
        Indicates possible modes the security attributes in this namespace is set to. Supported values are `enforce` and `audit`. Currently mode cannot be controlled by the user
        """
        return pulumi.get(self, "modes")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name of the security attribute namespace. It must be unique across all security attribute namespaces in the tenancy and cannot be changed.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="securityAttributeNamespaceId")
    def security_attribute_namespace_id(self) -> _builtins.str:
        return pulumi.get(self, "security_attribute_namespace_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The security attribute namespace's current state. After creating a security attribute namespace, `lifecycleState` is in ACTIVE state. After retiring a security attribute namespace, its `lifecycleState` becomes INACTIVE. Security Attributes from a retired namespace cannot be attached to more resources.
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


class AwaitableGetSecurityAttributeNamespaceResult(GetSecurityAttributeNamespaceResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSecurityAttributeNamespaceResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_retired=self.is_retired,
            modes=self.modes,
            name=self.name,
            security_attribute_namespace_id=self.security_attribute_namespace_id,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created)


def get_security_attribute_namespace(security_attribute_namespace_id: Optional[_builtins.str] = None,
                                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSecurityAttributeNamespaceResult:
    """
    This data source provides details about a specific Security Attribute Namespace resource in Oracle Cloud Infrastructure Security Attribute service.

    Gets the specified security attribute namespace's information.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_attribute_namespace = oci.SecurityAttribute.get_security_attribute_namespace(security_attribute_namespace_id=test_security_attribute_namespace_oci_security_attribute_security_attribute_namespace["id"])
    ```


    :param _builtins.str security_attribute_namespace_id: The OCID of the security attribute namespace.
    """
    __args__ = dict()
    __args__['securityAttributeNamespaceId'] = security_attribute_namespace_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:SecurityAttribute/getSecurityAttributeNamespace:getSecurityAttributeNamespace', __args__, opts=opts, typ=GetSecurityAttributeNamespaceResult).value

    return AwaitableGetSecurityAttributeNamespaceResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        is_retired=pulumi.get(__ret__, 'is_retired'),
        modes=pulumi.get(__ret__, 'modes'),
        name=pulumi.get(__ret__, 'name'),
        security_attribute_namespace_id=pulumi.get(__ret__, 'security_attribute_namespace_id'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'))
def get_security_attribute_namespace_output(security_attribute_namespace_id: Optional[pulumi.Input[_builtins.str]] = None,
                                            opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetSecurityAttributeNamespaceResult]:
    """
    This data source provides details about a specific Security Attribute Namespace resource in Oracle Cloud Infrastructure Security Attribute service.

    Gets the specified security attribute namespace's information.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_attribute_namespace = oci.SecurityAttribute.get_security_attribute_namespace(security_attribute_namespace_id=test_security_attribute_namespace_oci_security_attribute_security_attribute_namespace["id"])
    ```


    :param _builtins.str security_attribute_namespace_id: The OCID of the security attribute namespace.
    """
    __args__ = dict()
    __args__['securityAttributeNamespaceId'] = security_attribute_namespace_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:SecurityAttribute/getSecurityAttributeNamespace:getSecurityAttributeNamespace', __args__, opts=opts, typ=GetSecurityAttributeNamespaceResult)
    return __ret__.apply(lambda __response__: GetSecurityAttributeNamespaceResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        is_retired=pulumi.get(__response__, 'is_retired'),
        modes=pulumi.get(__response__, 'modes'),
        name=pulumi.get(__response__, 'name'),
        security_attribute_namespace_id=pulumi.get(__response__, 'security_attribute_namespace_id'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created')))
