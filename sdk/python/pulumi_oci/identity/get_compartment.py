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
    'GetCompartmentResult',
    'AwaitableGetCompartmentResult',
    'get_compartment',
    'get_compartment_output',
]

@pulumi.output_type
class GetCompartmentResult:
    """
    A collection of values returned by getCompartment.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, description=None, freeform_tags=None, id=None, inactive_state=None, is_accessible=None, name=None, state=None, time_created=None):
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
        if inactive_state and not isinstance(inactive_state, str):
            raise TypeError("Expected argument 'inactive_state' to be a str")
        pulumi.set(__self__, "inactive_state", inactive_state)
        if is_accessible and not isinstance(is_accessible, bool):
            raise TypeError("Expected argument 'is_accessible' to be a bool")
        pulumi.set(__self__, "is_accessible", is_accessible)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the parent compartment containing the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        The description you assign to the compartment. Does not have to be unique, and it's changeable.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The OCID of the compartment.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="inactiveState")
    def inactive_state(self) -> _builtins.str:
        """
        The detailed status of INACTIVE lifecycleState.
        """
        return pulumi.get(self, "inactive_state")

    @_builtins.property
    @pulumi.getter(name="isAccessible")
    def is_accessible(self) -> _builtins.bool:
        """
        Indicates whether or not the compartment is accessible for the user making the request. Returns true when the user has INSPECT permissions directly on a resource in the compartment or indirectly (permissions can be on a resource in a subcompartment).
        """
        return pulumi.get(self, "is_accessible")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name you assign to the compartment during creation. The name must be unique across all compartments in the parent. Avoid entering confidential information.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The compartment's current state.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        Date and time the compartment was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")


class AwaitableGetCompartmentResult(GetCompartmentResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetCompartmentResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            freeform_tags=self.freeform_tags,
            id=self.id,
            inactive_state=self.inactive_state,
            is_accessible=self.is_accessible,
            name=self.name,
            state=self.state,
            time_created=self.time_created)


def get_compartment(id: Optional[_builtins.str] = None,
                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetCompartmentResult:
    """
    This data source provides details about a specific Compartment resource in Oracle Cloud Infrastructure Identity service.

    Gets the specified compartment's information.

    This operation does not return a list of all the resources inside the compartment. There is no single
    API operation that does that. Compartments can contain multiple types of resources (instances, block
    storage volumes, etc.). To find out what's in a compartment, you must call the "List" operation for
    each resource type and specify the compartment's OCID as a query parameter in the request. For example,
    call the [ListInstances](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/Instance/ListInstances) operation in the Cloud Compute
    Service or the [ListVolumes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/Volume/ListVolumes) operation in Cloud Block Storage.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compartment = oci.Identity.get_compartment(id=compartment_id)
    ```


    :param _builtins.str id: The OCID of the compartment.
    """
    __args__ = dict()
    __args__['id'] = id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Identity/getCompartment:getCompartment', __args__, opts=opts, typ=GetCompartmentResult).value

    return AwaitableGetCompartmentResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        inactive_state=pulumi.get(__ret__, 'inactive_state'),
        is_accessible=pulumi.get(__ret__, 'is_accessible'),
        name=pulumi.get(__ret__, 'name'),
        state=pulumi.get(__ret__, 'state'),
        time_created=pulumi.get(__ret__, 'time_created'))
def get_compartment_output(id: Optional[pulumi.Input[_builtins.str]] = None,
                           opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetCompartmentResult]:
    """
    This data source provides details about a specific Compartment resource in Oracle Cloud Infrastructure Identity service.

    Gets the specified compartment's information.

    This operation does not return a list of all the resources inside the compartment. There is no single
    API operation that does that. Compartments can contain multiple types of resources (instances, block
    storage volumes, etc.). To find out what's in a compartment, you must call the "List" operation for
    each resource type and specify the compartment's OCID as a query parameter in the request. For example,
    call the [ListInstances](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/Instance/ListInstances) operation in the Cloud Compute
    Service or the [ListVolumes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/Volume/ListVolumes) operation in Cloud Block Storage.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compartment = oci.Identity.get_compartment(id=compartment_id)
    ```


    :param _builtins.str id: The OCID of the compartment.
    """
    __args__ = dict()
    __args__['id'] = id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Identity/getCompartment:getCompartment', __args__, opts=opts, typ=GetCompartmentResult)
    return __ret__.apply(lambda __response__: GetCompartmentResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        inactive_state=pulumi.get(__response__, 'inactive_state'),
        is_accessible=pulumi.get(__response__, 'is_accessible'),
        name=pulumi.get(__response__, 'name'),
        state=pulumi.get(__response__, 'state'),
        time_created=pulumi.get(__response__, 'time_created')))
