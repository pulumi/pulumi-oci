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
    'GetActionResult',
    'AwaitableGetActionResult',
    'get_action',
    'get_action_output',
]

@pulumi.output_type
class GetActionResult:
    """
    A collection of values returned by getAction.
    """
    def __init__(__self__, component=None, customer_display_name=None, description=None, id=None, name=None, operator_action_id=None, properties=None, resource_type=None):
        if component and not isinstance(component, str):
            raise TypeError("Expected argument 'component' to be a str")
        pulumi.set(__self__, "component", component)
        if customer_display_name and not isinstance(customer_display_name, str):
            raise TypeError("Expected argument 'customer_display_name' to be a str")
        pulumi.set(__self__, "customer_display_name", customer_display_name)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if operator_action_id and not isinstance(operator_action_id, str):
            raise TypeError("Expected argument 'operator_action_id' to be a str")
        pulumi.set(__self__, "operator_action_id", operator_action_id)
        if properties and not isinstance(properties, list):
            raise TypeError("Expected argument 'properties' to be a list")
        pulumi.set(__self__, "properties", properties)
        if resource_type and not isinstance(resource_type, str):
            raise TypeError("Expected argument 'resource_type' to be a str")
        pulumi.set(__self__, "resource_type", resource_type)

    @property
    @pulumi.getter
    def component(self) -> str:
        """
        Name of the infrastructure layer associated with the operator action.
        """
        return pulumi.get(self, "component")

    @property
    @pulumi.getter(name="customerDisplayName")
    def customer_display_name(self) -> str:
        """
        Display Name of the operator action.
        """
        return pulumi.get(self, "customer_display_name")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Description of the operator action in terms of associated risk profile, and characteristics of the operating system commands made available to the operator under this operator action.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Name of the property
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="operatorActionId")
    def operator_action_id(self) -> str:
        return pulumi.get(self, "operator_action_id")

    @property
    @pulumi.getter
    def properties(self) -> Sequence['outputs.GetActionPropertyResult']:
        """
        Fine grained properties associated with the operator control.
        """
        return pulumi.get(self, "properties")

    @property
    @pulumi.getter(name="resourceType")
    def resource_type(self) -> str:
        """
        resourceType for which the OperatorAction is applicable
        """
        return pulumi.get(self, "resource_type")


class AwaitableGetActionResult(GetActionResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetActionResult(
            component=self.component,
            customer_display_name=self.customer_display_name,
            description=self.description,
            id=self.id,
            name=self.name,
            operator_action_id=self.operator_action_id,
            properties=self.properties,
            resource_type=self.resource_type)


def get_action(operator_action_id: Optional[str] = None,
               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetActionResult:
    """
    This data source provides details about a specific Operator Action resource in Oracle Cloud Infrastructure Operator Access Control service.

    Gets the operator action associated with the specified operator action ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_operator_action = oci.OperatorAccessControl.get_action(operator_action_id=oci_operator_access_control_operator_action["test_operator_action"]["id"])
    ```


    :param str operator_action_id: Unique Oracle supplied identifier associated with the operator action.
    """
    __args__ = dict()
    __args__['operatorActionId'] = operator_action_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:OperatorAccessControl/getAction:getAction', __args__, opts=opts, typ=GetActionResult).value

    return AwaitableGetActionResult(
        component=__ret__.component,
        customer_display_name=__ret__.customer_display_name,
        description=__ret__.description,
        id=__ret__.id,
        name=__ret__.name,
        operator_action_id=__ret__.operator_action_id,
        properties=__ret__.properties,
        resource_type=__ret__.resource_type)


@_utilities.lift_output_func(get_action)
def get_action_output(operator_action_id: Optional[pulumi.Input[str]] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetActionResult]:
    """
    This data source provides details about a specific Operator Action resource in Oracle Cloud Infrastructure Operator Access Control service.

    Gets the operator action associated with the specified operator action ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_operator_action = oci.OperatorAccessControl.get_action(operator_action_id=oci_operator_access_control_operator_action["test_operator_action"]["id"])
    ```


    :param str operator_action_id: Unique Oracle supplied identifier associated with the operator action.
    """
    ...