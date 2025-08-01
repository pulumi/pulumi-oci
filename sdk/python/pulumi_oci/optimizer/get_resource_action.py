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
    'GetResourceActionResult',
    'AwaitableGetResourceActionResult',
    'get_resource_action',
    'get_resource_action_output',
]

@pulumi.output_type
class GetResourceActionResult:
    """
    A collection of values returned by getResourceAction.
    """
    def __init__(__self__, actions=None, category_id=None, compartment_id=None, compartment_name=None, estimated_cost_saving=None, extended_metadata=None, id=None, include_resource_metadata=None, metadata=None, name=None, recommendation_id=None, resource_action_id=None, resource_id=None, resource_type=None, state=None, status=None, time_created=None, time_status_begin=None, time_status_end=None, time_updated=None):
        if actions and not isinstance(actions, list):
            raise TypeError("Expected argument 'actions' to be a list")
        pulumi.set(__self__, "actions", actions)
        if category_id and not isinstance(category_id, str):
            raise TypeError("Expected argument 'category_id' to be a str")
        pulumi.set(__self__, "category_id", category_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compartment_name and not isinstance(compartment_name, str):
            raise TypeError("Expected argument 'compartment_name' to be a str")
        pulumi.set(__self__, "compartment_name", compartment_name)
        if estimated_cost_saving and not isinstance(estimated_cost_saving, float):
            raise TypeError("Expected argument 'estimated_cost_saving' to be a float")
        pulumi.set(__self__, "estimated_cost_saving", estimated_cost_saving)
        if extended_metadata and not isinstance(extended_metadata, dict):
            raise TypeError("Expected argument 'extended_metadata' to be a dict")
        pulumi.set(__self__, "extended_metadata", extended_metadata)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if include_resource_metadata and not isinstance(include_resource_metadata, bool):
            raise TypeError("Expected argument 'include_resource_metadata' to be a bool")
        pulumi.set(__self__, "include_resource_metadata", include_resource_metadata)
        if metadata and not isinstance(metadata, dict):
            raise TypeError("Expected argument 'metadata' to be a dict")
        pulumi.set(__self__, "metadata", metadata)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if recommendation_id and not isinstance(recommendation_id, str):
            raise TypeError("Expected argument 'recommendation_id' to be a str")
        pulumi.set(__self__, "recommendation_id", recommendation_id)
        if resource_action_id and not isinstance(resource_action_id, str):
            raise TypeError("Expected argument 'resource_action_id' to be a str")
        pulumi.set(__self__, "resource_action_id", resource_action_id)
        if resource_id and not isinstance(resource_id, str):
            raise TypeError("Expected argument 'resource_id' to be a str")
        pulumi.set(__self__, "resource_id", resource_id)
        if resource_type and not isinstance(resource_type, str):
            raise TypeError("Expected argument 'resource_type' to be a str")
        pulumi.set(__self__, "resource_type", resource_type)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if status and not isinstance(status, str):
            raise TypeError("Expected argument 'status' to be a str")
        pulumi.set(__self__, "status", status)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_status_begin and not isinstance(time_status_begin, str):
            raise TypeError("Expected argument 'time_status_begin' to be a str")
        pulumi.set(__self__, "time_status_begin", time_status_begin)
        if time_status_end and not isinstance(time_status_end, str):
            raise TypeError("Expected argument 'time_status_end' to be a str")
        pulumi.set(__self__, "time_status_end", time_status_end)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter
    def actions(self) -> Sequence['outputs.GetResourceActionActionResult']:
        """
        Details about the recommended action.
        """
        return pulumi.get(self, "actions")

    @_builtins.property
    @pulumi.getter(name="categoryId")
    def category_id(self) -> _builtins.str:
        """
        The unique OCID associated with the category.
        """
        return pulumi.get(self, "category_id")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="compartmentName")
    def compartment_name(self) -> _builtins.str:
        """
        The name associated with the compartment.
        """
        return pulumi.get(self, "compartment_name")

    @_builtins.property
    @pulumi.getter(name="estimatedCostSaving")
    def estimated_cost_saving(self) -> _builtins.float:
        """
        The estimated cost savings, in dollars, for the resource action.
        """
        return pulumi.get(self, "estimated_cost_saving")

    @_builtins.property
    @pulumi.getter(name="extendedMetadata")
    def extended_metadata(self) -> Mapping[str, _builtins.str]:
        """
        Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
        """
        return pulumi.get(self, "extended_metadata")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The unique OCID associated with the resource action.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="includeResourceMetadata")
    def include_resource_metadata(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "include_resource_metadata")

    @_builtins.property
    @pulumi.getter
    def metadata(self) -> Mapping[str, _builtins.str]:
        """
        Custom metadata key/value pairs for the resource action.
        """
        return pulumi.get(self, "metadata")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name assigned to the resource.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="recommendationId")
    def recommendation_id(self) -> _builtins.str:
        """
        The unique OCID associated with the recommendation.
        """
        return pulumi.get(self, "recommendation_id")

    @_builtins.property
    @pulumi.getter(name="resourceActionId")
    def resource_action_id(self) -> _builtins.str:
        return pulumi.get(self, "resource_action_id")

    @_builtins.property
    @pulumi.getter(name="resourceId")
    def resource_id(self) -> _builtins.str:
        """
        The unique OCID associated with the resource.
        """
        return pulumi.get(self, "resource_id")

    @_builtins.property
    @pulumi.getter(name="resourceType")
    def resource_type(self) -> _builtins.str:
        """
        The kind of resource.
        """
        return pulumi.get(self, "resource_type")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The resource action's current state.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter
    def status(self) -> _builtins.str:
        """
        The current status of the resource action.
        """
        return pulumi.get(self, "status")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the resource action details were created, in the format defined by RFC3339.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeStatusBegin")
    def time_status_begin(self) -> _builtins.str:
        """
        The date and time that the resource action entered its current status. The format is defined by RFC3339.
        """
        return pulumi.get(self, "time_status_begin")

    @_builtins.property
    @pulumi.getter(name="timeStatusEnd")
    def time_status_end(self) -> _builtins.str:
        """
        The date and time the current status will change. The format is defined by RFC3339.
        """
        return pulumi.get(self, "time_status_end")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The date and time the resource action details were last updated, in the format defined by RFC3339.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetResourceActionResult(GetResourceActionResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetResourceActionResult(
            actions=self.actions,
            category_id=self.category_id,
            compartment_id=self.compartment_id,
            compartment_name=self.compartment_name,
            estimated_cost_saving=self.estimated_cost_saving,
            extended_metadata=self.extended_metadata,
            id=self.id,
            include_resource_metadata=self.include_resource_metadata,
            metadata=self.metadata,
            name=self.name,
            recommendation_id=self.recommendation_id,
            resource_action_id=self.resource_action_id,
            resource_id=self.resource_id,
            resource_type=self.resource_type,
            state=self.state,
            status=self.status,
            time_created=self.time_created,
            time_status_begin=self.time_status_begin,
            time_status_end=self.time_status_end,
            time_updated=self.time_updated)


def get_resource_action(include_resource_metadata: Optional[_builtins.bool] = None,
                        resource_action_id: Optional[_builtins.str] = None,
                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetResourceActionResult:
    """
    This data source provides details about a specific Resource Action resource in Oracle Cloud Infrastructure Optimizer service.

    Gets the resource action that corresponds to the specified OCID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_resource_action = oci.Optimizer.get_resource_action(resource_action_id=test_resource_action_oci_optimizer_resource_action["id"],
        include_resource_metadata=resource_action_include_resource_metadata)
    ```


    :param _builtins.bool include_resource_metadata: Supplement additional resource information in extended metadata response.
    :param _builtins.str resource_action_id: The unique OCID associated with the resource action.
    """
    __args__ = dict()
    __args__['includeResourceMetadata'] = include_resource_metadata
    __args__['resourceActionId'] = resource_action_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Optimizer/getResourceAction:getResourceAction', __args__, opts=opts, typ=GetResourceActionResult).value

    return AwaitableGetResourceActionResult(
        actions=pulumi.get(__ret__, 'actions'),
        category_id=pulumi.get(__ret__, 'category_id'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compartment_name=pulumi.get(__ret__, 'compartment_name'),
        estimated_cost_saving=pulumi.get(__ret__, 'estimated_cost_saving'),
        extended_metadata=pulumi.get(__ret__, 'extended_metadata'),
        id=pulumi.get(__ret__, 'id'),
        include_resource_metadata=pulumi.get(__ret__, 'include_resource_metadata'),
        metadata=pulumi.get(__ret__, 'metadata'),
        name=pulumi.get(__ret__, 'name'),
        recommendation_id=pulumi.get(__ret__, 'recommendation_id'),
        resource_action_id=pulumi.get(__ret__, 'resource_action_id'),
        resource_id=pulumi.get(__ret__, 'resource_id'),
        resource_type=pulumi.get(__ret__, 'resource_type'),
        state=pulumi.get(__ret__, 'state'),
        status=pulumi.get(__ret__, 'status'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_status_begin=pulumi.get(__ret__, 'time_status_begin'),
        time_status_end=pulumi.get(__ret__, 'time_status_end'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_resource_action_output(include_resource_metadata: Optional[pulumi.Input[Optional[_builtins.bool]]] = None,
                               resource_action_id: Optional[pulumi.Input[_builtins.str]] = None,
                               opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetResourceActionResult]:
    """
    This data source provides details about a specific Resource Action resource in Oracle Cloud Infrastructure Optimizer service.

    Gets the resource action that corresponds to the specified OCID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_resource_action = oci.Optimizer.get_resource_action(resource_action_id=test_resource_action_oci_optimizer_resource_action["id"],
        include_resource_metadata=resource_action_include_resource_metadata)
    ```


    :param _builtins.bool include_resource_metadata: Supplement additional resource information in extended metadata response.
    :param _builtins.str resource_action_id: The unique OCID associated with the resource action.
    """
    __args__ = dict()
    __args__['includeResourceMetadata'] = include_resource_metadata
    __args__['resourceActionId'] = resource_action_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Optimizer/getResourceAction:getResourceAction', __args__, opts=opts, typ=GetResourceActionResult)
    return __ret__.apply(lambda __response__: GetResourceActionResult(
        actions=pulumi.get(__response__, 'actions'),
        category_id=pulumi.get(__response__, 'category_id'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        compartment_name=pulumi.get(__response__, 'compartment_name'),
        estimated_cost_saving=pulumi.get(__response__, 'estimated_cost_saving'),
        extended_metadata=pulumi.get(__response__, 'extended_metadata'),
        id=pulumi.get(__response__, 'id'),
        include_resource_metadata=pulumi.get(__response__, 'include_resource_metadata'),
        metadata=pulumi.get(__response__, 'metadata'),
        name=pulumi.get(__response__, 'name'),
        recommendation_id=pulumi.get(__response__, 'recommendation_id'),
        resource_action_id=pulumi.get(__response__, 'resource_action_id'),
        resource_id=pulumi.get(__response__, 'resource_id'),
        resource_type=pulumi.get(__response__, 'resource_type'),
        state=pulumi.get(__response__, 'state'),
        status=pulumi.get(__response__, 'status'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_status_begin=pulumi.get(__response__, 'time_status_begin'),
        time_status_end=pulumi.get(__response__, 'time_status_end'),
        time_updated=pulumi.get(__response__, 'time_updated')))
