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
from ._inputs import *

__all__ = [
    'GetContainersResult',
    'AwaitableGetContainersResult',
    'get_containers',
    'get_containers_output',
]

@pulumi.output_type
class GetContainersResult:
    """
    A collection of values returned by getContainers.
    """
    def __init__(__self__, container_name=None, containers=None, display_name=None, filters=None, id=None, is_latest=None, state=None, tag_query_param=None, target_workload=None, usage_query_param=None):
        if container_name and not isinstance(container_name, str):
            raise TypeError("Expected argument 'container_name' to be a str")
        pulumi.set(__self__, "container_name", container_name)
        if containers and not isinstance(containers, list):
            raise TypeError("Expected argument 'containers' to be a list")
        pulumi.set(__self__, "containers", containers)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_latest and not isinstance(is_latest, bool):
            raise TypeError("Expected argument 'is_latest' to be a bool")
        pulumi.set(__self__, "is_latest", is_latest)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if tag_query_param and not isinstance(tag_query_param, str):
            raise TypeError("Expected argument 'tag_query_param' to be a str")
        pulumi.set(__self__, "tag_query_param", tag_query_param)
        if target_workload and not isinstance(target_workload, str):
            raise TypeError("Expected argument 'target_workload' to be a str")
        pulumi.set(__self__, "target_workload", target_workload)
        if usage_query_param and not isinstance(usage_query_param, str):
            raise TypeError("Expected argument 'usage_query_param' to be a str")
        pulumi.set(__self__, "usage_query_param", usage_query_param)

    @_builtins.property
    @pulumi.getter(name="containerName")
    def container_name(self) -> Optional[_builtins.str]:
        """
        The name of the container. This can be same for different tags
        """
        return pulumi.get(self, "container_name")

    @_builtins.property
    @pulumi.getter
    def containers(self) -> Sequence['outputs.GetContainersContainerResult']:
        """
        The list of containers.
        """
        return pulumi.get(self, "containers")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        The display name of the container.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetContainersFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isLatest")
    def is_latest(self) -> Optional[_builtins.bool]:
        """
        The latest tag of the container.
        """
        return pulumi.get(self, "is_latest")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        Container Version LifecycleState.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="tagQueryParam")
    def tag_query_param(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "tag_query_param")

    @_builtins.property
    @pulumi.getter(name="targetWorkload")
    def target_workload(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "target_workload")

    @_builtins.property
    @pulumi.getter(name="usageQueryParam")
    def usage_query_param(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "usage_query_param")


class AwaitableGetContainersResult(GetContainersResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetContainersResult(
            container_name=self.container_name,
            containers=self.containers,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            is_latest=self.is_latest,
            state=self.state,
            tag_query_param=self.tag_query_param,
            target_workload=self.target_workload,
            usage_query_param=self.usage_query_param)


def get_containers(container_name: Optional[_builtins.str] = None,
                   display_name: Optional[_builtins.str] = None,
                   filters: Optional[Sequence[Union['GetContainersFilterArgs', 'GetContainersFilterArgsDict']]] = None,
                   is_latest: Optional[_builtins.bool] = None,
                   state: Optional[_builtins.str] = None,
                   tag_query_param: Optional[_builtins.str] = None,
                   target_workload: Optional[_builtins.str] = None,
                   usage_query_param: Optional[_builtins.str] = None,
                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetContainersResult:
    """
    This data source provides the list of Containers in Oracle Cloud Infrastructure Data Science service.

    List containers.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_containers = oci.DataScience.get_containers(container_name=test_container["name"],
        display_name=container_display_name,
        is_latest=container_is_latest,
        state=container_state,
        tag_query_param=container_tag_query_param,
        target_workload=container_target_workload,
        usage_query_param=container_usage_query_param)
    ```


    :param _builtins.str container_name: <b>Filter</b> results by the container name.
    :param _builtins.str display_name: <b>Filter</b> results by its user-friendly name.
    :param _builtins.bool is_latest: if true, this returns latest version of container.
    :param _builtins.str state: <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
    :param _builtins.str tag_query_param: <b>Filter</b> results by the container version tag.
    :param _builtins.str target_workload: <b>Filter</b> results by the target workload.
    :param _builtins.str usage_query_param: <b>Filter</b> results by the usage.
    """
    __args__ = dict()
    __args__['containerName'] = container_name
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['isLatest'] = is_latest
    __args__['state'] = state
    __args__['tagQueryParam'] = tag_query_param
    __args__['targetWorkload'] = target_workload
    __args__['usageQueryParam'] = usage_query_param
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataScience/getContainers:getContainers', __args__, opts=opts, typ=GetContainersResult).value

    return AwaitableGetContainersResult(
        container_name=pulumi.get(__ret__, 'container_name'),
        containers=pulumi.get(__ret__, 'containers'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        is_latest=pulumi.get(__ret__, 'is_latest'),
        state=pulumi.get(__ret__, 'state'),
        tag_query_param=pulumi.get(__ret__, 'tag_query_param'),
        target_workload=pulumi.get(__ret__, 'target_workload'),
        usage_query_param=pulumi.get(__ret__, 'usage_query_param'))
def get_containers_output(container_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                          display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                          filters: Optional[pulumi.Input[Optional[Sequence[Union['GetContainersFilterArgs', 'GetContainersFilterArgsDict']]]]] = None,
                          is_latest: Optional[pulumi.Input[Optional[_builtins.bool]]] = None,
                          state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                          tag_query_param: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                          target_workload: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                          usage_query_param: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                          opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetContainersResult]:
    """
    This data source provides the list of Containers in Oracle Cloud Infrastructure Data Science service.

    List containers.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_containers = oci.DataScience.get_containers(container_name=test_container["name"],
        display_name=container_display_name,
        is_latest=container_is_latest,
        state=container_state,
        tag_query_param=container_tag_query_param,
        target_workload=container_target_workload,
        usage_query_param=container_usage_query_param)
    ```


    :param _builtins.str container_name: <b>Filter</b> results by the container name.
    :param _builtins.str display_name: <b>Filter</b> results by its user-friendly name.
    :param _builtins.bool is_latest: if true, this returns latest version of container.
    :param _builtins.str state: <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
    :param _builtins.str tag_query_param: <b>Filter</b> results by the container version tag.
    :param _builtins.str target_workload: <b>Filter</b> results by the target workload.
    :param _builtins.str usage_query_param: <b>Filter</b> results by the usage.
    """
    __args__ = dict()
    __args__['containerName'] = container_name
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['isLatest'] = is_latest
    __args__['state'] = state
    __args__['tagQueryParam'] = tag_query_param
    __args__['targetWorkload'] = target_workload
    __args__['usageQueryParam'] = usage_query_param
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataScience/getContainers:getContainers', __args__, opts=opts, typ=GetContainersResult)
    return __ret__.apply(lambda __response__: GetContainersResult(
        container_name=pulumi.get(__response__, 'container_name'),
        containers=pulumi.get(__response__, 'containers'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        is_latest=pulumi.get(__response__, 'is_latest'),
        state=pulumi.get(__response__, 'state'),
        tag_query_param=pulumi.get(__response__, 'tag_query_param'),
        target_workload=pulumi.get(__response__, 'target_workload'),
        usage_query_param=pulumi.get(__response__, 'usage_query_param')))
