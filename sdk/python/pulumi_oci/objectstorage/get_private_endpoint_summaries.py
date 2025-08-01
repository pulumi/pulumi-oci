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
    'GetPrivateEndpointSummariesResult',
    'AwaitableGetPrivateEndpointSummariesResult',
    'get_private_endpoint_summaries',
    'get_private_endpoint_summaries_output',
]

@pulumi.output_type
class GetPrivateEndpointSummariesResult:
    """
    A collection of values returned by getPrivateEndpointSummaries.
    """
    def __init__(__self__, compartment_id=None, filters=None, id=None, namespace=None, private_endpoint_summaries=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if namespace and not isinstance(namespace, str):
            raise TypeError("Expected argument 'namespace' to be a str")
        pulumi.set(__self__, "namespace", namespace)
        if private_endpoint_summaries and not isinstance(private_endpoint_summaries, list):
            raise TypeError("Expected argument 'private_endpoint_summaries' to be a list")
        pulumi.set(__self__, "private_endpoint_summaries", private_endpoint_summaries)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetPrivateEndpointSummariesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def namespace(self) -> _builtins.str:
        return pulumi.get(self, "namespace")

    @_builtins.property
    @pulumi.getter(name="privateEndpointSummaries")
    def private_endpoint_summaries(self) -> Sequence['outputs.GetPrivateEndpointSummariesPrivateEndpointSummaryResult']:
        return pulumi.get(self, "private_endpoint_summaries")


class AwaitableGetPrivateEndpointSummariesResult(GetPrivateEndpointSummariesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetPrivateEndpointSummariesResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            namespace=self.namespace,
            private_endpoint_summaries=self.private_endpoint_summaries)


def get_private_endpoint_summaries(compartment_id: Optional[_builtins.str] = None,
                                   filters: Optional[Sequence[Union['GetPrivateEndpointSummariesFilterArgs', 'GetPrivateEndpointSummariesFilterArgsDict']]] = None,
                                   namespace: Optional[_builtins.str] = None,
                                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetPrivateEndpointSummariesResult:
    """
    Use this data source to access information about an existing resource.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['namespace'] = namespace
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ObjectStorage/getPrivateEndpointSummaries:getPrivateEndpointSummaries', __args__, opts=opts, typ=GetPrivateEndpointSummariesResult).value

    return AwaitableGetPrivateEndpointSummariesResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        namespace=pulumi.get(__ret__, 'namespace'),
        private_endpoint_summaries=pulumi.get(__ret__, 'private_endpoint_summaries'))
def get_private_endpoint_summaries_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                          filters: Optional[pulumi.Input[Optional[Sequence[Union['GetPrivateEndpointSummariesFilterArgs', 'GetPrivateEndpointSummariesFilterArgsDict']]]]] = None,
                                          namespace: Optional[pulumi.Input[_builtins.str]] = None,
                                          opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetPrivateEndpointSummariesResult]:
    """
    Use this data source to access information about an existing resource.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['namespace'] = namespace
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:ObjectStorage/getPrivateEndpointSummaries:getPrivateEndpointSummaries', __args__, opts=opts, typ=GetPrivateEndpointSummariesResult)
    return __ret__.apply(lambda __response__: GetPrivateEndpointSummariesResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        namespace=pulumi.get(__response__, 'namespace'),
        private_endpoint_summaries=pulumi.get(__response__, 'private_endpoint_summaries')))
