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
    'GetNamespaceOccOverviewsResult',
    'AwaitableGetNamespaceOccOverviewsResult',
    'get_namespace_occ_overviews',
    'get_namespace_occ_overviews_output',
]

@pulumi.output_type
class GetNamespaceOccOverviewsResult:
    """
    A collection of values returned by getNamespaceOccOverviews.
    """
    def __init__(__self__, compartment_id=None, filters=None, from_=None, id=None, namespace=None, occ_overview_collections=None, to=None, workload_type=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if from_ and not isinstance(from_, str):
            raise TypeError("Expected argument 'from_' to be a str")
        pulumi.set(__self__, "from_", from_)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if namespace and not isinstance(namespace, str):
            raise TypeError("Expected argument 'namespace' to be a str")
        pulumi.set(__self__, "namespace", namespace)
        if occ_overview_collections and not isinstance(occ_overview_collections, list):
            raise TypeError("Expected argument 'occ_overview_collections' to be a list")
        pulumi.set(__self__, "occ_overview_collections", occ_overview_collections)
        if to and not isinstance(to, str):
            raise TypeError("Expected argument 'to' to be a str")
        pulumi.set(__self__, "to", to)
        if workload_type and not isinstance(workload_type, str):
            raise TypeError("Expected argument 'workload_type' to be a str")
        pulumi.set(__self__, "workload_type", workload_type)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment from which the api call is made. This will be used for authorizing the request.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetNamespaceOccOverviewsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter(name="from")
    def from_(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "from_")

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
    @pulumi.getter(name="occOverviewCollections")
    def occ_overview_collections(self) -> Sequence['outputs.GetNamespaceOccOverviewsOccOverviewCollectionResult']:
        """
        The list of occ_overview_collection.
        """
        return pulumi.get(self, "occ_overview_collections")

    @_builtins.property
    @pulumi.getter
    def to(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "to")

    @_builtins.property
    @pulumi.getter(name="workloadType")
    def workload_type(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "workload_type")


class AwaitableGetNamespaceOccOverviewsResult(GetNamespaceOccOverviewsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNamespaceOccOverviewsResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            from_=self.from_,
            id=self.id,
            namespace=self.namespace,
            occ_overview_collections=self.occ_overview_collections,
            to=self.to,
            workload_type=self.workload_type)


def get_namespace_occ_overviews(compartment_id: Optional[_builtins.str] = None,
                                filters: Optional[Sequence[Union['GetNamespaceOccOverviewsFilterArgs', 'GetNamespaceOccOverviewsFilterArgsDict']]] = None,
                                from_: Optional[_builtins.str] = None,
                                namespace: Optional[_builtins.str] = None,
                                to: Optional[_builtins.str] = None,
                                workload_type: Optional[_builtins.str] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNamespaceOccOverviewsResult:
    """
    This data source provides the list of Namespace Occ Overviews in Oracle Cloud Infrastructure Capacity Management service.

    Lists an overview of all resources in that namespace in a given time interval.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_namespace_occ_overviews = oci.CapacityManagement.get_namespace_occ_overviews(compartment_id=compartment_id,
        namespace=namespace_occ_overview_namespace,
        from_=namespace_occ_overview_from,
        to=namespace_occ_overview_to,
        workload_type=namespace_occ_overview_workload_type)
    ```


    :param _builtins.str compartment_id: The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
    :param _builtins.str from_: The month corresponding to this date would be considered as the starting point of the time period against which we would like to perform an aggregation.
    :param _builtins.str namespace: The namespace by which we would filter the list.
    :param _builtins.str to: The month corresponding to this date would be considered as the ending point of the time period against which we would like to perform an aggregation.
    :param _builtins.str workload_type: Workload type using the resources in an availability catalog can be filtered.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['from'] = from_
    __args__['namespace'] = namespace
    __args__['to'] = to
    __args__['workloadType'] = workload_type
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:CapacityManagement/getNamespaceOccOverviews:getNamespaceOccOverviews', __args__, opts=opts, typ=GetNamespaceOccOverviewsResult).value

    return AwaitableGetNamespaceOccOverviewsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        filters=pulumi.get(__ret__, 'filters'),
        from_=pulumi.get(__ret__, 'from_'),
        id=pulumi.get(__ret__, 'id'),
        namespace=pulumi.get(__ret__, 'namespace'),
        occ_overview_collections=pulumi.get(__ret__, 'occ_overview_collections'),
        to=pulumi.get(__ret__, 'to'),
        workload_type=pulumi.get(__ret__, 'workload_type'))
def get_namespace_occ_overviews_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                       filters: Optional[pulumi.Input[Optional[Sequence[Union['GetNamespaceOccOverviewsFilterArgs', 'GetNamespaceOccOverviewsFilterArgsDict']]]]] = None,
                                       from_: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                       namespace: Optional[pulumi.Input[_builtins.str]] = None,
                                       to: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                       workload_type: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                       opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetNamespaceOccOverviewsResult]:
    """
    This data source provides the list of Namespace Occ Overviews in Oracle Cloud Infrastructure Capacity Management service.

    Lists an overview of all resources in that namespace in a given time interval.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_namespace_occ_overviews = oci.CapacityManagement.get_namespace_occ_overviews(compartment_id=compartment_id,
        namespace=namespace_occ_overview_namespace,
        from_=namespace_occ_overview_from,
        to=namespace_occ_overview_to,
        workload_type=namespace_occ_overview_workload_type)
    ```


    :param _builtins.str compartment_id: The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
    :param _builtins.str from_: The month corresponding to this date would be considered as the starting point of the time period against which we would like to perform an aggregation.
    :param _builtins.str namespace: The namespace by which we would filter the list.
    :param _builtins.str to: The month corresponding to this date would be considered as the ending point of the time period against which we would like to perform an aggregation.
    :param _builtins.str workload_type: Workload type using the resources in an availability catalog can be filtered.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['from'] = from_
    __args__['namespace'] = namespace
    __args__['to'] = to
    __args__['workloadType'] = workload_type
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:CapacityManagement/getNamespaceOccOverviews:getNamespaceOccOverviews', __args__, opts=opts, typ=GetNamespaceOccOverviewsResult)
    return __ret__.apply(lambda __response__: GetNamespaceOccOverviewsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        filters=pulumi.get(__response__, 'filters'),
        from_=pulumi.get(__response__, 'from_'),
        id=pulumi.get(__response__, 'id'),
        namespace=pulumi.get(__response__, 'namespace'),
        occ_overview_collections=pulumi.get(__response__, 'occ_overview_collections'),
        to=pulumi.get(__response__, 'to'),
        workload_type=pulumi.get(__response__, 'workload_type')))
