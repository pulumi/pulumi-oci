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
from ._inputs import *

__all__ = [
    'GetQueryQuickPicksResult',
    'AwaitableGetQueryQuickPicksResult',
    'get_query_quick_picks',
    'get_query_quick_picks_output',
]

@pulumi.output_type
class GetQueryQuickPicksResult:
    """
    A collection of values returned by getQueryQuickPicks.
    """
    def __init__(__self__, apm_domain_id=None, filters=None, id=None, quick_picks=None):
        if apm_domain_id and not isinstance(apm_domain_id, str):
            raise TypeError("Expected argument 'apm_domain_id' to be a str")
        pulumi.set(__self__, "apm_domain_id", apm_domain_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if quick_picks and not isinstance(quick_picks, list):
            raise TypeError("Expected argument 'quick_picks' to be a list")
        pulumi.set(__self__, "quick_picks", quick_picks)

    @property
    @pulumi.getter(name="apmDomainId")
    def apm_domain_id(self) -> str:
        return pulumi.get(self, "apm_domain_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetQueryQuickPicksFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="quickPicks")
    def quick_picks(self) -> Sequence['outputs.GetQueryQuickPicksQuickPickResult']:
        """
        The list of quick_picks.
        """
        return pulumi.get(self, "quick_picks")


class AwaitableGetQueryQuickPicksResult(GetQueryQuickPicksResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetQueryQuickPicksResult(
            apm_domain_id=self.apm_domain_id,
            filters=self.filters,
            id=self.id,
            quick_picks=self.quick_picks)


def get_query_quick_picks(apm_domain_id: Optional[str] = None,
                          filters: Optional[Sequence[pulumi.InputType['GetQueryQuickPicksFilterArgs']]] = None,
                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetQueryQuickPicksResult:
    """
    This data source provides the list of Query Quick Picks in Oracle Cloud Infrastructure Apm Traces service.

    Returns a list of predefined Quick Pick queries intended to assist the user
    to choose a query to run.  There is no sorting applied on the results.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_query_quick_picks = oci.ApmTraces.get_query_quick_picks(apm_domain_id=oci_apm_apm_domain["test_apm_domain"]["id"])
    ```


    :param str apm_domain_id: The APM Domain ID the request is intended for.
    """
    __args__ = dict()
    __args__['apmDomainId'] = apm_domain_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ApmTraces/getQueryQuickPicks:getQueryQuickPicks', __args__, opts=opts, typ=GetQueryQuickPicksResult).value

    return AwaitableGetQueryQuickPicksResult(
        apm_domain_id=__ret__.apm_domain_id,
        filters=__ret__.filters,
        id=__ret__.id,
        quick_picks=__ret__.quick_picks)


@_utilities.lift_output_func(get_query_quick_picks)
def get_query_quick_picks_output(apm_domain_id: Optional[pulumi.Input[str]] = None,
                                 filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetQueryQuickPicksFilterArgs']]]]] = None,
                                 opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetQueryQuickPicksResult]:
    """
    This data source provides the list of Query Quick Picks in Oracle Cloud Infrastructure Apm Traces service.

    Returns a list of predefined Quick Pick queries intended to assist the user
    to choose a query to run.  There is no sorting applied on the results.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_query_quick_picks = oci.ApmTraces.get_query_quick_picks(apm_domain_id=oci_apm_apm_domain["test_apm_domain"]["id"])
    ```


    :param str apm_domain_id: The APM Domain ID the request is intended for.
    """
    ...