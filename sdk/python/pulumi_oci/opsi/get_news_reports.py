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
    'GetNewsReportsResult',
    'AwaitableGetNewsReportsResult',
    'get_news_reports',
    'get_news_reports_output',
]

@pulumi.output_type
class GetNewsReportsResult:
    """
    A collection of values returned by getNewsReports.
    """
    def __init__(__self__, compartment_id=None, compartment_id_in_subtree=None, filters=None, id=None, news_report_collections=None, news_report_id=None, states=None, statuses=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compartment_id_in_subtree and not isinstance(compartment_id_in_subtree, bool):
            raise TypeError("Expected argument 'compartment_id_in_subtree' to be a bool")
        pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if news_report_collections and not isinstance(news_report_collections, list):
            raise TypeError("Expected argument 'news_report_collections' to be a list")
        pulumi.set(__self__, "news_report_collections", news_report_collections)
        if news_report_id and not isinstance(news_report_id, str):
            raise TypeError("Expected argument 'news_report_id' to be a str")
        pulumi.set(__self__, "news_report_id", news_report_id)
        if states and not isinstance(states, list):
            raise TypeError("Expected argument 'states' to be a list")
        pulumi.set(__self__, "states", states)
        if statuses and not isinstance(statuses, list):
            raise TypeError("Expected argument 'statuses' to be a list")
        pulumi.set(__self__, "statuses", statuses)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetNewsReportsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="newsReportCollections")
    def news_report_collections(self) -> Sequence['outputs.GetNewsReportsNewsReportCollectionResult']:
        """
        The list of news_report_collection.
        """
        return pulumi.get(self, "news_report_collections")

    @property
    @pulumi.getter(name="newsReportId")
    def news_report_id(self) -> Optional[str]:
        return pulumi.get(self, "news_report_id")

    @property
    @pulumi.getter
    def states(self) -> Optional[Sequence[str]]:
        """
        The current state of the news report.
        """
        return pulumi.get(self, "states")

    @property
    @pulumi.getter
    def statuses(self) -> Optional[Sequence[str]]:
        """
        Indicates the status of a news report in Operations Insights.
        """
        return pulumi.get(self, "statuses")


class AwaitableGetNewsReportsResult(GetNewsReportsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNewsReportsResult(
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            filters=self.filters,
            id=self.id,
            news_report_collections=self.news_report_collections,
            news_report_id=self.news_report_id,
            states=self.states,
            statuses=self.statuses)


def get_news_reports(compartment_id: Optional[str] = None,
                     compartment_id_in_subtree: Optional[bool] = None,
                     filters: Optional[Sequence[pulumi.InputType['GetNewsReportsFilterArgs']]] = None,
                     news_report_id: Optional[str] = None,
                     states: Optional[Sequence[str]] = None,
                     statuses: Optional[Sequence[str]] = None,
                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNewsReportsResult:
    """
    This data source provides the list of News Reports in Oracle Cloud Infrastructure Opsi service.

    Gets a list of news reports based on the query parameters specified. Either compartmentId or id query parameter must be specified.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_news_reports = oci.Opsi.get_news_reports(compartment_id=var["compartment_id"],
        compartment_id_in_subtree=var["news_report_compartment_id_in_subtree"],
        news_report_id=oci_opsi_news_report["test_news_report"]["id"],
        states=var["news_report_state"],
        statuses=var["news_report_status"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param bool compartment_id_in_subtree: A flag to search all resources within a given compartment and all sub-compartments.
    :param str news_report_id: Unique Operations Insights news report identifier
    :param Sequence[str] states: Lifecycle states
    :param Sequence[str] statuses: Resource Status
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['filters'] = filters
    __args__['newsReportId'] = news_report_id
    __args__['states'] = states
    __args__['statuses'] = statuses
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Opsi/getNewsReports:getNewsReports', __args__, opts=opts, typ=GetNewsReportsResult).value

    return AwaitableGetNewsReportsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compartment_id_in_subtree=pulumi.get(__ret__, 'compartment_id_in_subtree'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        news_report_collections=pulumi.get(__ret__, 'news_report_collections'),
        news_report_id=pulumi.get(__ret__, 'news_report_id'),
        states=pulumi.get(__ret__, 'states'),
        statuses=pulumi.get(__ret__, 'statuses'))


@_utilities.lift_output_func(get_news_reports)
def get_news_reports_output(compartment_id: Optional[pulumi.Input[Optional[str]]] = None,
                            compartment_id_in_subtree: Optional[pulumi.Input[Optional[bool]]] = None,
                            filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetNewsReportsFilterArgs']]]]] = None,
                            news_report_id: Optional[pulumi.Input[Optional[str]]] = None,
                            states: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                            statuses: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetNewsReportsResult]:
    """
    This data source provides the list of News Reports in Oracle Cloud Infrastructure Opsi service.

    Gets a list of news reports based on the query parameters specified. Either compartmentId or id query parameter must be specified.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_news_reports = oci.Opsi.get_news_reports(compartment_id=var["compartment_id"],
        compartment_id_in_subtree=var["news_report_compartment_id_in_subtree"],
        news_report_id=oci_opsi_news_report["test_news_report"]["id"],
        states=var["news_report_state"],
        statuses=var["news_report_status"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param bool compartment_id_in_subtree: A flag to search all resources within a given compartment and all sub-compartments.
    :param str news_report_id: Unique Operations Insights news report identifier
    :param Sequence[str] states: Lifecycle states
    :param Sequence[str] statuses: Resource Status
    """
    ...