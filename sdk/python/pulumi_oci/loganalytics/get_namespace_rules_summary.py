# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetNamespaceRulesSummaryResult',
    'AwaitableGetNamespaceRulesSummaryResult',
    'get_namespace_rules_summary',
    'get_namespace_rules_summary_output',
]

@pulumi.output_type
class GetNamespaceRulesSummaryResult:
    """
    A collection of values returned by getNamespaceRulesSummary.
    """
    def __init__(__self__, compartment_id=None, id=None, ingest_time_rules_count=None, namespace=None, saved_search_rules_count=None, total_count=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if ingest_time_rules_count and not isinstance(ingest_time_rules_count, int):
            raise TypeError("Expected argument 'ingest_time_rules_count' to be a int")
        pulumi.set(__self__, "ingest_time_rules_count", ingest_time_rules_count)
        if namespace and not isinstance(namespace, str):
            raise TypeError("Expected argument 'namespace' to be a str")
        pulumi.set(__self__, "namespace", namespace)
        if saved_search_rules_count and not isinstance(saved_search_rules_count, int):
            raise TypeError("Expected argument 'saved_search_rules_count' to be a int")
        pulumi.set(__self__, "saved_search_rules_count", saved_search_rules_count)
        if total_count and not isinstance(total_count, int):
            raise TypeError("Expected argument 'total_count' to be a int")
        pulumi.set(__self__, "total_count", total_count)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="ingestTimeRulesCount")
    def ingest_time_rules_count(self) -> int:
        """
        The count of ingest time rules.
        """
        return pulumi.get(self, "ingest_time_rules_count")

    @property
    @pulumi.getter
    def namespace(self) -> str:
        return pulumi.get(self, "namespace")

    @property
    @pulumi.getter(name="savedSearchRulesCount")
    def saved_search_rules_count(self) -> int:
        """
        The count of saved search rules.
        """
        return pulumi.get(self, "saved_search_rules_count")

    @property
    @pulumi.getter(name="totalCount")
    def total_count(self) -> int:
        """
        The total count of detection rules.
        """
        return pulumi.get(self, "total_count")


class AwaitableGetNamespaceRulesSummaryResult(GetNamespaceRulesSummaryResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNamespaceRulesSummaryResult(
            compartment_id=self.compartment_id,
            id=self.id,
            ingest_time_rules_count=self.ingest_time_rules_count,
            namespace=self.namespace,
            saved_search_rules_count=self.saved_search_rules_count,
            total_count=self.total_count)


def get_namespace_rules_summary(compartment_id: Optional[str] = None,
                                namespace: Optional[str] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNamespaceRulesSummaryResult:
    """
    This data source provides details about a specific Namespace Rules Summary resource in Oracle Cloud Infrastructure Log Analytics service.

    Returns the count of detection rules in a compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_namespace_rules_summary = oci.LogAnalytics.get_namespace_rules_summary(compartment_id=var["compartment_id"],
        namespace=var["namespace_rules_summary_namespace"])
    ```


    :param str compartment_id: The ID of the compartment in which to list resources.
    :param str namespace: The Logging Analytics namespace used for the request.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['namespace'] = namespace
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:LogAnalytics/getNamespaceRulesSummary:getNamespaceRulesSummary', __args__, opts=opts, typ=GetNamespaceRulesSummaryResult).value

    return AwaitableGetNamespaceRulesSummaryResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        id=pulumi.get(__ret__, 'id'),
        ingest_time_rules_count=pulumi.get(__ret__, 'ingest_time_rules_count'),
        namespace=pulumi.get(__ret__, 'namespace'),
        saved_search_rules_count=pulumi.get(__ret__, 'saved_search_rules_count'),
        total_count=pulumi.get(__ret__, 'total_count'))


@_utilities.lift_output_func(get_namespace_rules_summary)
def get_namespace_rules_summary_output(compartment_id: Optional[pulumi.Input[str]] = None,
                                       namespace: Optional[pulumi.Input[str]] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetNamespaceRulesSummaryResult]:
    """
    This data source provides details about a specific Namespace Rules Summary resource in Oracle Cloud Infrastructure Log Analytics service.

    Returns the count of detection rules in a compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_namespace_rules_summary = oci.LogAnalytics.get_namespace_rules_summary(compartment_id=var["compartment_id"],
        namespace=var["namespace_rules_summary_namespace"])
    ```


    :param str compartment_id: The ID of the compartment in which to list resources.
    :param str namespace: The Logging Analytics namespace used for the request.
    """
    ...