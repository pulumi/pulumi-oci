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
    'GetUserAssessmentPasswordExpiryDateAnalyticsResult',
    'AwaitableGetUserAssessmentPasswordExpiryDateAnalyticsResult',
    'get_user_assessment_password_expiry_date_analytics',
    'get_user_assessment_password_expiry_date_analytics_output',
]

@pulumi.output_type
class GetUserAssessmentPasswordExpiryDateAnalyticsResult:
    """
    A collection of values returned by getUserAssessmentPasswordExpiryDateAnalytics.
    """
    def __init__(__self__, access_level=None, compartment_id_in_subtree=None, filters=None, id=None, time_password_expiry_less_than=None, user_aggregations=None, user_assessment_id=None, user_category=None):
        if access_level and not isinstance(access_level, str):
            raise TypeError("Expected argument 'access_level' to be a str")
        pulumi.set(__self__, "access_level", access_level)
        if compartment_id_in_subtree and not isinstance(compartment_id_in_subtree, bool):
            raise TypeError("Expected argument 'compartment_id_in_subtree' to be a bool")
        pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if time_password_expiry_less_than and not isinstance(time_password_expiry_less_than, str):
            raise TypeError("Expected argument 'time_password_expiry_less_than' to be a str")
        pulumi.set(__self__, "time_password_expiry_less_than", time_password_expiry_less_than)
        if user_aggregations and not isinstance(user_aggregations, list):
            raise TypeError("Expected argument 'user_aggregations' to be a list")
        pulumi.set(__self__, "user_aggregations", user_aggregations)
        if user_assessment_id and not isinstance(user_assessment_id, str):
            raise TypeError("Expected argument 'user_assessment_id' to be a str")
        pulumi.set(__self__, "user_assessment_id", user_assessment_id)
        if user_category and not isinstance(user_category, str):
            raise TypeError("Expected argument 'user_category' to be a str")
        pulumi.set(__self__, "user_category", user_category)

    @_builtins.property
    @pulumi.getter(name="accessLevel")
    def access_level(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "access_level")

    @_builtins.property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetUserAssessmentPasswordExpiryDateAnalyticsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="timePasswordExpiryLessThan")
    def time_password_expiry_less_than(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "time_password_expiry_less_than")

    @_builtins.property
    @pulumi.getter(name="userAggregations")
    def user_aggregations(self) -> Sequence['outputs.GetUserAssessmentPasswordExpiryDateAnalyticsUserAggregationResult']:
        """
        The list of user_aggregations.
        """
        return pulumi.get(self, "user_aggregations")

    @_builtins.property
    @pulumi.getter(name="userAssessmentId")
    def user_assessment_id(self) -> _builtins.str:
        return pulumi.get(self, "user_assessment_id")

    @_builtins.property
    @pulumi.getter(name="userCategory")
    def user_category(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "user_category")


class AwaitableGetUserAssessmentPasswordExpiryDateAnalyticsResult(GetUserAssessmentPasswordExpiryDateAnalyticsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetUserAssessmentPasswordExpiryDateAnalyticsResult(
            access_level=self.access_level,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            filters=self.filters,
            id=self.id,
            time_password_expiry_less_than=self.time_password_expiry_less_than,
            user_aggregations=self.user_aggregations,
            user_assessment_id=self.user_assessment_id,
            user_category=self.user_category)


def get_user_assessment_password_expiry_date_analytics(access_level: Optional[_builtins.str] = None,
                                                       compartment_id_in_subtree: Optional[_builtins.bool] = None,
                                                       filters: Optional[Sequence[Union['GetUserAssessmentPasswordExpiryDateAnalyticsFilterArgs', 'GetUserAssessmentPasswordExpiryDateAnalyticsFilterArgsDict']]] = None,
                                                       time_password_expiry_less_than: Optional[_builtins.str] = None,
                                                       user_assessment_id: Optional[_builtins.str] = None,
                                                       user_category: Optional[_builtins.str] = None,
                                                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetUserAssessmentPasswordExpiryDateAnalyticsResult:
    """
    This data source provides the list of User Assessment Password Expiry Date Analytics in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of count of the users with password expiry dates in next 30 days, between next 30-90 days, and beyond 90 days based on specified user assessment.
    It internally uses the aforementioned userAnalytics api.

    When you perform the ListPasswordExpiryDateAnalytics operation, if the parameter compartmentIdInSubtree is set to "true," and if the
    parameter accessLevel is set to ACCESSIBLE, then the operation returns compartments in which the requestor has READ
    permissions on at least one resource, directly or indirectly (in subcompartments). If the operation is performed at the
    root compartment and the requestor does not have access to at least one subcompartment of the compartment specified by
    compartmentId, then "Not Authorized" is returned.

    To use ListPasswordExpiryDateAnalytics to get a full list of all compartments and subcompartments in the tenancy from the root compartment,
    set the parameter compartmentIdInSubtree to true and accessLevel to ACCESSIBLE.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_user_assessment_password_expiry_date_analytics = oci.DataSafe.get_user_assessment_password_expiry_date_analytics(user_assessment_id=test_user_assessment["id"],
        access_level=user_assessment_password_expiry_date_analytic_access_level,
        compartment_id_in_subtree=user_assessment_password_expiry_date_analytic_compartment_id_in_subtree,
        time_password_expiry_less_than=user_assessment_password_expiry_date_analytic_time_password_expiry_less_than,
        user_category=user_assessment_password_expiry_date_analytic_user_category)
    ```


    :param _builtins.str access_level: Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
    :param _builtins.bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param _builtins.str time_password_expiry_less_than: A filter to return users whose password expiry date in the database is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). **Example:** 2016-12-19T16:39:57.600Z
    :param _builtins.str user_assessment_id: The OCID of the user assessment.
    :param _builtins.str user_category: A filter to return only items that match the specified user category.
    """
    __args__ = dict()
    __args__['accessLevel'] = access_level
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['filters'] = filters
    __args__['timePasswordExpiryLessThan'] = time_password_expiry_less_than
    __args__['userAssessmentId'] = user_assessment_id
    __args__['userCategory'] = user_category
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getUserAssessmentPasswordExpiryDateAnalytics:getUserAssessmentPasswordExpiryDateAnalytics', __args__, opts=opts, typ=GetUserAssessmentPasswordExpiryDateAnalyticsResult).value

    return AwaitableGetUserAssessmentPasswordExpiryDateAnalyticsResult(
        access_level=pulumi.get(__ret__, 'access_level'),
        compartment_id_in_subtree=pulumi.get(__ret__, 'compartment_id_in_subtree'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        time_password_expiry_less_than=pulumi.get(__ret__, 'time_password_expiry_less_than'),
        user_aggregations=pulumi.get(__ret__, 'user_aggregations'),
        user_assessment_id=pulumi.get(__ret__, 'user_assessment_id'),
        user_category=pulumi.get(__ret__, 'user_category'))
def get_user_assessment_password_expiry_date_analytics_output(access_level: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                              compartment_id_in_subtree: Optional[pulumi.Input[Optional[_builtins.bool]]] = None,
                                                              filters: Optional[pulumi.Input[Optional[Sequence[Union['GetUserAssessmentPasswordExpiryDateAnalyticsFilterArgs', 'GetUserAssessmentPasswordExpiryDateAnalyticsFilterArgsDict']]]]] = None,
                                                              time_password_expiry_less_than: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                              user_assessment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                              user_category: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                              opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetUserAssessmentPasswordExpiryDateAnalyticsResult]:
    """
    This data source provides the list of User Assessment Password Expiry Date Analytics in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of count of the users with password expiry dates in next 30 days, between next 30-90 days, and beyond 90 days based on specified user assessment.
    It internally uses the aforementioned userAnalytics api.

    When you perform the ListPasswordExpiryDateAnalytics operation, if the parameter compartmentIdInSubtree is set to "true," and if the
    parameter accessLevel is set to ACCESSIBLE, then the operation returns compartments in which the requestor has READ
    permissions on at least one resource, directly or indirectly (in subcompartments). If the operation is performed at the
    root compartment and the requestor does not have access to at least one subcompartment of the compartment specified by
    compartmentId, then "Not Authorized" is returned.

    To use ListPasswordExpiryDateAnalytics to get a full list of all compartments and subcompartments in the tenancy from the root compartment,
    set the parameter compartmentIdInSubtree to true and accessLevel to ACCESSIBLE.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_user_assessment_password_expiry_date_analytics = oci.DataSafe.get_user_assessment_password_expiry_date_analytics(user_assessment_id=test_user_assessment["id"],
        access_level=user_assessment_password_expiry_date_analytic_access_level,
        compartment_id_in_subtree=user_assessment_password_expiry_date_analytic_compartment_id_in_subtree,
        time_password_expiry_less_than=user_assessment_password_expiry_date_analytic_time_password_expiry_less_than,
        user_category=user_assessment_password_expiry_date_analytic_user_category)
    ```


    :param _builtins.str access_level: Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
    :param _builtins.bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param _builtins.str time_password_expiry_less_than: A filter to return users whose password expiry date in the database is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). **Example:** 2016-12-19T16:39:57.600Z
    :param _builtins.str user_assessment_id: The OCID of the user assessment.
    :param _builtins.str user_category: A filter to return only items that match the specified user category.
    """
    __args__ = dict()
    __args__['accessLevel'] = access_level
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['filters'] = filters
    __args__['timePasswordExpiryLessThan'] = time_password_expiry_less_than
    __args__['userAssessmentId'] = user_assessment_id
    __args__['userCategory'] = user_category
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataSafe/getUserAssessmentPasswordExpiryDateAnalytics:getUserAssessmentPasswordExpiryDateAnalytics', __args__, opts=opts, typ=GetUserAssessmentPasswordExpiryDateAnalyticsResult)
    return __ret__.apply(lambda __response__: GetUserAssessmentPasswordExpiryDateAnalyticsResult(
        access_level=pulumi.get(__response__, 'access_level'),
        compartment_id_in_subtree=pulumi.get(__response__, 'compartment_id_in_subtree'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        time_password_expiry_less_than=pulumi.get(__response__, 'time_password_expiry_less_than'),
        user_aggregations=pulumi.get(__response__, 'user_aggregations'),
        user_assessment_id=pulumi.get(__response__, 'user_assessment_id'),
        user_category=pulumi.get(__response__, 'user_category')))
