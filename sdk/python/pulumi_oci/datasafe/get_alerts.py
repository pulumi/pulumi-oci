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
    'GetAlertsResult',
    'AwaitableGetAlertsResult',
    'get_alerts',
    'get_alerts_output',
]

@pulumi.output_type
class GetAlertsResult:
    """
    A collection of values returned by getAlerts.
    """
    def __init__(__self__, access_level=None, alert_collections=None, compartment_id=None, compartment_id_in_subtree=None, fields=None, filters=None, id=None, scim_query=None):
        if access_level and not isinstance(access_level, str):
            raise TypeError("Expected argument 'access_level' to be a str")
        pulumi.set(__self__, "access_level", access_level)
        if alert_collections and not isinstance(alert_collections, list):
            raise TypeError("Expected argument 'alert_collections' to be a list")
        pulumi.set(__self__, "alert_collections", alert_collections)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compartment_id_in_subtree and not isinstance(compartment_id_in_subtree, bool):
            raise TypeError("Expected argument 'compartment_id_in_subtree' to be a bool")
        pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if fields and not isinstance(fields, list):
            raise TypeError("Expected argument 'fields' to be a list")
        pulumi.set(__self__, "fields", fields)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if scim_query and not isinstance(scim_query, str):
            raise TypeError("Expected argument 'scim_query' to be a str")
        pulumi.set(__self__, "scim_query", scim_query)

    @property
    @pulumi.getter(name="accessLevel")
    def access_level(self) -> Optional[str]:
        return pulumi.get(self, "access_level")

    @property
    @pulumi.getter(name="alertCollections")
    def alert_collections(self) -> Sequence['outputs.GetAlertsAlertCollectionResult']:
        """
        The list of alert_collection.
        """
        return pulumi.get(self, "alert_collections")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment that contains the alert.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @property
    @pulumi.getter
    def fields(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "fields")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetAlertsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> Optional[str]:
        """
        The OCID of the alert.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="scimQuery")
    def scim_query(self) -> Optional[str]:
        return pulumi.get(self, "scim_query")


class AwaitableGetAlertsResult(GetAlertsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAlertsResult(
            access_level=self.access_level,
            alert_collections=self.alert_collections,
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            fields=self.fields,
            filters=self.filters,
            id=self.id,
            scim_query=self.scim_query)


def get_alerts(access_level: Optional[str] = None,
               compartment_id: Optional[str] = None,
               compartment_id_in_subtree: Optional[bool] = None,
               fields: Optional[Sequence[str]] = None,
               filters: Optional[Sequence[pulumi.InputType['GetAlertsFilterArgs']]] = None,
               id: Optional[str] = None,
               scim_query: Optional[str] = None,
               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAlertsResult:
    """
    This data source provides the list of Alerts in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of all alerts.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_alerts = oci.DataSafe.get_alerts(compartment_id=var["compartment_id"],
        access_level=var["alert_access_level"],
        compartment_id_in_subtree=var["alert_compartment_id_in_subtree"],
        fields=var["alert_field"],
        id=var["alert_id"],
        scim_query=var["alert_scim_query"])
    ```


    :param str access_level: Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
    :param str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param Sequence[str] fields: Specifies a subset of fields to be returned in the response.
    :param str id: A filter to return alert by it's OCID.
    :param str scim_query: The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
    """
    __args__ = dict()
    __args__['accessLevel'] = access_level
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['fields'] = fields
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['scimQuery'] = scim_query
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getAlerts:getAlerts', __args__, opts=opts, typ=GetAlertsResult).value

    return AwaitableGetAlertsResult(
        access_level=__ret__.access_level,
        alert_collections=__ret__.alert_collections,
        compartment_id=__ret__.compartment_id,
        compartment_id_in_subtree=__ret__.compartment_id_in_subtree,
        fields=__ret__.fields,
        filters=__ret__.filters,
        id=__ret__.id,
        scim_query=__ret__.scim_query)


@_utilities.lift_output_func(get_alerts)
def get_alerts_output(access_level: Optional[pulumi.Input[Optional[str]]] = None,
                      compartment_id: Optional[pulumi.Input[str]] = None,
                      compartment_id_in_subtree: Optional[pulumi.Input[Optional[bool]]] = None,
                      fields: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                      filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetAlertsFilterArgs']]]]] = None,
                      id: Optional[pulumi.Input[Optional[str]]] = None,
                      scim_query: Optional[pulumi.Input[Optional[str]]] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetAlertsResult]:
    """
    This data source provides the list of Alerts in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of all alerts.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_alerts = oci.DataSafe.get_alerts(compartment_id=var["compartment_id"],
        access_level=var["alert_access_level"],
        compartment_id_in_subtree=var["alert_compartment_id_in_subtree"],
        fields=var["alert_field"],
        id=var["alert_id"],
        scim_query=var["alert_scim_query"])
    ```


    :param str access_level: Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
    :param str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param Sequence[str] fields: Specifies a subset of fields to be returned in the response.
    :param str id: A filter to return alert by it's OCID.
    :param str scim_query: The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
    """
    ...