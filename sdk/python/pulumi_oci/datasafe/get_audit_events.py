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
    'GetAuditEventsResult',
    'AwaitableGetAuditEventsResult',
    'get_audit_events',
    'get_audit_events_output',
]

@pulumi.output_type
class GetAuditEventsResult:
    """
    A collection of values returned by getAuditEvents.
    """
    def __init__(__self__, access_level=None, audit_event_collections=None, compartment_id=None, compartment_id_in_subtree=None, filters=None, id=None, scim_query=None):
        if access_level and not isinstance(access_level, str):
            raise TypeError("Expected argument 'access_level' to be a str")
        pulumi.set(__self__, "access_level", access_level)
        if audit_event_collections and not isinstance(audit_event_collections, list):
            raise TypeError("Expected argument 'audit_event_collections' to be a list")
        pulumi.set(__self__, "audit_event_collections", audit_event_collections)
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
        if scim_query and not isinstance(scim_query, str):
            raise TypeError("Expected argument 'scim_query' to be a str")
        pulumi.set(__self__, "scim_query", scim_query)

    @property
    @pulumi.getter(name="accessLevel")
    def access_level(self) -> Optional[str]:
        return pulumi.get(self, "access_level")

    @property
    @pulumi.getter(name="auditEventCollections")
    def audit_event_collections(self) -> Sequence['outputs.GetAuditEventsAuditEventCollectionResult']:
        """
        The list of audit_event_collection.
        """
        return pulumi.get(self, "audit_event_collections")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment containing the audit event. This is the same audited target database resource comparment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetAuditEventsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="scimQuery")
    def scim_query(self) -> Optional[str]:
        return pulumi.get(self, "scim_query")


class AwaitableGetAuditEventsResult(GetAuditEventsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAuditEventsResult(
            access_level=self.access_level,
            audit_event_collections=self.audit_event_collections,
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            filters=self.filters,
            id=self.id,
            scim_query=self.scim_query)


def get_audit_events(access_level: Optional[str] = None,
                     compartment_id: Optional[str] = None,
                     compartment_id_in_subtree: Optional[bool] = None,
                     filters: Optional[Sequence[pulumi.InputType['GetAuditEventsFilterArgs']]] = None,
                     scim_query: Optional[str] = None,
                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAuditEventsResult:
    """
    This data source provides the list of Audit Events in Oracle Cloud Infrastructure Data Safe service.

    The ListAuditEvents operation returns specified `compartmentId` audit Events only.
    The list does not include any audit Events associated with the `subcompartments` of the specified `compartmentId`.

    The parameter `accessLevel` specifies whether to return only those compartments for which the
    requestor has INSPECT permissions on at least one resource directly
    or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
    Principal doesn't have access to even one of the child compartments. This is valid only when
    `compartmentIdInSubtree` is set to `true`.

    The parameter `compartmentIdInSubtree` applies when you perform ListAuditEvents on the
    `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
    To get a full list of all compartments and subcompartments in the tenancy (root compartment),
    set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_audit_events = oci.DataSafe.get_audit_events(compartment_id=var["compartment_id"],
        access_level=var["audit_event_access_level"],
        compartment_id_in_subtree=var["audit_event_compartment_id_in_subtree"],
        scim_query=var["audit_event_scim_query"])
    ```


    :param str access_level: Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
    :param str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param str scim_query: The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
    """
    __args__ = dict()
    __args__['accessLevel'] = access_level
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['filters'] = filters
    __args__['scimQuery'] = scim_query
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getAuditEvents:getAuditEvents', __args__, opts=opts, typ=GetAuditEventsResult).value

    return AwaitableGetAuditEventsResult(
        access_level=__ret__.access_level,
        audit_event_collections=__ret__.audit_event_collections,
        compartment_id=__ret__.compartment_id,
        compartment_id_in_subtree=__ret__.compartment_id_in_subtree,
        filters=__ret__.filters,
        id=__ret__.id,
        scim_query=__ret__.scim_query)


@_utilities.lift_output_func(get_audit_events)
def get_audit_events_output(access_level: Optional[pulumi.Input[Optional[str]]] = None,
                            compartment_id: Optional[pulumi.Input[str]] = None,
                            compartment_id_in_subtree: Optional[pulumi.Input[Optional[bool]]] = None,
                            filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetAuditEventsFilterArgs']]]]] = None,
                            scim_query: Optional[pulumi.Input[Optional[str]]] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetAuditEventsResult]:
    """
    This data source provides the list of Audit Events in Oracle Cloud Infrastructure Data Safe service.

    The ListAuditEvents operation returns specified `compartmentId` audit Events only.
    The list does not include any audit Events associated with the `subcompartments` of the specified `compartmentId`.

    The parameter `accessLevel` specifies whether to return only those compartments for which the
    requestor has INSPECT permissions on at least one resource directly
    or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
    Principal doesn't have access to even one of the child compartments. This is valid only when
    `compartmentIdInSubtree` is set to `true`.

    The parameter `compartmentIdInSubtree` applies when you perform ListAuditEvents on the
    `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
    To get a full list of all compartments and subcompartments in the tenancy (root compartment),
    set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_audit_events = oci.DataSafe.get_audit_events(compartment_id=var["compartment_id"],
        access_level=var["audit_event_access_level"],
        compartment_id_in_subtree=var["audit_event_compartment_id_in_subtree"],
        scim_query=var["audit_event_scim_query"])
    ```


    :param str access_level: Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
    :param str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param str scim_query: The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
    """
    ...