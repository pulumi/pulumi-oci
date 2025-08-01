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
    'GetComplianceRecordsResult',
    'AwaitableGetComplianceRecordsResult',
    'get_compliance_records',
    'get_compliance_records_output',
]

@pulumi.output_type
class GetComplianceRecordsResult:
    """
    A collection of values returned by getComplianceRecords.
    """
    def __init__(__self__, compartment_id=None, compartment_id_in_subtree=None, compliance_record_collections=None, compliance_state=None, entity_id=None, filters=None, id=None, product_name=None, product_stack=None, resource_id=None, target_name=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compartment_id_in_subtree and not isinstance(compartment_id_in_subtree, bool):
            raise TypeError("Expected argument 'compartment_id_in_subtree' to be a bool")
        pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if compliance_record_collections and not isinstance(compliance_record_collections, list):
            raise TypeError("Expected argument 'compliance_record_collections' to be a list")
        pulumi.set(__self__, "compliance_record_collections", compliance_record_collections)
        if compliance_state and not isinstance(compliance_state, str):
            raise TypeError("Expected argument 'compliance_state' to be a str")
        pulumi.set(__self__, "compliance_state", compliance_state)
        if entity_id and not isinstance(entity_id, str):
            raise TypeError("Expected argument 'entity_id' to be a str")
        pulumi.set(__self__, "entity_id", entity_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if product_name and not isinstance(product_name, str):
            raise TypeError("Expected argument 'product_name' to be a str")
        pulumi.set(__self__, "product_name", product_name)
        if product_stack and not isinstance(product_stack, str):
            raise TypeError("Expected argument 'product_stack' to be a str")
        pulumi.set(__self__, "product_stack", product_stack)
        if resource_id and not isinstance(resource_id, str):
            raise TypeError("Expected argument 'resource_id' to be a str")
        pulumi.set(__self__, "resource_id", resource_id)
        if target_name and not isinstance(target_name, str):
            raise TypeError("Expected argument 'target_name' to be a str")
        pulumi.set(__self__, "target_name", target_name)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        Compartment OCID of the resource.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @_builtins.property
    @pulumi.getter(name="complianceRecordCollections")
    def compliance_record_collections(self) -> Sequence['outputs.GetComplianceRecordsComplianceRecordCollectionResult']:
        """
        The list of compliance_record_collection.
        """
        return pulumi.get(self, "compliance_record_collections")

    @_builtins.property
    @pulumi.getter(name="complianceState")
    def compliance_state(self) -> Optional[_builtins.str]:
        """
        Last known compliance state of target.
        """
        return pulumi.get(self, "compliance_state")

    @_builtins.property
    @pulumi.getter(name="entityId")
    def entity_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the entity for which the compliance is calculated.Ex.FleetId
        """
        return pulumi.get(self, "entity_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetComplianceRecordsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="productName")
    def product_name(self) -> Optional[_builtins.str]:
        """
        Product Name.
        """
        return pulumi.get(self, "product_name")

    @_builtins.property
    @pulumi.getter(name="productStack")
    def product_stack(self) -> Optional[_builtins.str]:
        """
        Product Stack.
        """
        return pulumi.get(self, "product_stack")

    @_builtins.property
    @pulumi.getter(name="resourceId")
    def resource_id(self) -> Optional[_builtins.str]:
        """
        The OCID to identify the resource.
        """
        return pulumi.get(self, "resource_id")

    @_builtins.property
    @pulumi.getter(name="targetName")
    def target_name(self) -> Optional[_builtins.str]:
        """
        Target Name.
        """
        return pulumi.get(self, "target_name")


class AwaitableGetComplianceRecordsResult(GetComplianceRecordsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetComplianceRecordsResult(
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            compliance_record_collections=self.compliance_record_collections,
            compliance_state=self.compliance_state,
            entity_id=self.entity_id,
            filters=self.filters,
            id=self.id,
            product_name=self.product_name,
            product_stack=self.product_stack,
            resource_id=self.resource_id,
            target_name=self.target_name)


def get_compliance_records(compartment_id: Optional[_builtins.str] = None,
                           compartment_id_in_subtree: Optional[_builtins.bool] = None,
                           compliance_state: Optional[_builtins.str] = None,
                           entity_id: Optional[_builtins.str] = None,
                           filters: Optional[Sequence[Union['GetComplianceRecordsFilterArgs', 'GetComplianceRecordsFilterArgsDict']]] = None,
                           product_name: Optional[_builtins.str] = None,
                           product_stack: Optional[_builtins.str] = None,
                           resource_id: Optional[_builtins.str] = None,
                           target_name: Optional[_builtins.str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetComplianceRecordsResult:
    """
    This data source provides the list of Compliance Records in Oracle Cloud Infrastructure Fleet Apps Management service.

    Gets a list of complianceDetails.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compliance_records = oci.FleetAppsManagement.get_compliance_records(compartment_id=compartment_id,
        compartment_id_in_subtree=compliance_record_compartment_id_in_subtree,
        compliance_state=compliance_record_compliance_state,
        entity_id=test_entity["id"],
        product_name=compliance_record_product_name,
        product_stack=compliance_record_product_stack,
        resource_id=test_resource["id"],
        target_name=test_target["name"])
    ```


    :param _builtins.str compartment_id: The ID of the compartment in which to list resources.
    :param _builtins.bool compartment_id_in_subtree: If set to true, resources will be returned for not only the provided compartment, but all compartments which descend from it. Which resources are returned and their field contents depends on the value of accessLevel.
    :param _builtins.str compliance_state: Target Compliance State.
    :param _builtins.str entity_id: Entity identifier.Ex:FleetId
    :param _builtins.str product_name: Product Name.
    :param _builtins.str product_stack: ProductStack name.
    :param _builtins.str resource_id: Resource identifier.
    :param _builtins.str target_name: Unique target name
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['complianceState'] = compliance_state
    __args__['entityId'] = entity_id
    __args__['filters'] = filters
    __args__['productName'] = product_name
    __args__['productStack'] = product_stack
    __args__['resourceId'] = resource_id
    __args__['targetName'] = target_name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:FleetAppsManagement/getComplianceRecords:getComplianceRecords', __args__, opts=opts, typ=GetComplianceRecordsResult).value

    return AwaitableGetComplianceRecordsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compartment_id_in_subtree=pulumi.get(__ret__, 'compartment_id_in_subtree'),
        compliance_record_collections=pulumi.get(__ret__, 'compliance_record_collections'),
        compliance_state=pulumi.get(__ret__, 'compliance_state'),
        entity_id=pulumi.get(__ret__, 'entity_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        product_name=pulumi.get(__ret__, 'product_name'),
        product_stack=pulumi.get(__ret__, 'product_stack'),
        resource_id=pulumi.get(__ret__, 'resource_id'),
        target_name=pulumi.get(__ret__, 'target_name'))
def get_compliance_records_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                  compartment_id_in_subtree: Optional[pulumi.Input[Optional[_builtins.bool]]] = None,
                                  compliance_state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                  entity_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                  filters: Optional[pulumi.Input[Optional[Sequence[Union['GetComplianceRecordsFilterArgs', 'GetComplianceRecordsFilterArgsDict']]]]] = None,
                                  product_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                  product_stack: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                  resource_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                  target_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                  opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetComplianceRecordsResult]:
    """
    This data source provides the list of Compliance Records in Oracle Cloud Infrastructure Fleet Apps Management service.

    Gets a list of complianceDetails.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compliance_records = oci.FleetAppsManagement.get_compliance_records(compartment_id=compartment_id,
        compartment_id_in_subtree=compliance_record_compartment_id_in_subtree,
        compliance_state=compliance_record_compliance_state,
        entity_id=test_entity["id"],
        product_name=compliance_record_product_name,
        product_stack=compliance_record_product_stack,
        resource_id=test_resource["id"],
        target_name=test_target["name"])
    ```


    :param _builtins.str compartment_id: The ID of the compartment in which to list resources.
    :param _builtins.bool compartment_id_in_subtree: If set to true, resources will be returned for not only the provided compartment, but all compartments which descend from it. Which resources are returned and their field contents depends on the value of accessLevel.
    :param _builtins.str compliance_state: Target Compliance State.
    :param _builtins.str entity_id: Entity identifier.Ex:FleetId
    :param _builtins.str product_name: Product Name.
    :param _builtins.str product_stack: ProductStack name.
    :param _builtins.str resource_id: Resource identifier.
    :param _builtins.str target_name: Unique target name
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['complianceState'] = compliance_state
    __args__['entityId'] = entity_id
    __args__['filters'] = filters
    __args__['productName'] = product_name
    __args__['productStack'] = product_stack
    __args__['resourceId'] = resource_id
    __args__['targetName'] = target_name
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:FleetAppsManagement/getComplianceRecords:getComplianceRecords', __args__, opts=opts, typ=GetComplianceRecordsResult)
    return __ret__.apply(lambda __response__: GetComplianceRecordsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        compartment_id_in_subtree=pulumi.get(__response__, 'compartment_id_in_subtree'),
        compliance_record_collections=pulumi.get(__response__, 'compliance_record_collections'),
        compliance_state=pulumi.get(__response__, 'compliance_state'),
        entity_id=pulumi.get(__response__, 'entity_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        product_name=pulumi.get(__response__, 'product_name'),
        product_stack=pulumi.get(__response__, 'product_stack'),
        resource_id=pulumi.get(__response__, 'resource_id'),
        target_name=pulumi.get(__response__, 'target_name')))
