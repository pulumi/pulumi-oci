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
    'GetServiceCatalogAssociationsResult',
    'AwaitableGetServiceCatalogAssociationsResult',
    'get_service_catalog_associations',
    'get_service_catalog_associations_output',
]

@pulumi.output_type
class GetServiceCatalogAssociationsResult:
    """
    A collection of values returned by getServiceCatalogAssociations.
    """
    def __init__(__self__, entity_id=None, entity_type=None, filters=None, id=None, service_catalog_association_collections=None, service_catalog_association_id=None, service_catalog_id=None):
        if entity_id and not isinstance(entity_id, str):
            raise TypeError("Expected argument 'entity_id' to be a str")
        pulumi.set(__self__, "entity_id", entity_id)
        if entity_type and not isinstance(entity_type, str):
            raise TypeError("Expected argument 'entity_type' to be a str")
        pulumi.set(__self__, "entity_type", entity_type)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if service_catalog_association_collections and not isinstance(service_catalog_association_collections, list):
            raise TypeError("Expected argument 'service_catalog_association_collections' to be a list")
        pulumi.set(__self__, "service_catalog_association_collections", service_catalog_association_collections)
        if service_catalog_association_id and not isinstance(service_catalog_association_id, str):
            raise TypeError("Expected argument 'service_catalog_association_id' to be a str")
        pulumi.set(__self__, "service_catalog_association_id", service_catalog_association_id)
        if service_catalog_id and not isinstance(service_catalog_id, str):
            raise TypeError("Expected argument 'service_catalog_id' to be a str")
        pulumi.set(__self__, "service_catalog_id", service_catalog_id)

    @property
    @pulumi.getter(name="entityId")
    def entity_id(self) -> Optional[str]:
        """
        Identifier of the entity being associated with service catalog.
        """
        return pulumi.get(self, "entity_id")

    @property
    @pulumi.getter(name="entityType")
    def entity_type(self) -> Optional[str]:
        """
        The type of the entity that is associated with the service catalog.
        """
        return pulumi.get(self, "entity_type")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetServiceCatalogAssociationsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="serviceCatalogAssociationCollections")
    def service_catalog_association_collections(self) -> Sequence['outputs.GetServiceCatalogAssociationsServiceCatalogAssociationCollectionResult']:
        """
        The list of service_catalog_association_collection.
        """
        return pulumi.get(self, "service_catalog_association_collections")

    @property
    @pulumi.getter(name="serviceCatalogAssociationId")
    def service_catalog_association_id(self) -> Optional[str]:
        return pulumi.get(self, "service_catalog_association_id")

    @property
    @pulumi.getter(name="serviceCatalogId")
    def service_catalog_id(self) -> Optional[str]:
        """
        Identifier of the service catalog.
        """
        return pulumi.get(self, "service_catalog_id")


class AwaitableGetServiceCatalogAssociationsResult(GetServiceCatalogAssociationsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetServiceCatalogAssociationsResult(
            entity_id=self.entity_id,
            entity_type=self.entity_type,
            filters=self.filters,
            id=self.id,
            service_catalog_association_collections=self.service_catalog_association_collections,
            service_catalog_association_id=self.service_catalog_association_id,
            service_catalog_id=self.service_catalog_id)


def get_service_catalog_associations(entity_id: Optional[str] = None,
                                     entity_type: Optional[str] = None,
                                     filters: Optional[Sequence[pulumi.InputType['GetServiceCatalogAssociationsFilterArgs']]] = None,
                                     service_catalog_association_id: Optional[str] = None,
                                     service_catalog_id: Optional[str] = None,
                                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetServiceCatalogAssociationsResult:
    """
    This data source provides the list of Service Catalog Associations in Oracle Cloud Infrastructure Service Catalog service.

    Lists all the resource associations for a specific service catalog.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_service_catalog_associations = oci.ServiceCatalog.get_service_catalog_associations(entity_id=oci_service_catalog_entity["test_entity"]["id"],
        entity_type=var["service_catalog_association_entity_type"],
        service_catalog_association_id=oci_service_catalog_service_catalog_association["test_service_catalog_association"]["id"],
        service_catalog_id=oci_service_catalog_service_catalog["test_service_catalog"]["id"])
    ```


    :param str entity_id: The unique identifier of the entity associated with service catalog.
    :param str entity_type: The type of the application in the service catalog.
    :param str service_catalog_association_id: The unique identifier for the service catalog association.
    :param str service_catalog_id: The unique identifier for the service catalog.
    """
    __args__ = dict()
    __args__['entityId'] = entity_id
    __args__['entityType'] = entity_type
    __args__['filters'] = filters
    __args__['serviceCatalogAssociationId'] = service_catalog_association_id
    __args__['serviceCatalogId'] = service_catalog_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ServiceCatalog/getServiceCatalogAssociations:getServiceCatalogAssociations', __args__, opts=opts, typ=GetServiceCatalogAssociationsResult).value

    return AwaitableGetServiceCatalogAssociationsResult(
        entity_id=__ret__.entity_id,
        entity_type=__ret__.entity_type,
        filters=__ret__.filters,
        id=__ret__.id,
        service_catalog_association_collections=__ret__.service_catalog_association_collections,
        service_catalog_association_id=__ret__.service_catalog_association_id,
        service_catalog_id=__ret__.service_catalog_id)


@_utilities.lift_output_func(get_service_catalog_associations)
def get_service_catalog_associations_output(entity_id: Optional[pulumi.Input[Optional[str]]] = None,
                                            entity_type: Optional[pulumi.Input[Optional[str]]] = None,
                                            filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetServiceCatalogAssociationsFilterArgs']]]]] = None,
                                            service_catalog_association_id: Optional[pulumi.Input[Optional[str]]] = None,
                                            service_catalog_id: Optional[pulumi.Input[Optional[str]]] = None,
                                            opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetServiceCatalogAssociationsResult]:
    """
    This data source provides the list of Service Catalog Associations in Oracle Cloud Infrastructure Service Catalog service.

    Lists all the resource associations for a specific service catalog.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_service_catalog_associations = oci.ServiceCatalog.get_service_catalog_associations(entity_id=oci_service_catalog_entity["test_entity"]["id"],
        entity_type=var["service_catalog_association_entity_type"],
        service_catalog_association_id=oci_service_catalog_service_catalog_association["test_service_catalog_association"]["id"],
        service_catalog_id=oci_service_catalog_service_catalog["test_service_catalog"]["id"])
    ```


    :param str entity_id: The unique identifier of the entity associated with service catalog.
    :param str entity_type: The type of the application in the service catalog.
    :param str service_catalog_association_id: The unique identifier for the service catalog association.
    :param str service_catalog_id: The unique identifier for the service catalog.
    """
    ...