# coding=utf-8
# *** WARNING: this file was generated by pulumi-language-python. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import builtins
import copy
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

__all__ = [
    'PrivateApplicationLogo',
    'PrivateApplicationPackageDetails',
    'GetPrivateApplicationLogoResult',
    'GetPrivateApplicationPackageDetailResult',
    'GetPrivateApplicationPackagesFilterResult',
    'GetPrivateApplicationPackagesPrivateApplicationPackageCollectionResult',
    'GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItemResult',
    'GetPrivateApplicationsFilterResult',
    'GetPrivateApplicationsPrivateApplicationCollectionResult',
    'GetPrivateApplicationsPrivateApplicationCollectionItemResult',
    'GetPrivateApplicationsPrivateApplicationCollectionItemLogoResult',
    'GetPrivateApplicationsPrivateApplicationCollectionItemPackageDetailResult',
    'GetServiceCatalogAssociationsFilterResult',
    'GetServiceCatalogAssociationsServiceCatalogAssociationCollectionResult',
    'GetServiceCatalogAssociationsServiceCatalogAssociationCollectionItemResult',
    'GetServiceCatalogsFilterResult',
    'GetServiceCatalogsServiceCatalogCollectionResult',
    'GetServiceCatalogsServiceCatalogCollectionItemResult',
]

@pulumi.output_type
class PrivateApplicationLogo(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "contentUrl":
            suggest = "content_url"
        elif key == "displayName":
            suggest = "display_name"
        elif key == "mimeType":
            suggest = "mime_type"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in PrivateApplicationLogo. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        PrivateApplicationLogo.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        PrivateApplicationLogo.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 content_url: Optional[builtins.str] = None,
                 display_name: Optional[builtins.str] = None,
                 mime_type: Optional[builtins.str] = None):
        """
        :param builtins.str content_url: The content URL of the uploaded data.
        :param builtins.str display_name: (Updatable) The name of the private application.
        :param builtins.str mime_type: The MIME type of the uploaded data.
        """
        if content_url is not None:
            pulumi.set(__self__, "content_url", content_url)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if mime_type is not None:
            pulumi.set(__self__, "mime_type", mime_type)

    @property
    @pulumi.getter(name="contentUrl")
    def content_url(self) -> Optional[builtins.str]:
        """
        The content URL of the uploaded data.
        """
        return pulumi.get(self, "content_url")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[builtins.str]:
        """
        (Updatable) The name of the private application.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="mimeType")
    def mime_type(self) -> Optional[builtins.str]:
        """
        The MIME type of the uploaded data.
        """
        return pulumi.get(self, "mime_type")


@pulumi.output_type
class PrivateApplicationPackageDetails(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "packageType":
            suggest = "package_type"
        elif key == "zipFileBase64encoded":
            suggest = "zip_file_base64encoded"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in PrivateApplicationPackageDetails. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        PrivateApplicationPackageDetails.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        PrivateApplicationPackageDetails.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 package_type: builtins.str,
                 version: builtins.str,
                 zip_file_base64encoded: Optional[builtins.str] = None):
        """
        :param builtins.str package_type: The package's type.
        :param builtins.str version: The package version.
        """
        pulumi.set(__self__, "package_type", package_type)
        pulumi.set(__self__, "version", version)
        if zip_file_base64encoded is not None:
            pulumi.set(__self__, "zip_file_base64encoded", zip_file_base64encoded)

    @property
    @pulumi.getter(name="packageType")
    def package_type(self) -> builtins.str:
        """
        The package's type.
        """
        return pulumi.get(self, "package_type")

    @property
    @pulumi.getter
    def version(self) -> builtins.str:
        """
        The package version.
        """
        return pulumi.get(self, "version")

    @property
    @pulumi.getter(name="zipFileBase64encoded")
    def zip_file_base64encoded(self) -> Optional[builtins.str]:
        return pulumi.get(self, "zip_file_base64encoded")


@pulumi.output_type
class GetPrivateApplicationLogoResult(dict):
    def __init__(__self__, *,
                 content_url: builtins.str,
                 display_name: builtins.str,
                 mime_type: builtins.str):
        """
        :param builtins.str content_url: The content URL of the uploaded data.
        :param builtins.str display_name: The name used to refer to the uploaded data.
        :param builtins.str mime_type: The MIME type of the uploaded data.
        """
        pulumi.set(__self__, "content_url", content_url)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "mime_type", mime_type)

    @property
    @pulumi.getter(name="contentUrl")
    def content_url(self) -> builtins.str:
        """
        The content URL of the uploaded data.
        """
        return pulumi.get(self, "content_url")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> builtins.str:
        """
        The name used to refer to the uploaded data.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="mimeType")
    def mime_type(self) -> builtins.str:
        """
        The MIME type of the uploaded data.
        """
        return pulumi.get(self, "mime_type")


@pulumi.output_type
class GetPrivateApplicationPackageDetailResult(dict):
    def __init__(__self__, *,
                 package_type: builtins.str,
                 version: builtins.str,
                 zip_file_base64encoded: builtins.str):
        """
        :param builtins.str package_type: Type of packages within this private application.
        """
        pulumi.set(__self__, "package_type", package_type)
        pulumi.set(__self__, "version", version)
        pulumi.set(__self__, "zip_file_base64encoded", zip_file_base64encoded)

    @property
    @pulumi.getter(name="packageType")
    def package_type(self) -> builtins.str:
        """
        Type of packages within this private application.
        """
        return pulumi.get(self, "package_type")

    @property
    @pulumi.getter
    def version(self) -> builtins.str:
        return pulumi.get(self, "version")

    @property
    @pulumi.getter(name="zipFileBase64encoded")
    def zip_file_base64encoded(self) -> builtins.str:
        return pulumi.get(self, "zip_file_base64encoded")


@pulumi.output_type
class GetPrivateApplicationPackagesFilterResult(dict):
    def __init__(__self__, *,
                 name: builtins.str,
                 values: Sequence[builtins.str],
                 regex: Optional[builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> builtins.str:
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def values(self) -> Sequence[builtins.str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[builtins.bool]:
        return pulumi.get(self, "regex")


@pulumi.output_type
class GetPrivateApplicationPackagesPrivateApplicationPackageCollectionResult(dict):
    def __init__(__self__, *,
                 items: Sequence['outputs.GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItemResult']):
        pulumi.set(__self__, "items", items)

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItemResult']:
        return pulumi.get(self, "items")


@pulumi.output_type
class GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItemResult(dict):
    def __init__(__self__, *,
                 content_url: builtins.str,
                 display_name: builtins.str,
                 id: builtins.str,
                 mime_type: builtins.str,
                 package_type: builtins.str,
                 private_application_id: builtins.str,
                 time_created: builtins.str,
                 version: builtins.str):
        """
        :param builtins.str display_name: Exact match name filter.
        :param builtins.str id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private application package.
        :param builtins.str package_type: Name of the package type. If multiple package types are provided, then any resource with one or more matching package types will be returned.
        :param builtins.str private_application_id: The unique identifier for the private application.
        :param builtins.str time_created: The date and time the private application package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-27T21:10:29.600Z`
        :param builtins.str version: The package version.
        """
        pulumi.set(__self__, "content_url", content_url)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "mime_type", mime_type)
        pulumi.set(__self__, "package_type", package_type)
        pulumi.set(__self__, "private_application_id", private_application_id)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "version", version)

    @property
    @pulumi.getter(name="contentUrl")
    def content_url(self) -> builtins.str:
        return pulumi.get(self, "content_url")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> builtins.str:
        """
        Exact match name filter.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def id(self) -> builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private application package.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="mimeType")
    def mime_type(self) -> builtins.str:
        return pulumi.get(self, "mime_type")

    @property
    @pulumi.getter(name="packageType")
    def package_type(self) -> builtins.str:
        """
        Name of the package type. If multiple package types are provided, then any resource with one or more matching package types will be returned.
        """
        return pulumi.get(self, "package_type")

    @property
    @pulumi.getter(name="privateApplicationId")
    def private_application_id(self) -> builtins.str:
        """
        The unique identifier for the private application.
        """
        return pulumi.get(self, "private_application_id")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> builtins.str:
        """
        The date and time the private application package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-27T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter
    def version(self) -> builtins.str:
        """
        The package version.
        """
        return pulumi.get(self, "version")


@pulumi.output_type
class GetPrivateApplicationsFilterResult(dict):
    def __init__(__self__, *,
                 name: builtins.str,
                 values: Sequence[builtins.str],
                 regex: Optional[builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> builtins.str:
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def values(self) -> Sequence[builtins.str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[builtins.bool]:
        return pulumi.get(self, "regex")


@pulumi.output_type
class GetPrivateApplicationsPrivateApplicationCollectionResult(dict):
    def __init__(__self__, *,
                 items: Sequence['outputs.GetPrivateApplicationsPrivateApplicationCollectionItemResult']):
        pulumi.set(__self__, "items", items)

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetPrivateApplicationsPrivateApplicationCollectionItemResult']:
        return pulumi.get(self, "items")


@pulumi.output_type
class GetPrivateApplicationsPrivateApplicationCollectionItemResult(dict):
    def __init__(__self__, *,
                 compartment_id: builtins.str,
                 defined_tags: Mapping[str, builtins.str],
                 display_name: builtins.str,
                 freeform_tags: Mapping[str, builtins.str],
                 id: builtins.str,
                 logo_file_base64encoded: builtins.str,
                 logos: Sequence['outputs.GetPrivateApplicationsPrivateApplicationCollectionItemLogoResult'],
                 long_description: builtins.str,
                 package_details: Sequence['outputs.GetPrivateApplicationsPrivateApplicationCollectionItemPackageDetailResult'],
                 package_type: builtins.str,
                 short_description: builtins.str,
                 state: builtins.str,
                 time_created: builtins.str,
                 time_updated: builtins.str):
        """
        :param builtins.str compartment_id: The unique identifier for the compartment.
        :param Mapping[str, builtins.str] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param builtins.str display_name: Exact match name filter.
        :param Mapping[str, builtins.str] freeform_tags: Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param builtins.str id: The unique identifier for the private application in Marketplace.
        :param Sequence['GetPrivateApplicationsPrivateApplicationCollectionItemLogoArgs'] logos: The model for uploaded binary data, like logos and images.
        :param builtins.str long_description: A long description of the private application.
        :param builtins.str package_type: Type of packages within this private application.
        :param builtins.str short_description: A short description of the private application.
        :param builtins.str state: The lifecycle state of the private application.
        :param builtins.str time_created: The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
        :param builtins.str time_updated: The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "logo_file_base64encoded", logo_file_base64encoded)
        pulumi.set(__self__, "logos", logos)
        pulumi.set(__self__, "long_description", long_description)
        pulumi.set(__self__, "package_details", package_details)
        pulumi.set(__self__, "package_type", package_type)
        pulumi.set(__self__, "short_description", short_description)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> builtins.str:
        """
        The unique identifier for the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> builtins.str:
        """
        Exact match name filter.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, builtins.str]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> builtins.str:
        """
        The unique identifier for the private application in Marketplace.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="logoFileBase64encoded")
    def logo_file_base64encoded(self) -> builtins.str:
        return pulumi.get(self, "logo_file_base64encoded")

    @property
    @pulumi.getter
    def logos(self) -> Sequence['outputs.GetPrivateApplicationsPrivateApplicationCollectionItemLogoResult']:
        """
        The model for uploaded binary data, like logos and images.
        """
        return pulumi.get(self, "logos")

    @property
    @pulumi.getter(name="longDescription")
    def long_description(self) -> builtins.str:
        """
        A long description of the private application.
        """
        return pulumi.get(self, "long_description")

    @property
    @pulumi.getter(name="packageDetails")
    def package_details(self) -> Sequence['outputs.GetPrivateApplicationsPrivateApplicationCollectionItemPackageDetailResult']:
        return pulumi.get(self, "package_details")

    @property
    @pulumi.getter(name="packageType")
    def package_type(self) -> builtins.str:
        """
        Type of packages within this private application.
        """
        return pulumi.get(self, "package_type")

    @property
    @pulumi.getter(name="shortDescription")
    def short_description(self) -> builtins.str:
        """
        A short description of the private application.
        """
        return pulumi.get(self, "short_description")

    @property
    @pulumi.getter
    def state(self) -> builtins.str:
        """
        The lifecycle state of the private application.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> builtins.str:
        """
        The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> builtins.str:
        """
        The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
        """
        return pulumi.get(self, "time_updated")


@pulumi.output_type
class GetPrivateApplicationsPrivateApplicationCollectionItemLogoResult(dict):
    def __init__(__self__, *,
                 content_url: builtins.str,
                 display_name: builtins.str,
                 mime_type: builtins.str):
        """
        :param builtins.str content_url: The content URL of the uploaded data.
        :param builtins.str display_name: Exact match name filter.
        :param builtins.str mime_type: The MIME type of the uploaded data.
        """
        pulumi.set(__self__, "content_url", content_url)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "mime_type", mime_type)

    @property
    @pulumi.getter(name="contentUrl")
    def content_url(self) -> builtins.str:
        """
        The content URL of the uploaded data.
        """
        return pulumi.get(self, "content_url")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> builtins.str:
        """
        Exact match name filter.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="mimeType")
    def mime_type(self) -> builtins.str:
        """
        The MIME type of the uploaded data.
        """
        return pulumi.get(self, "mime_type")


@pulumi.output_type
class GetPrivateApplicationsPrivateApplicationCollectionItemPackageDetailResult(dict):
    def __init__(__self__, *,
                 package_type: builtins.str,
                 version: builtins.str,
                 zip_file_base64encoded: builtins.str):
        """
        :param builtins.str package_type: Type of packages within this private application.
        """
        pulumi.set(__self__, "package_type", package_type)
        pulumi.set(__self__, "version", version)
        pulumi.set(__self__, "zip_file_base64encoded", zip_file_base64encoded)

    @property
    @pulumi.getter(name="packageType")
    def package_type(self) -> builtins.str:
        """
        Type of packages within this private application.
        """
        return pulumi.get(self, "package_type")

    @property
    @pulumi.getter
    def version(self) -> builtins.str:
        return pulumi.get(self, "version")

    @property
    @pulumi.getter(name="zipFileBase64encoded")
    def zip_file_base64encoded(self) -> builtins.str:
        return pulumi.get(self, "zip_file_base64encoded")


@pulumi.output_type
class GetServiceCatalogAssociationsFilterResult(dict):
    def __init__(__self__, *,
                 name: builtins.str,
                 values: Sequence[builtins.str],
                 regex: Optional[builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> builtins.str:
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def values(self) -> Sequence[builtins.str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[builtins.bool]:
        return pulumi.get(self, "regex")


@pulumi.output_type
class GetServiceCatalogAssociationsServiceCatalogAssociationCollectionResult(dict):
    def __init__(__self__, *,
                 items: Sequence['outputs.GetServiceCatalogAssociationsServiceCatalogAssociationCollectionItemResult']):
        pulumi.set(__self__, "items", items)

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetServiceCatalogAssociationsServiceCatalogAssociationCollectionItemResult']:
        return pulumi.get(self, "items")


@pulumi.output_type
class GetServiceCatalogAssociationsServiceCatalogAssociationCollectionItemResult(dict):
    def __init__(__self__, *,
                 entity_id: builtins.str,
                 entity_type: builtins.str,
                 id: builtins.str,
                 service_catalog_id: builtins.str,
                 time_created: builtins.str):
        """
        :param builtins.str entity_id: The unique identifier of the entity associated with service catalog.
        :param builtins.str entity_type: The type of the application in the service catalog.
        :param builtins.str id: Identifier of the association.
        :param builtins.str service_catalog_id: The unique identifier for the service catalog.
        :param builtins.str time_created: Timestamp of when the resource was associated with service catalog.
        """
        pulumi.set(__self__, "entity_id", entity_id)
        pulumi.set(__self__, "entity_type", entity_type)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "service_catalog_id", service_catalog_id)
        pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="entityId")
    def entity_id(self) -> builtins.str:
        """
        The unique identifier of the entity associated with service catalog.
        """
        return pulumi.get(self, "entity_id")

    @property
    @pulumi.getter(name="entityType")
    def entity_type(self) -> builtins.str:
        """
        The type of the application in the service catalog.
        """
        return pulumi.get(self, "entity_type")

    @property
    @pulumi.getter
    def id(self) -> builtins.str:
        """
        Identifier of the association.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="serviceCatalogId")
    def service_catalog_id(self) -> builtins.str:
        """
        The unique identifier for the service catalog.
        """
        return pulumi.get(self, "service_catalog_id")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> builtins.str:
        """
        Timestamp of when the resource was associated with service catalog.
        """
        return pulumi.get(self, "time_created")


@pulumi.output_type
class GetServiceCatalogsFilterResult(dict):
    def __init__(__self__, *,
                 name: builtins.str,
                 values: Sequence[builtins.str],
                 regex: Optional[builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> builtins.str:
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def values(self) -> Sequence[builtins.str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[builtins.bool]:
        return pulumi.get(self, "regex")


@pulumi.output_type
class GetServiceCatalogsServiceCatalogCollectionResult(dict):
    def __init__(__self__, *,
                 items: Sequence['outputs.GetServiceCatalogsServiceCatalogCollectionItemResult']):
        pulumi.set(__self__, "items", items)

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetServiceCatalogsServiceCatalogCollectionItemResult']:
        return pulumi.get(self, "items")


@pulumi.output_type
class GetServiceCatalogsServiceCatalogCollectionItemResult(dict):
    def __init__(__self__, *,
                 compartment_id: builtins.str,
                 defined_tags: Mapping[str, builtins.str],
                 display_name: builtins.str,
                 freeform_tags: Mapping[str, builtins.str],
                 id: builtins.str,
                 state: builtins.str,
                 time_created: builtins.str,
                 time_updated: builtins.str):
        """
        :param builtins.str compartment_id: The unique identifier for the compartment.
        :param Mapping[str, builtins.str] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param builtins.str display_name: Exact match name filter.
        :param Mapping[str, builtins.str] freeform_tags: Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param builtins.str id: The unique identifier for the Service catalog.
        :param builtins.str state: The lifecycle state of the service catalog.
        :param builtins.str time_created: The date and time the service catalog was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
        :param builtins.str time_updated: The date and time the service catalog was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> builtins.str:
        """
        The unique identifier for the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> builtins.str:
        """
        Exact match name filter.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, builtins.str]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> builtins.str:
        """
        The unique identifier for the Service catalog.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def state(self) -> builtins.str:
        """
        The lifecycle state of the service catalog.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> builtins.str:
        """
        The date and time the service catalog was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> builtins.str:
        """
        The date and time the service catalog was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
        """
        return pulumi.get(self, "time_updated")


