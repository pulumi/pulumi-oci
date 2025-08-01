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

__all__ = [
    'PublicationIconArgs',
    'PublicationIconArgsDict',
    'PublicationPackageDetailsArgs',
    'PublicationPackageDetailsArgsDict',
    'PublicationPackageDetailsEulaArgs',
    'PublicationPackageDetailsEulaArgsDict',
    'PublicationPackageDetailsOperatingSystemArgs',
    'PublicationPackageDetailsOperatingSystemArgsDict',
    'PublicationSupportContactArgs',
    'PublicationSupportContactArgsDict',
    'PublicationSupportedOperatingSystemArgs',
    'PublicationSupportedOperatingSystemArgsDict',
    'GetAcceptedAgreementsFilterArgs',
    'GetAcceptedAgreementsFilterArgsDict',
    'GetCategoriesFilterArgs',
    'GetCategoriesFilterArgsDict',
    'GetListingPackageAgreementsFilterArgs',
    'GetListingPackageAgreementsFilterArgsDict',
    'GetListingPackagesFilterArgs',
    'GetListingPackagesFilterArgsDict',
    'GetListingTaxesFilterArgs',
    'GetListingTaxesFilterArgsDict',
    'GetListingsFilterArgs',
    'GetListingsFilterArgsDict',
    'GetPublicationPackagesFilterArgs',
    'GetPublicationPackagesFilterArgsDict',
    'GetPublicationsFilterArgs',
    'GetPublicationsFilterArgsDict',
    'GetPublishersFilterArgs',
    'GetPublishersFilterArgsDict',
]

MYPY = False

if not MYPY:
    class PublicationIconArgsDict(TypedDict):
        content_url: NotRequired[pulumi.Input[_builtins.str]]
        """
        The content URL of the upload data.
        """
        file_extension: NotRequired[pulumi.Input[_builtins.str]]
        """
        The file extension of the upload data.
        """
        mime_type: NotRequired[pulumi.Input[_builtins.str]]
        """
        The MIME type of the upload data.
        """
        name: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The name of the publication, which is also used in the listing.
        """
elif False:
    PublicationIconArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class PublicationIconArgs:
    def __init__(__self__, *,
                 content_url: Optional[pulumi.Input[_builtins.str]] = None,
                 file_extension: Optional[pulumi.Input[_builtins.str]] = None,
                 mime_type: Optional[pulumi.Input[_builtins.str]] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input[_builtins.str] content_url: The content URL of the upload data.
        :param pulumi.Input[_builtins.str] file_extension: The file extension of the upload data.
        :param pulumi.Input[_builtins.str] mime_type: The MIME type of the upload data.
        :param pulumi.Input[_builtins.str] name: (Updatable) The name of the publication, which is also used in the listing.
        """
        if content_url is not None:
            pulumi.set(__self__, "content_url", content_url)
        if file_extension is not None:
            pulumi.set(__self__, "file_extension", file_extension)
        if mime_type is not None:
            pulumi.set(__self__, "mime_type", mime_type)
        if name is not None:
            pulumi.set(__self__, "name", name)

    @_builtins.property
    @pulumi.getter(name="contentUrl")
    def content_url(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The content URL of the upload data.
        """
        return pulumi.get(self, "content_url")

    @content_url.setter
    def content_url(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "content_url", value)

    @_builtins.property
    @pulumi.getter(name="fileExtension")
    def file_extension(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The file extension of the upload data.
        """
        return pulumi.get(self, "file_extension")

    @file_extension.setter
    def file_extension(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "file_extension", value)

    @_builtins.property
    @pulumi.getter(name="mimeType")
    def mime_type(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The MIME type of the upload data.
        """
        return pulumi.get(self, "mime_type")

    @mime_type.setter
    def mime_type(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "mime_type", value)

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The name of the publication, which is also used in the listing.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "name", value)


if not MYPY:
    class PublicationPackageDetailsArgsDict(TypedDict):
        eulas: pulumi.Input[Sequence[pulumi.Input['PublicationPackageDetailsEulaArgsDict']]]
        """
        The end user license agreeement (EULA) that consumers of this listing must accept.
        """
        operating_system: pulumi.Input['PublicationPackageDetailsOperatingSystemArgsDict']
        """
        The operating system used by the listing.
        """
        package_type: pulumi.Input[_builtins.str]
        """
        The package's type.
        """
        package_version: pulumi.Input[_builtins.str]
        """
        The package version.
        """
        image_id: NotRequired[pulumi.Input[_builtins.str]]
        """
        The unique identifier for the base image of the publication.
        """
elif False:
    PublicationPackageDetailsArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class PublicationPackageDetailsArgs:
    def __init__(__self__, *,
                 eulas: pulumi.Input[Sequence[pulumi.Input['PublicationPackageDetailsEulaArgs']]],
                 operating_system: pulumi.Input['PublicationPackageDetailsOperatingSystemArgs'],
                 package_type: pulumi.Input[_builtins.str],
                 package_version: pulumi.Input[_builtins.str],
                 image_id: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input[Sequence[pulumi.Input['PublicationPackageDetailsEulaArgs']]] eulas: The end user license agreeement (EULA) that consumers of this listing must accept.
        :param pulumi.Input['PublicationPackageDetailsOperatingSystemArgs'] operating_system: The operating system used by the listing.
        :param pulumi.Input[_builtins.str] package_type: The package's type.
        :param pulumi.Input[_builtins.str] package_version: The package version.
        :param pulumi.Input[_builtins.str] image_id: The unique identifier for the base image of the publication.
        """
        pulumi.set(__self__, "eulas", eulas)
        pulumi.set(__self__, "operating_system", operating_system)
        pulumi.set(__self__, "package_type", package_type)
        pulumi.set(__self__, "package_version", package_version)
        if image_id is not None:
            pulumi.set(__self__, "image_id", image_id)

    @_builtins.property
    @pulumi.getter
    def eulas(self) -> pulumi.Input[Sequence[pulumi.Input['PublicationPackageDetailsEulaArgs']]]:
        """
        The end user license agreeement (EULA) that consumers of this listing must accept.
        """
        return pulumi.get(self, "eulas")

    @eulas.setter
    def eulas(self, value: pulumi.Input[Sequence[pulumi.Input['PublicationPackageDetailsEulaArgs']]]):
        pulumi.set(self, "eulas", value)

    @_builtins.property
    @pulumi.getter(name="operatingSystem")
    def operating_system(self) -> pulumi.Input['PublicationPackageDetailsOperatingSystemArgs']:
        """
        The operating system used by the listing.
        """
        return pulumi.get(self, "operating_system")

    @operating_system.setter
    def operating_system(self, value: pulumi.Input['PublicationPackageDetailsOperatingSystemArgs']):
        pulumi.set(self, "operating_system", value)

    @_builtins.property
    @pulumi.getter(name="packageType")
    def package_type(self) -> pulumi.Input[_builtins.str]:
        """
        The package's type.
        """
        return pulumi.get(self, "package_type")

    @package_type.setter
    def package_type(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "package_type", value)

    @_builtins.property
    @pulumi.getter(name="packageVersion")
    def package_version(self) -> pulumi.Input[_builtins.str]:
        """
        The package version.
        """
        return pulumi.get(self, "package_version")

    @package_version.setter
    def package_version(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "package_version", value)

    @_builtins.property
    @pulumi.getter(name="imageId")
    def image_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The unique identifier for the base image of the publication.
        """
        return pulumi.get(self, "image_id")

    @image_id.setter
    def image_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "image_id", value)


if not MYPY:
    class PublicationPackageDetailsEulaArgsDict(TypedDict):
        eula_type: pulumi.Input[_builtins.str]
        """
        The end user license agreement's type.
        """
        license_text: NotRequired[pulumi.Input[_builtins.str]]
        """
        The text of the end user license agreement.
        """
elif False:
    PublicationPackageDetailsEulaArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class PublicationPackageDetailsEulaArgs:
    def __init__(__self__, *,
                 eula_type: pulumi.Input[_builtins.str],
                 license_text: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input[_builtins.str] eula_type: The end user license agreement's type.
        :param pulumi.Input[_builtins.str] license_text: The text of the end user license agreement.
        """
        pulumi.set(__self__, "eula_type", eula_type)
        if license_text is not None:
            pulumi.set(__self__, "license_text", license_text)

    @_builtins.property
    @pulumi.getter(name="eulaType")
    def eula_type(self) -> pulumi.Input[_builtins.str]:
        """
        The end user license agreement's type.
        """
        return pulumi.get(self, "eula_type")

    @eula_type.setter
    def eula_type(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "eula_type", value)

    @_builtins.property
    @pulumi.getter(name="licenseText")
    def license_text(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The text of the end user license agreement.
        """
        return pulumi.get(self, "license_text")

    @license_text.setter
    def license_text(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "license_text", value)


if not MYPY:
    class PublicationPackageDetailsOperatingSystemArgsDict(TypedDict):
        name: NotRequired[pulumi.Input[_builtins.str]]
        """
        The name of the operating system.
        """
elif False:
    PublicationPackageDetailsOperatingSystemArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class PublicationPackageDetailsOperatingSystemArgs:
    def __init__(__self__, *,
                 name: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input[_builtins.str] name: The name of the operating system.
        """
        if name is not None:
            pulumi.set(__self__, "name", name)

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The name of the operating system.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "name", value)


if not MYPY:
    class PublicationSupportContactArgsDict(TypedDict):
        email: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The email of the contact.
        """
        name: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The name of the contact.
        """
        phone: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The phone number of the contact.
        """
        subject: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The email subject line to use when contacting support.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
elif False:
    PublicationSupportContactArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class PublicationSupportContactArgs:
    def __init__(__self__, *,
                 email: Optional[pulumi.Input[_builtins.str]] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 phone: Optional[pulumi.Input[_builtins.str]] = None,
                 subject: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input[_builtins.str] email: (Updatable) The email of the contact.
        :param pulumi.Input[_builtins.str] name: (Updatable) The name of the contact.
        :param pulumi.Input[_builtins.str] phone: (Updatable) The phone number of the contact.
        :param pulumi.Input[_builtins.str] subject: (Updatable) The email subject line to use when contacting support.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if email is not None:
            pulumi.set(__self__, "email", email)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if phone is not None:
            pulumi.set(__self__, "phone", phone)
        if subject is not None:
            pulumi.set(__self__, "subject", subject)

    @_builtins.property
    @pulumi.getter
    def email(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The email of the contact.
        """
        return pulumi.get(self, "email")

    @email.setter
    def email(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "email", value)

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The name of the contact.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def phone(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The phone number of the contact.
        """
        return pulumi.get(self, "phone")

    @phone.setter
    def phone(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "phone", value)

    @_builtins.property
    @pulumi.getter
    def subject(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The email subject line to use when contacting support.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "subject")

    @subject.setter
    def subject(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "subject", value)


if not MYPY:
    class PublicationSupportedOperatingSystemArgsDict(TypedDict):
        name: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The name of the publication, which is also used in the listing.
        """
elif False:
    PublicationSupportedOperatingSystemArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class PublicationSupportedOperatingSystemArgs:
    def __init__(__self__, *,
                 name: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input[_builtins.str] name: (Updatable) The name of the publication, which is also used in the listing.
        """
        if name is not None:
            pulumi.set(__self__, "name", name)

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The name of the publication, which is also used in the listing.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "name", value)


if not MYPY:
    class GetAcceptedAgreementsFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetAcceptedAgreementsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetAcceptedAgreementsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetCategoriesFilterArgsDict(TypedDict):
        name: _builtins.str
        """
        Name of the product category.
        """
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetCategoriesFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetCategoriesFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        """
        :param _builtins.str name: Name of the product category.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        Name of the product category.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetListingPackageAgreementsFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetListingPackageAgreementsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetListingPackageAgreementsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetListingPackagesFilterArgsDict(TypedDict):
        name: _builtins.str
        """
        The name of the variable.
        """
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetListingPackagesFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetListingPackagesFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        """
        :param _builtins.str name: The name of the variable.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name of the variable.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetListingTaxesFilterArgsDict(TypedDict):
        name: _builtins.str
        """
        Name of the tax code.
        """
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetListingTaxesFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetListingTaxesFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        """
        :param _builtins.str name: Name of the tax code.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        Name of the tax code.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetListingsFilterArgsDict(TypedDict):
        name: _builtins.str
        """
        The name of the listing.
        """
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetListingsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetListingsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        """
        :param _builtins.str name: The name of the listing.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name of the listing.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetPublicationPackagesFilterArgsDict(TypedDict):
        name: _builtins.str
        """
        The name of the variable.
        """
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetPublicationPackagesFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetPublicationPackagesFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        """
        :param _builtins.str name: The name of the variable.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name of the variable.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetPublicationsFilterArgsDict(TypedDict):
        name: _builtins.str
        """
        The name of the publication.
        """
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetPublicationsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetPublicationsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        """
        :param _builtins.str name: The name of the publication.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name of the publication.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetPublishersFilterArgsDict(TypedDict):
        name: _builtins.str
        """
        The name of the publisher.
        """
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetPublishersFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetPublishersFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        """
        :param _builtins.str name: The name of the publisher.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name of the publisher.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


