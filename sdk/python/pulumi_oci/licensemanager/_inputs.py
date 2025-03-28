# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

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

__all__ = [
    'ProductLicenseImageArgs',
    'ProductLicenseImageArgsDict',
    'GetLicenseRecordsFilterArgs',
    'GetLicenseRecordsFilterArgsDict',
    'GetProductLicensesFilterArgs',
    'GetProductLicensesFilterArgsDict',
]

MYPY = False

if not MYPY:
    class ProductLicenseImageArgsDict(TypedDict):
        listing_id: pulumi.Input[str]
        """
        (Updatable) Marketplace image listing ID.
        """
        package_version: pulumi.Input[str]
        """
        (Updatable) Image package version.
        """
        id: NotRequired[pulumi.Input[str]]
        """
        The image ID associated with the product license.
        """
        listing_name: NotRequired[pulumi.Input[str]]
        """
        The listing name associated with the product license.
        """
        publisher: NotRequired[pulumi.Input[str]]
        """
        The image publisher.
        """
elif False:
    ProductLicenseImageArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class ProductLicenseImageArgs:
    def __init__(__self__, *,
                 listing_id: pulumi.Input[str],
                 package_version: pulumi.Input[str],
                 id: Optional[pulumi.Input[str]] = None,
                 listing_name: Optional[pulumi.Input[str]] = None,
                 publisher: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] listing_id: (Updatable) Marketplace image listing ID.
        :param pulumi.Input[str] package_version: (Updatable) Image package version.
        :param pulumi.Input[str] id: The image ID associated with the product license.
        :param pulumi.Input[str] listing_name: The listing name associated with the product license.
        :param pulumi.Input[str] publisher: The image publisher.
        """
        pulumi.set(__self__, "listing_id", listing_id)
        pulumi.set(__self__, "package_version", package_version)
        if id is not None:
            pulumi.set(__self__, "id", id)
        if listing_name is not None:
            pulumi.set(__self__, "listing_name", listing_name)
        if publisher is not None:
            pulumi.set(__self__, "publisher", publisher)

    @property
    @pulumi.getter(name="listingId")
    def listing_id(self) -> pulumi.Input[str]:
        """
        (Updatable) Marketplace image listing ID.
        """
        return pulumi.get(self, "listing_id")

    @listing_id.setter
    def listing_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "listing_id", value)

    @property
    @pulumi.getter(name="packageVersion")
    def package_version(self) -> pulumi.Input[str]:
        """
        (Updatable) Image package version.
        """
        return pulumi.get(self, "package_version")

    @package_version.setter
    def package_version(self, value: pulumi.Input[str]):
        pulumi.set(self, "package_version", value)

    @property
    @pulumi.getter
    def id(self) -> Optional[pulumi.Input[str]]:
        """
        The image ID associated with the product license.
        """
        return pulumi.get(self, "id")

    @id.setter
    def id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "id", value)

    @property
    @pulumi.getter(name="listingName")
    def listing_name(self) -> Optional[pulumi.Input[str]]:
        """
        The listing name associated with the product license.
        """
        return pulumi.get(self, "listing_name")

    @listing_name.setter
    def listing_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "listing_name", value)

    @property
    @pulumi.getter
    def publisher(self) -> Optional[pulumi.Input[str]]:
        """
        The image publisher.
        """
        return pulumi.get(self, "publisher")

    @publisher.setter
    def publisher(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "publisher", value)


if not MYPY:
    class GetLicenseRecordsFilterArgsDict(TypedDict):
        name: str
        values: Sequence[str]
        regex: NotRequired[bool]
elif False:
    GetLicenseRecordsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetLicenseRecordsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetProductLicensesFilterArgsDict(TypedDict):
        name: str
        values: Sequence[str]
        regex: NotRequired[bool]
elif False:
    GetProductLicensesFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetProductLicensesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


