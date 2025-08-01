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
    'GetAppCatalogListingResult',
    'AwaitableGetAppCatalogListingResult',
    'get_app_catalog_listing',
    'get_app_catalog_listing_output',
]

@pulumi.output_type
class GetAppCatalogListingResult:
    """
    A collection of values returned by getAppCatalogListing.
    """
    def __init__(__self__, contact_url=None, description=None, display_name=None, id=None, listing_id=None, publisher_logo_url=None, publisher_name=None, summary=None, time_published=None):
        if contact_url and not isinstance(contact_url, str):
            raise TypeError("Expected argument 'contact_url' to be a str")
        pulumi.set(__self__, "contact_url", contact_url)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if listing_id and not isinstance(listing_id, str):
            raise TypeError("Expected argument 'listing_id' to be a str")
        pulumi.set(__self__, "listing_id", listing_id)
        if publisher_logo_url and not isinstance(publisher_logo_url, str):
            raise TypeError("Expected argument 'publisher_logo_url' to be a str")
        pulumi.set(__self__, "publisher_logo_url", publisher_logo_url)
        if publisher_name and not isinstance(publisher_name, str):
            raise TypeError("Expected argument 'publisher_name' to be a str")
        pulumi.set(__self__, "publisher_name", publisher_name)
        if summary and not isinstance(summary, str):
            raise TypeError("Expected argument 'summary' to be a str")
        pulumi.set(__self__, "summary", summary)
        if time_published and not isinstance(time_published, str):
            raise TypeError("Expected argument 'time_published' to be a str")
        pulumi.set(__self__, "time_published", time_published)

    @_builtins.property
    @pulumi.getter(name="contactUrl")
    def contact_url(self) -> _builtins.str:
        """
        Listing's contact URL.
        """
        return pulumi.get(self, "contact_url")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        Description of the listing.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="listingId")
    def listing_id(self) -> _builtins.str:
        """
        the region free ocid of the listing resource.
        """
        return pulumi.get(self, "listing_id")

    @_builtins.property
    @pulumi.getter(name="publisherLogoUrl")
    def publisher_logo_url(self) -> _builtins.str:
        """
        Publisher's logo URL.
        """
        return pulumi.get(self, "publisher_logo_url")

    @_builtins.property
    @pulumi.getter(name="publisherName")
    def publisher_name(self) -> _builtins.str:
        """
        The name of the publisher who published this listing.
        """
        return pulumi.get(self, "publisher_name")

    @_builtins.property
    @pulumi.getter
    def summary(self) -> _builtins.str:
        """
        The short summary for the listing.
        """
        return pulumi.get(self, "summary")

    @_builtins.property
    @pulumi.getter(name="timePublished")
    def time_published(self) -> _builtins.str:
        """
        Date and time the listing was published, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
        """
        return pulumi.get(self, "time_published")


class AwaitableGetAppCatalogListingResult(GetAppCatalogListingResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAppCatalogListingResult(
            contact_url=self.contact_url,
            description=self.description,
            display_name=self.display_name,
            id=self.id,
            listing_id=self.listing_id,
            publisher_logo_url=self.publisher_logo_url,
            publisher_name=self.publisher_name,
            summary=self.summary,
            time_published=self.time_published)


def get_app_catalog_listing(listing_id: Optional[_builtins.str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAppCatalogListingResult:
    """
    This data source provides details about a specific App Catalog Listing resource in Oracle Cloud Infrastructure Core service.

    Gets the specified listing.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_app_catalog_listing = oci.Core.get_app_catalog_listing(listing_id=test_listing["id"])
    ```


    :param _builtins.str listing_id: The OCID of the listing.
    """
    __args__ = dict()
    __args__['listingId'] = listing_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getAppCatalogListing:getAppCatalogListing', __args__, opts=opts, typ=GetAppCatalogListingResult).value

    return AwaitableGetAppCatalogListingResult(
        contact_url=pulumi.get(__ret__, 'contact_url'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        id=pulumi.get(__ret__, 'id'),
        listing_id=pulumi.get(__ret__, 'listing_id'),
        publisher_logo_url=pulumi.get(__ret__, 'publisher_logo_url'),
        publisher_name=pulumi.get(__ret__, 'publisher_name'),
        summary=pulumi.get(__ret__, 'summary'),
        time_published=pulumi.get(__ret__, 'time_published'))
def get_app_catalog_listing_output(listing_id: Optional[pulumi.Input[_builtins.str]] = None,
                                   opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetAppCatalogListingResult]:
    """
    This data source provides details about a specific App Catalog Listing resource in Oracle Cloud Infrastructure Core service.

    Gets the specified listing.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_app_catalog_listing = oci.Core.get_app_catalog_listing(listing_id=test_listing["id"])
    ```


    :param _builtins.str listing_id: The OCID of the listing.
    """
    __args__ = dict()
    __args__['listingId'] = listing_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getAppCatalogListing:getAppCatalogListing', __args__, opts=opts, typ=GetAppCatalogListingResult)
    return __ret__.apply(lambda __response__: GetAppCatalogListingResult(
        contact_url=pulumi.get(__response__, 'contact_url'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        id=pulumi.get(__response__, 'id'),
        listing_id=pulumi.get(__response__, 'listing_id'),
        publisher_logo_url=pulumi.get(__response__, 'publisher_logo_url'),
        publisher_name=pulumi.get(__response__, 'publisher_name'),
        summary=pulumi.get(__response__, 'summary'),
        time_published=pulumi.get(__response__, 'time_published')))
