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

__all__ = ['ListingResourceVersionAgreementArgs', 'ListingResourceVersionAgreement']

@pulumi.input_type
class ListingResourceVersionAgreementArgs:
    def __init__(__self__, *,
                 listing_id: pulumi.Input[_builtins.str],
                 listing_resource_version: pulumi.Input[_builtins.str]):
        """
        The set of arguments for constructing a ListingResourceVersionAgreement resource.
        :param pulumi.Input[_builtins.str] listing_id: The OCID of the listing.
        :param pulumi.Input[_builtins.str] listing_resource_version: Listing Resource Version.
        """
        pulumi.set(__self__, "listing_id", listing_id)
        pulumi.set(__self__, "listing_resource_version", listing_resource_version)

    @_builtins.property
    @pulumi.getter(name="listingId")
    def listing_id(self) -> pulumi.Input[_builtins.str]:
        """
        The OCID of the listing.
        """
        return pulumi.get(self, "listing_id")

    @listing_id.setter
    def listing_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "listing_id", value)

    @_builtins.property
    @pulumi.getter(name="listingResourceVersion")
    def listing_resource_version(self) -> pulumi.Input[_builtins.str]:
        """
        Listing Resource Version.
        """
        return pulumi.get(self, "listing_resource_version")

    @listing_resource_version.setter
    def listing_resource_version(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "listing_resource_version", value)


@pulumi.input_type
class _ListingResourceVersionAgreementState:
    def __init__(__self__, *,
                 eula_link: Optional[pulumi.Input[_builtins.str]] = None,
                 listing_id: Optional[pulumi.Input[_builtins.str]] = None,
                 listing_resource_version: Optional[pulumi.Input[_builtins.str]] = None,
                 oracle_terms_of_use_link: Optional[pulumi.Input[_builtins.str]] = None,
                 signature: Optional[pulumi.Input[_builtins.str]] = None,
                 time_retrieved: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering ListingResourceVersionAgreement resources.
        :param pulumi.Input[_builtins.str] eula_link: EULA link
        :param pulumi.Input[_builtins.str] listing_id: The OCID of the listing.
        :param pulumi.Input[_builtins.str] listing_resource_version: Listing Resource Version.
        :param pulumi.Input[_builtins.str] oracle_terms_of_use_link: Oracle TOU link
        :param pulumi.Input[_builtins.str] signature: A generated signature for this agreement retrieval operation which should be used in the create subscription call.
        :param pulumi.Input[_builtins.str] time_retrieved: Date and time the agreements were retrieved, in RFC3339 format. Example: `2018-03-20T12:32:53.532Z`
        """
        if eula_link is not None:
            pulumi.set(__self__, "eula_link", eula_link)
        if listing_id is not None:
            pulumi.set(__self__, "listing_id", listing_id)
        if listing_resource_version is not None:
            pulumi.set(__self__, "listing_resource_version", listing_resource_version)
        if oracle_terms_of_use_link is not None:
            pulumi.set(__self__, "oracle_terms_of_use_link", oracle_terms_of_use_link)
        if signature is not None:
            pulumi.set(__self__, "signature", signature)
        if time_retrieved is not None:
            pulumi.set(__self__, "time_retrieved", time_retrieved)

    @_builtins.property
    @pulumi.getter(name="eulaLink")
    def eula_link(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        EULA link
        """
        return pulumi.get(self, "eula_link")

    @eula_link.setter
    def eula_link(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "eula_link", value)

    @_builtins.property
    @pulumi.getter(name="listingId")
    def listing_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The OCID of the listing.
        """
        return pulumi.get(self, "listing_id")

    @listing_id.setter
    def listing_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "listing_id", value)

    @_builtins.property
    @pulumi.getter(name="listingResourceVersion")
    def listing_resource_version(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Listing Resource Version.
        """
        return pulumi.get(self, "listing_resource_version")

    @listing_resource_version.setter
    def listing_resource_version(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "listing_resource_version", value)

    @_builtins.property
    @pulumi.getter(name="oracleTermsOfUseLink")
    def oracle_terms_of_use_link(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Oracle TOU link
        """
        return pulumi.get(self, "oracle_terms_of_use_link")

    @oracle_terms_of_use_link.setter
    def oracle_terms_of_use_link(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "oracle_terms_of_use_link", value)

    @_builtins.property
    @pulumi.getter
    def signature(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        A generated signature for this agreement retrieval operation which should be used in the create subscription call.
        """
        return pulumi.get(self, "signature")

    @signature.setter
    def signature(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "signature", value)

    @_builtins.property
    @pulumi.getter(name="timeRetrieved")
    def time_retrieved(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Date and time the agreements were retrieved, in RFC3339 format. Example: `2018-03-20T12:32:53.532Z`
        """
        return pulumi.get(self, "time_retrieved")

    @time_retrieved.setter
    def time_retrieved(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_retrieved", value)


@pulumi.type_token("oci:Core/listingResourceVersionAgreement:ListingResourceVersionAgreement")
class ListingResourceVersionAgreement(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 listing_id: Optional[pulumi.Input[_builtins.str]] = None,
                 listing_resource_version: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        The `Core.AppCatalogListingResourceVersionAgreement` resource creates AppCatalogListingResourceVersionAgreement for a particular resource version of a listing.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_app_catalog_listing_resource_version_agreement = oci.core.AppCatalogListingResourceVersionAgreement("test_app_catalog_listing_resource_version_agreement",
            listing_id=test_listing["id"],
            listing_resource_version=app_catalog_listing_resource_version_agreement_listing_resource_version)
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] listing_id: The OCID of the listing.
        :param pulumi.Input[_builtins.str] listing_resource_version: Listing Resource Version.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ListingResourceVersionAgreementArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        The `Core.AppCatalogListingResourceVersionAgreement` resource creates AppCatalogListingResourceVersionAgreement for a particular resource version of a listing.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_app_catalog_listing_resource_version_agreement = oci.core.AppCatalogListingResourceVersionAgreement("test_app_catalog_listing_resource_version_agreement",
            listing_id=test_listing["id"],
            listing_resource_version=app_catalog_listing_resource_version_agreement_listing_resource_version)
        ```

        :param str resource_name: The name of the resource.
        :param ListingResourceVersionAgreementArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ListingResourceVersionAgreementArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 listing_id: Optional[pulumi.Input[_builtins.str]] = None,
                 listing_resource_version: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = ListingResourceVersionAgreementArgs.__new__(ListingResourceVersionAgreementArgs)

            if listing_id is None and not opts.urn:
                raise TypeError("Missing required property 'listing_id'")
            __props__.__dict__["listing_id"] = listing_id
            if listing_resource_version is None and not opts.urn:
                raise TypeError("Missing required property 'listing_resource_version'")
            __props__.__dict__["listing_resource_version"] = listing_resource_version
            __props__.__dict__["eula_link"] = None
            __props__.__dict__["oracle_terms_of_use_link"] = None
            __props__.__dict__["signature"] = None
            __props__.__dict__["time_retrieved"] = None
        super(ListingResourceVersionAgreement, __self__).__init__(
            'oci:Core/listingResourceVersionAgreement:ListingResourceVersionAgreement',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            eula_link: Optional[pulumi.Input[_builtins.str]] = None,
            listing_id: Optional[pulumi.Input[_builtins.str]] = None,
            listing_resource_version: Optional[pulumi.Input[_builtins.str]] = None,
            oracle_terms_of_use_link: Optional[pulumi.Input[_builtins.str]] = None,
            signature: Optional[pulumi.Input[_builtins.str]] = None,
            time_retrieved: Optional[pulumi.Input[_builtins.str]] = None) -> 'ListingResourceVersionAgreement':
        """
        Get an existing ListingResourceVersionAgreement resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] eula_link: EULA link
        :param pulumi.Input[_builtins.str] listing_id: The OCID of the listing.
        :param pulumi.Input[_builtins.str] listing_resource_version: Listing Resource Version.
        :param pulumi.Input[_builtins.str] oracle_terms_of_use_link: Oracle TOU link
        :param pulumi.Input[_builtins.str] signature: A generated signature for this agreement retrieval operation which should be used in the create subscription call.
        :param pulumi.Input[_builtins.str] time_retrieved: Date and time the agreements were retrieved, in RFC3339 format. Example: `2018-03-20T12:32:53.532Z`
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ListingResourceVersionAgreementState.__new__(_ListingResourceVersionAgreementState)

        __props__.__dict__["eula_link"] = eula_link
        __props__.__dict__["listing_id"] = listing_id
        __props__.__dict__["listing_resource_version"] = listing_resource_version
        __props__.__dict__["oracle_terms_of_use_link"] = oracle_terms_of_use_link
        __props__.__dict__["signature"] = signature
        __props__.__dict__["time_retrieved"] = time_retrieved
        return ListingResourceVersionAgreement(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="eulaLink")
    def eula_link(self) -> pulumi.Output[_builtins.str]:
        """
        EULA link
        """
        return pulumi.get(self, "eula_link")

    @_builtins.property
    @pulumi.getter(name="listingId")
    def listing_id(self) -> pulumi.Output[_builtins.str]:
        """
        The OCID of the listing.
        """
        return pulumi.get(self, "listing_id")

    @_builtins.property
    @pulumi.getter(name="listingResourceVersion")
    def listing_resource_version(self) -> pulumi.Output[_builtins.str]:
        """
        Listing Resource Version.
        """
        return pulumi.get(self, "listing_resource_version")

    @_builtins.property
    @pulumi.getter(name="oracleTermsOfUseLink")
    def oracle_terms_of_use_link(self) -> pulumi.Output[_builtins.str]:
        """
        Oracle TOU link
        """
        return pulumi.get(self, "oracle_terms_of_use_link")

    @_builtins.property
    @pulumi.getter
    def signature(self) -> pulumi.Output[_builtins.str]:
        """
        A generated signature for this agreement retrieval operation which should be used in the create subscription call.
        """
        return pulumi.get(self, "signature")

    @_builtins.property
    @pulumi.getter(name="timeRetrieved")
    def time_retrieved(self) -> pulumi.Output[_builtins.str]:
        """
        Date and time the agreements were retrieved, in RFC3339 format. Example: `2018-03-20T12:32:53.532Z`
        """
        return pulumi.get(self, "time_retrieved")

