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

__all__ = ['ListingPackageAgreementArgs', 'ListingPackageAgreement']

@pulumi.input_type
class ListingPackageAgreementArgs:
    def __init__(__self__, *,
                 agreement_id: pulumi.Input[_builtins.str],
                 listing_id: pulumi.Input[_builtins.str],
                 package_version: pulumi.Input[_builtins.str],
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None):
        """
        The set of arguments for constructing a ListingPackageAgreement resource.
        :param pulumi.Input[_builtins.str] agreement_id: The unique identifier for the agreement.
        :param pulumi.Input[_builtins.str] listing_id: The unique identifier for the listing.
        :param pulumi.Input[_builtins.str] package_version: The version of the package. Package versions are unique within a listing.
        :param pulumi.Input[_builtins.str] compartment_id: The unique identifier for the compartment, required in gov regions.
        """
        pulumi.set(__self__, "agreement_id", agreement_id)
        pulumi.set(__self__, "listing_id", listing_id)
        pulumi.set(__self__, "package_version", package_version)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)

    @_builtins.property
    @pulumi.getter(name="agreementId")
    def agreement_id(self) -> pulumi.Input[_builtins.str]:
        """
        The unique identifier for the agreement.
        """
        return pulumi.get(self, "agreement_id")

    @agreement_id.setter
    def agreement_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "agreement_id", value)

    @_builtins.property
    @pulumi.getter(name="listingId")
    def listing_id(self) -> pulumi.Input[_builtins.str]:
        """
        The unique identifier for the listing.
        """
        return pulumi.get(self, "listing_id")

    @listing_id.setter
    def listing_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "listing_id", value)

    @_builtins.property
    @pulumi.getter(name="packageVersion")
    def package_version(self) -> pulumi.Input[_builtins.str]:
        """
        The version of the package. Package versions are unique within a listing.
        """
        return pulumi.get(self, "package_version")

    @package_version.setter
    def package_version(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "package_version", value)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The unique identifier for the compartment, required in gov regions.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "compartment_id", value)


@pulumi.input_type
class _ListingPackageAgreementState:
    def __init__(__self__, *,
                 agreement_id: Optional[pulumi.Input[_builtins.str]] = None,
                 author: Optional[pulumi.Input[_builtins.str]] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 content_url: Optional[pulumi.Input[_builtins.str]] = None,
                 listing_id: Optional[pulumi.Input[_builtins.str]] = None,
                 package_version: Optional[pulumi.Input[_builtins.str]] = None,
                 prompt: Optional[pulumi.Input[_builtins.str]] = None,
                 signature: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering ListingPackageAgreement resources.
        :param pulumi.Input[_builtins.str] agreement_id: The unique identifier for the agreement.
        :param pulumi.Input[_builtins.str] author: Who authored the agreement.
        :param pulumi.Input[_builtins.str] compartment_id: The unique identifier for the compartment, required in gov regions.
        :param pulumi.Input[_builtins.str] content_url: The content URL of the agreement.
        :param pulumi.Input[_builtins.str] listing_id: The unique identifier for the listing.
        :param pulumi.Input[_builtins.str] package_version: The version of the package. Package versions are unique within a listing.
        :param pulumi.Input[_builtins.str] prompt: Textual prompt to read and accept the agreement.
        :param pulumi.Input[_builtins.str] signature: A time-based signature that can be used to accept an agreement or remove a previously accepted agreement from the list that Marketplace checks before a deployment.
        """
        if agreement_id is not None:
            pulumi.set(__self__, "agreement_id", agreement_id)
        if author is not None:
            pulumi.set(__self__, "author", author)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if content_url is not None:
            pulumi.set(__self__, "content_url", content_url)
        if listing_id is not None:
            pulumi.set(__self__, "listing_id", listing_id)
        if package_version is not None:
            pulumi.set(__self__, "package_version", package_version)
        if prompt is not None:
            pulumi.set(__self__, "prompt", prompt)
        if signature is not None:
            pulumi.set(__self__, "signature", signature)

    @_builtins.property
    @pulumi.getter(name="agreementId")
    def agreement_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The unique identifier for the agreement.
        """
        return pulumi.get(self, "agreement_id")

    @agreement_id.setter
    def agreement_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "agreement_id", value)

    @_builtins.property
    @pulumi.getter
    def author(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Who authored the agreement.
        """
        return pulumi.get(self, "author")

    @author.setter
    def author(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "author", value)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The unique identifier for the compartment, required in gov regions.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="contentUrl")
    def content_url(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The content URL of the agreement.
        """
        return pulumi.get(self, "content_url")

    @content_url.setter
    def content_url(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "content_url", value)

    @_builtins.property
    @pulumi.getter(name="listingId")
    def listing_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The unique identifier for the listing.
        """
        return pulumi.get(self, "listing_id")

    @listing_id.setter
    def listing_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "listing_id", value)

    @_builtins.property
    @pulumi.getter(name="packageVersion")
    def package_version(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The version of the package. Package versions are unique within a listing.
        """
        return pulumi.get(self, "package_version")

    @package_version.setter
    def package_version(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "package_version", value)

    @_builtins.property
    @pulumi.getter
    def prompt(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Textual prompt to read and accept the agreement.
        """
        return pulumi.get(self, "prompt")

    @prompt.setter
    def prompt(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "prompt", value)

    @_builtins.property
    @pulumi.getter
    def signature(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        A time-based signature that can be used to accept an agreement or remove a previously accepted agreement from the list that Marketplace checks before a deployment.
        """
        return pulumi.get(self, "signature")

    @signature.setter
    def signature(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "signature", value)


@pulumi.type_token("oci:Marketplace/listingPackageAgreement:ListingPackageAgreement")
class ListingPackageAgreement(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 agreement_id: Optional[pulumi.Input[_builtins.str]] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 listing_id: Optional[pulumi.Input[_builtins.str]] = None,
                 package_version: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides details about a specific Listing Package Agreement resource in Oracle Cloud Infrastructure Marketplace service.

        This resource can be used to retrieve the time-based signature of terms of use agreement for a package that can be used to
        accept the agreement.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_listing_package_agreement = oci.marketplace.ListingPackageAgreement("test_listing_package_agreement",
            agreement_id=test_agreement["id"],
            listing_id=test_listing["id"],
            package_version=listing_package_agreement_package_version,
            compartment_id=compartment_id)
        ```

        ## Import

        Import is not supported for this resource.

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] agreement_id: The unique identifier for the agreement.
        :param pulumi.Input[_builtins.str] compartment_id: The unique identifier for the compartment, required in gov regions.
        :param pulumi.Input[_builtins.str] listing_id: The unique identifier for the listing.
        :param pulumi.Input[_builtins.str] package_version: The version of the package. Package versions are unique within a listing.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ListingPackageAgreementArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides details about a specific Listing Package Agreement resource in Oracle Cloud Infrastructure Marketplace service.

        This resource can be used to retrieve the time-based signature of terms of use agreement for a package that can be used to
        accept the agreement.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_listing_package_agreement = oci.marketplace.ListingPackageAgreement("test_listing_package_agreement",
            agreement_id=test_agreement["id"],
            listing_id=test_listing["id"],
            package_version=listing_package_agreement_package_version,
            compartment_id=compartment_id)
        ```

        ## Import

        Import is not supported for this resource.

        :param str resource_name: The name of the resource.
        :param ListingPackageAgreementArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ListingPackageAgreementArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 agreement_id: Optional[pulumi.Input[_builtins.str]] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 listing_id: Optional[pulumi.Input[_builtins.str]] = None,
                 package_version: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = ListingPackageAgreementArgs.__new__(ListingPackageAgreementArgs)

            if agreement_id is None and not opts.urn:
                raise TypeError("Missing required property 'agreement_id'")
            __props__.__dict__["agreement_id"] = agreement_id
            __props__.__dict__["compartment_id"] = compartment_id
            if listing_id is None and not opts.urn:
                raise TypeError("Missing required property 'listing_id'")
            __props__.__dict__["listing_id"] = listing_id
            if package_version is None and not opts.urn:
                raise TypeError("Missing required property 'package_version'")
            __props__.__dict__["package_version"] = package_version
            __props__.__dict__["author"] = None
            __props__.__dict__["content_url"] = None
            __props__.__dict__["prompt"] = None
            __props__.__dict__["signature"] = None
        super(ListingPackageAgreement, __self__).__init__(
            'oci:Marketplace/listingPackageAgreement:ListingPackageAgreement',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            agreement_id: Optional[pulumi.Input[_builtins.str]] = None,
            author: Optional[pulumi.Input[_builtins.str]] = None,
            compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
            content_url: Optional[pulumi.Input[_builtins.str]] = None,
            listing_id: Optional[pulumi.Input[_builtins.str]] = None,
            package_version: Optional[pulumi.Input[_builtins.str]] = None,
            prompt: Optional[pulumi.Input[_builtins.str]] = None,
            signature: Optional[pulumi.Input[_builtins.str]] = None) -> 'ListingPackageAgreement':
        """
        Get an existing ListingPackageAgreement resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] agreement_id: The unique identifier for the agreement.
        :param pulumi.Input[_builtins.str] author: Who authored the agreement.
        :param pulumi.Input[_builtins.str] compartment_id: The unique identifier for the compartment, required in gov regions.
        :param pulumi.Input[_builtins.str] content_url: The content URL of the agreement.
        :param pulumi.Input[_builtins.str] listing_id: The unique identifier for the listing.
        :param pulumi.Input[_builtins.str] package_version: The version of the package. Package versions are unique within a listing.
        :param pulumi.Input[_builtins.str] prompt: Textual prompt to read and accept the agreement.
        :param pulumi.Input[_builtins.str] signature: A time-based signature that can be used to accept an agreement or remove a previously accepted agreement from the list that Marketplace checks before a deployment.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ListingPackageAgreementState.__new__(_ListingPackageAgreementState)

        __props__.__dict__["agreement_id"] = agreement_id
        __props__.__dict__["author"] = author
        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["content_url"] = content_url
        __props__.__dict__["listing_id"] = listing_id
        __props__.__dict__["package_version"] = package_version
        __props__.__dict__["prompt"] = prompt
        __props__.__dict__["signature"] = signature
        return ListingPackageAgreement(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="agreementId")
    def agreement_id(self) -> pulumi.Output[_builtins.str]:
        """
        The unique identifier for the agreement.
        """
        return pulumi.get(self, "agreement_id")

    @_builtins.property
    @pulumi.getter
    def author(self) -> pulumi.Output[_builtins.str]:
        """
        Who authored the agreement.
        """
        return pulumi.get(self, "author")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[_builtins.str]:
        """
        The unique identifier for the compartment, required in gov regions.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="contentUrl")
    def content_url(self) -> pulumi.Output[_builtins.str]:
        """
        The content URL of the agreement.
        """
        return pulumi.get(self, "content_url")

    @_builtins.property
    @pulumi.getter(name="listingId")
    def listing_id(self) -> pulumi.Output[_builtins.str]:
        """
        The unique identifier for the listing.
        """
        return pulumi.get(self, "listing_id")

    @_builtins.property
    @pulumi.getter(name="packageVersion")
    def package_version(self) -> pulumi.Output[_builtins.str]:
        """
        The version of the package. Package versions are unique within a listing.
        """
        return pulumi.get(self, "package_version")

    @_builtins.property
    @pulumi.getter
    def prompt(self) -> pulumi.Output[_builtins.str]:
        """
        Textual prompt to read and accept the agreement.
        """
        return pulumi.get(self, "prompt")

    @_builtins.property
    @pulumi.getter
    def signature(self) -> pulumi.Output[_builtins.str]:
        """
        A time-based signature that can be used to accept an agreement or remove a previously accepted agreement from the list that Marketplace checks before a deployment.
        """
        return pulumi.get(self, "signature")

