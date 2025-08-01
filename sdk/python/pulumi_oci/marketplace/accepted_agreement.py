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

__all__ = ['AcceptedAgreementArgs', 'AcceptedAgreement']

@pulumi.input_type
class AcceptedAgreementArgs:
    def __init__(__self__, *,
                 agreement_id: pulumi.Input[_builtins.str],
                 compartment_id: pulumi.Input[_builtins.str],
                 listing_id: pulumi.Input[_builtins.str],
                 package_version: pulumi.Input[_builtins.str],
                 signature: pulumi.Input[_builtins.str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None):
        """
        The set of arguments for constructing a AcceptedAgreement resource.
        :param pulumi.Input[_builtins.str] agreement_id: The agreement to accept.
        :param pulumi.Input[_builtins.str] compartment_id: The unique identifier for the compartment where the agreement will be accepted.
        :param pulumi.Input[_builtins.str] listing_id: The unique identifier for the listing associated with the agreement.
        :param pulumi.Input[_builtins.str] package_version: The package version associated with the agreement.
        :param pulumi.Input[_builtins.str] signature: A signature generated for the listing package agreements that you can retrieve with [GetAgreement](https://docs.cloud.oracle.com/iaas/api/#/en/marketplace/20181001/Agreement/GetAgreement). 
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A display name for the accepted agreement.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        pulumi.set(__self__, "agreement_id", agreement_id)
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "listing_id", listing_id)
        pulumi.set(__self__, "package_version", package_version)
        pulumi.set(__self__, "signature", signature)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)

    @_builtins.property
    @pulumi.getter(name="agreementId")
    def agreement_id(self) -> pulumi.Input[_builtins.str]:
        """
        The agreement to accept.
        """
        return pulumi.get(self, "agreement_id")

    @agreement_id.setter
    def agreement_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "agreement_id", value)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[_builtins.str]:
        """
        The unique identifier for the compartment where the agreement will be accepted.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="listingId")
    def listing_id(self) -> pulumi.Input[_builtins.str]:
        """
        The unique identifier for the listing associated with the agreement.
        """
        return pulumi.get(self, "listing_id")

    @listing_id.setter
    def listing_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "listing_id", value)

    @_builtins.property
    @pulumi.getter(name="packageVersion")
    def package_version(self) -> pulumi.Input[_builtins.str]:
        """
        The package version associated with the agreement.
        """
        return pulumi.get(self, "package_version")

    @package_version.setter
    def package_version(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "package_version", value)

    @_builtins.property
    @pulumi.getter
    def signature(self) -> pulumi.Input[_builtins.str]:
        """
        A signature generated for the listing package agreements that you can retrieve with [GetAgreement](https://docs.cloud.oracle.com/iaas/api/#/en/marketplace/20181001/Agreement/GetAgreement). 


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "signature")

    @signature.setter
    def signature(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "signature", value)

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "defined_tags", value)

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) A display name for the accepted agreement.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "display_name", value)

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "freeform_tags", value)


@pulumi.input_type
class _AcceptedAgreementState:
    def __init__(__self__, *,
                 agreement_id: Optional[pulumi.Input[_builtins.str]] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 listing_id: Optional[pulumi.Input[_builtins.str]] = None,
                 package_version: Optional[pulumi.Input[_builtins.str]] = None,
                 signature: Optional[pulumi.Input[_builtins.str]] = None,
                 time_accepted: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering AcceptedAgreement resources.
        :param pulumi.Input[_builtins.str] agreement_id: The agreement to accept.
        :param pulumi.Input[_builtins.str] compartment_id: The unique identifier for the compartment where the agreement will be accepted.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A display name for the accepted agreement.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        :param pulumi.Input[_builtins.str] listing_id: The unique identifier for the listing associated with the agreement.
        :param pulumi.Input[_builtins.str] package_version: The package version associated with the agreement.
        :param pulumi.Input[_builtins.str] signature: A signature generated for the listing package agreements that you can retrieve with [GetAgreement](https://docs.cloud.oracle.com/iaas/api/#/en/marketplace/20181001/Agreement/GetAgreement). 
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] time_accepted: The time the agreement was accepted.
        """
        if agreement_id is not None:
            pulumi.set(__self__, "agreement_id", agreement_id)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if listing_id is not None:
            pulumi.set(__self__, "listing_id", listing_id)
        if package_version is not None:
            pulumi.set(__self__, "package_version", package_version)
        if signature is not None:
            pulumi.set(__self__, "signature", signature)
        if time_accepted is not None:
            pulumi.set(__self__, "time_accepted", time_accepted)

    @_builtins.property
    @pulumi.getter(name="agreementId")
    def agreement_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The agreement to accept.
        """
        return pulumi.get(self, "agreement_id")

    @agreement_id.setter
    def agreement_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "agreement_id", value)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The unique identifier for the compartment where the agreement will be accepted.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "defined_tags", value)

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) A display name for the accepted agreement.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "display_name", value)

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "freeform_tags", value)

    @_builtins.property
    @pulumi.getter(name="listingId")
    def listing_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The unique identifier for the listing associated with the agreement.
        """
        return pulumi.get(self, "listing_id")

    @listing_id.setter
    def listing_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "listing_id", value)

    @_builtins.property
    @pulumi.getter(name="packageVersion")
    def package_version(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The package version associated with the agreement.
        """
        return pulumi.get(self, "package_version")

    @package_version.setter
    def package_version(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "package_version", value)

    @_builtins.property
    @pulumi.getter
    def signature(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        A signature generated for the listing package agreements that you can retrieve with [GetAgreement](https://docs.cloud.oracle.com/iaas/api/#/en/marketplace/20181001/Agreement/GetAgreement). 


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "signature")

    @signature.setter
    def signature(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "signature", value)

    @_builtins.property
    @pulumi.getter(name="timeAccepted")
    def time_accepted(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The time the agreement was accepted.
        """
        return pulumi.get(self, "time_accepted")

    @time_accepted.setter
    def time_accepted(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_accepted", value)


@pulumi.type_token("oci:Marketplace/acceptedAgreement:AcceptedAgreement")
class AcceptedAgreement(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 agreement_id: Optional[pulumi.Input[_builtins.str]] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 listing_id: Optional[pulumi.Input[_builtins.str]] = None,
                 package_version: Optional[pulumi.Input[_builtins.str]] = None,
                 signature: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Accepted Agreement resource in Oracle Cloud Infrastructure Marketplace service.

        Accepts a terms of use agreement for a specific package version of a listing. You must accept all
        terms of use for a package before you can deploy the package.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_accepted_agreement = oci.marketplace.AcceptedAgreement("test_accepted_agreement",
            agreement_id=test_agreement["id"],
            compartment_id=compartment_id,
            listing_id=test_listing["id"],
            package_version=accepted_agreement_package_version,
            signature=accepted_agreement_signature,
            defined_tags={
                "Operations.CostCenter": "42",
            },
            display_name=accepted_agreement_display_name,
            freeform_tags={
                "Department": "Finance",
            })
        ```

        ## Import

        AcceptedAgreements can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:Marketplace/acceptedAgreement:AcceptedAgreement test_accepted_agreement "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] agreement_id: The agreement to accept.
        :param pulumi.Input[_builtins.str] compartment_id: The unique identifier for the compartment where the agreement will be accepted.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A display name for the accepted agreement.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        :param pulumi.Input[_builtins.str] listing_id: The unique identifier for the listing associated with the agreement.
        :param pulumi.Input[_builtins.str] package_version: The package version associated with the agreement.
        :param pulumi.Input[_builtins.str] signature: A signature generated for the listing package agreements that you can retrieve with [GetAgreement](https://docs.cloud.oracle.com/iaas/api/#/en/marketplace/20181001/Agreement/GetAgreement). 
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: AcceptedAgreementArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Accepted Agreement resource in Oracle Cloud Infrastructure Marketplace service.

        Accepts a terms of use agreement for a specific package version of a listing. You must accept all
        terms of use for a package before you can deploy the package.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_accepted_agreement = oci.marketplace.AcceptedAgreement("test_accepted_agreement",
            agreement_id=test_agreement["id"],
            compartment_id=compartment_id,
            listing_id=test_listing["id"],
            package_version=accepted_agreement_package_version,
            signature=accepted_agreement_signature,
            defined_tags={
                "Operations.CostCenter": "42",
            },
            display_name=accepted_agreement_display_name,
            freeform_tags={
                "Department": "Finance",
            })
        ```

        ## Import

        AcceptedAgreements can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:Marketplace/acceptedAgreement:AcceptedAgreement test_accepted_agreement "id"
        ```

        :param str resource_name: The name of the resource.
        :param AcceptedAgreementArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(AcceptedAgreementArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 agreement_id: Optional[pulumi.Input[_builtins.str]] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 listing_id: Optional[pulumi.Input[_builtins.str]] = None,
                 package_version: Optional[pulumi.Input[_builtins.str]] = None,
                 signature: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = AcceptedAgreementArgs.__new__(AcceptedAgreementArgs)

            if agreement_id is None and not opts.urn:
                raise TypeError("Missing required property 'agreement_id'")
            __props__.__dict__["agreement_id"] = agreement_id
            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["freeform_tags"] = freeform_tags
            if listing_id is None and not opts.urn:
                raise TypeError("Missing required property 'listing_id'")
            __props__.__dict__["listing_id"] = listing_id
            if package_version is None and not opts.urn:
                raise TypeError("Missing required property 'package_version'")
            __props__.__dict__["package_version"] = package_version
            if signature is None and not opts.urn:
                raise TypeError("Missing required property 'signature'")
            __props__.__dict__["signature"] = signature
            __props__.__dict__["time_accepted"] = None
        super(AcceptedAgreement, __self__).__init__(
            'oci:Marketplace/acceptedAgreement:AcceptedAgreement',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            agreement_id: Optional[pulumi.Input[_builtins.str]] = None,
            compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            display_name: Optional[pulumi.Input[_builtins.str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            listing_id: Optional[pulumi.Input[_builtins.str]] = None,
            package_version: Optional[pulumi.Input[_builtins.str]] = None,
            signature: Optional[pulumi.Input[_builtins.str]] = None,
            time_accepted: Optional[pulumi.Input[_builtins.str]] = None) -> 'AcceptedAgreement':
        """
        Get an existing AcceptedAgreement resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] agreement_id: The agreement to accept.
        :param pulumi.Input[_builtins.str] compartment_id: The unique identifier for the compartment where the agreement will be accepted.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A display name for the accepted agreement.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        :param pulumi.Input[_builtins.str] listing_id: The unique identifier for the listing associated with the agreement.
        :param pulumi.Input[_builtins.str] package_version: The package version associated with the agreement.
        :param pulumi.Input[_builtins.str] signature: A signature generated for the listing package agreements that you can retrieve with [GetAgreement](https://docs.cloud.oracle.com/iaas/api/#/en/marketplace/20181001/Agreement/GetAgreement). 
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] time_accepted: The time the agreement was accepted.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _AcceptedAgreementState.__new__(_AcceptedAgreementState)

        __props__.__dict__["agreement_id"] = agreement_id
        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["listing_id"] = listing_id
        __props__.__dict__["package_version"] = package_version
        __props__.__dict__["signature"] = signature
        __props__.__dict__["time_accepted"] = time_accepted
        return AcceptedAgreement(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="agreementId")
    def agreement_id(self) -> pulumi.Output[_builtins.str]:
        """
        The agreement to accept.
        """
        return pulumi.get(self, "agreement_id")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[_builtins.str]:
        """
        The unique identifier for the compartment where the agreement will be accepted.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) A display name for the accepted agreement.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter(name="listingId")
    def listing_id(self) -> pulumi.Output[_builtins.str]:
        """
        The unique identifier for the listing associated with the agreement.
        """
        return pulumi.get(self, "listing_id")

    @_builtins.property
    @pulumi.getter(name="packageVersion")
    def package_version(self) -> pulumi.Output[_builtins.str]:
        """
        The package version associated with the agreement.
        """
        return pulumi.get(self, "package_version")

    @_builtins.property
    @pulumi.getter
    def signature(self) -> pulumi.Output[_builtins.str]:
        """
        A signature generated for the listing package agreements that you can retrieve with [GetAgreement](https://docs.cloud.oracle.com/iaas/api/#/en/marketplace/20181001/Agreement/GetAgreement). 


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "signature")

    @_builtins.property
    @pulumi.getter(name="timeAccepted")
    def time_accepted(self) -> pulumi.Output[_builtins.str]:
        """
        The time the agreement was accepted.
        """
        return pulumi.get(self, "time_accepted")

