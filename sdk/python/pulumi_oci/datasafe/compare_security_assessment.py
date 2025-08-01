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

__all__ = ['CompareSecurityAssessmentArgs', 'CompareSecurityAssessment']

@pulumi.input_type
class CompareSecurityAssessmentArgs:
    def __init__(__self__, *,
                 comparison_security_assessment_id: pulumi.Input[_builtins.str],
                 security_assessment_id: pulumi.Input[_builtins.str]):
        """
        The set of arguments for constructing a CompareSecurityAssessment resource.
        :param pulumi.Input[_builtins.str] comparison_security_assessment_id: The OCID of the security assessment. In this case a security assessment can be another security assessment, a latest assessment or a baseline.
        :param pulumi.Input[_builtins.str] security_assessment_id: The OCID of the security assessment.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "comparison_security_assessment_id", comparison_security_assessment_id)
        pulumi.set(__self__, "security_assessment_id", security_assessment_id)

    @_builtins.property
    @pulumi.getter(name="comparisonSecurityAssessmentId")
    def comparison_security_assessment_id(self) -> pulumi.Input[_builtins.str]:
        """
        The OCID of the security assessment. In this case a security assessment can be another security assessment, a latest assessment or a baseline.
        """
        return pulumi.get(self, "comparison_security_assessment_id")

    @comparison_security_assessment_id.setter
    def comparison_security_assessment_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "comparison_security_assessment_id", value)

    @_builtins.property
    @pulumi.getter(name="securityAssessmentId")
    def security_assessment_id(self) -> pulumi.Input[_builtins.str]:
        """
        The OCID of the security assessment.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "security_assessment_id")

    @security_assessment_id.setter
    def security_assessment_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "security_assessment_id", value)


@pulumi.input_type
class _CompareSecurityAssessmentState:
    def __init__(__self__, *,
                 comparison_security_assessment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 security_assessment_id: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering CompareSecurityAssessment resources.
        :param pulumi.Input[_builtins.str] comparison_security_assessment_id: The OCID of the security assessment. In this case a security assessment can be another security assessment, a latest assessment or a baseline.
        :param pulumi.Input[_builtins.str] security_assessment_id: The OCID of the security assessment.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if comparison_security_assessment_id is not None:
            pulumi.set(__self__, "comparison_security_assessment_id", comparison_security_assessment_id)
        if security_assessment_id is not None:
            pulumi.set(__self__, "security_assessment_id", security_assessment_id)

    @_builtins.property
    @pulumi.getter(name="comparisonSecurityAssessmentId")
    def comparison_security_assessment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The OCID of the security assessment. In this case a security assessment can be another security assessment, a latest assessment or a baseline.
        """
        return pulumi.get(self, "comparison_security_assessment_id")

    @comparison_security_assessment_id.setter
    def comparison_security_assessment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "comparison_security_assessment_id", value)

    @_builtins.property
    @pulumi.getter(name="securityAssessmentId")
    def security_assessment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The OCID of the security assessment.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "security_assessment_id")

    @security_assessment_id.setter
    def security_assessment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "security_assessment_id", value)


@pulumi.type_token("oci:DataSafe/compareSecurityAssessment:CompareSecurityAssessment")
class CompareSecurityAssessment(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 comparison_security_assessment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 security_assessment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Compare Security Assessment resource in Oracle Cloud Infrastructure Data Safe service.

        Compares two security assessments. For this comparison, a security assessment can be a saved assessment, a latest assessment, or a baseline assessment.
        For example, you can compare saved assessment or a latest assessment against a baseline.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_compare_security_assessment = oci.datasafe.CompareSecurityAssessment("test_compare_security_assessment",
            comparison_security_assessment_id=test_security_assessment["id"],
            security_assessment_id=test_security_assessment["id"])
        ```

        ## Import

        CompareSecurityAssessment can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:DataSafe/compareSecurityAssessment:CompareSecurityAssessment test_compare_security_assessment "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] comparison_security_assessment_id: The OCID of the security assessment. In this case a security assessment can be another security assessment, a latest assessment or a baseline.
        :param pulumi.Input[_builtins.str] security_assessment_id: The OCID of the security assessment.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: CompareSecurityAssessmentArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Compare Security Assessment resource in Oracle Cloud Infrastructure Data Safe service.

        Compares two security assessments. For this comparison, a security assessment can be a saved assessment, a latest assessment, or a baseline assessment.
        For example, you can compare saved assessment or a latest assessment against a baseline.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_compare_security_assessment = oci.datasafe.CompareSecurityAssessment("test_compare_security_assessment",
            comparison_security_assessment_id=test_security_assessment["id"],
            security_assessment_id=test_security_assessment["id"])
        ```

        ## Import

        CompareSecurityAssessment can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:DataSafe/compareSecurityAssessment:CompareSecurityAssessment test_compare_security_assessment "id"
        ```

        :param str resource_name: The name of the resource.
        :param CompareSecurityAssessmentArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(CompareSecurityAssessmentArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 comparison_security_assessment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 security_assessment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = CompareSecurityAssessmentArgs.__new__(CompareSecurityAssessmentArgs)

            if comparison_security_assessment_id is None and not opts.urn:
                raise TypeError("Missing required property 'comparison_security_assessment_id'")
            __props__.__dict__["comparison_security_assessment_id"] = comparison_security_assessment_id
            if security_assessment_id is None and not opts.urn:
                raise TypeError("Missing required property 'security_assessment_id'")
            __props__.__dict__["security_assessment_id"] = security_assessment_id
        super(CompareSecurityAssessment, __self__).__init__(
            'oci:DataSafe/compareSecurityAssessment:CompareSecurityAssessment',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            comparison_security_assessment_id: Optional[pulumi.Input[_builtins.str]] = None,
            security_assessment_id: Optional[pulumi.Input[_builtins.str]] = None) -> 'CompareSecurityAssessment':
        """
        Get an existing CompareSecurityAssessment resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] comparison_security_assessment_id: The OCID of the security assessment. In this case a security assessment can be another security assessment, a latest assessment or a baseline.
        :param pulumi.Input[_builtins.str] security_assessment_id: The OCID of the security assessment.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _CompareSecurityAssessmentState.__new__(_CompareSecurityAssessmentState)

        __props__.__dict__["comparison_security_assessment_id"] = comparison_security_assessment_id
        __props__.__dict__["security_assessment_id"] = security_assessment_id
        return CompareSecurityAssessment(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="comparisonSecurityAssessmentId")
    def comparison_security_assessment_id(self) -> pulumi.Output[_builtins.str]:
        """
        The OCID of the security assessment. In this case a security assessment can be another security assessment, a latest assessment or a baseline.
        """
        return pulumi.get(self, "comparison_security_assessment_id")

    @_builtins.property
    @pulumi.getter(name="securityAssessmentId")
    def security_assessment_id(self) -> pulumi.Output[_builtins.str]:
        """
        The OCID of the security assessment.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "security_assessment_id")

