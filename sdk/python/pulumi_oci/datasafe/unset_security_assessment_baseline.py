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

__all__ = ['UnsetSecurityAssessmentBaselineArgs', 'UnsetSecurityAssessmentBaseline']

@pulumi.input_type
class UnsetSecurityAssessmentBaselineArgs:
    def __init__(__self__, *,
                 security_assessment_id: pulumi.Input[_builtins.str],
                 target_ids: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None):
        """
        The set of arguments for constructing a UnsetSecurityAssessmentBaseline resource.
        :param pulumi.Input[_builtins.str] security_assessment_id: The OCID of the security assessment.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] target_ids: The list of database target OCIDs for which the user intends to unset the baseline.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "security_assessment_id", security_assessment_id)
        if target_ids is not None:
            pulumi.set(__self__, "target_ids", target_ids)

    @_builtins.property
    @pulumi.getter(name="securityAssessmentId")
    def security_assessment_id(self) -> pulumi.Input[_builtins.str]:
        """
        The OCID of the security assessment.
        """
        return pulumi.get(self, "security_assessment_id")

    @security_assessment_id.setter
    def security_assessment_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "security_assessment_id", value)

    @_builtins.property
    @pulumi.getter(name="targetIds")
    def target_ids(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]:
        """
        The list of database target OCIDs for which the user intends to unset the baseline.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "target_ids")

    @target_ids.setter
    def target_ids(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "target_ids", value)


@pulumi.input_type
class _UnsetSecurityAssessmentBaselineState:
    def __init__(__self__, *,
                 security_assessment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 target_ids: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None):
        """
        Input properties used for looking up and filtering UnsetSecurityAssessmentBaseline resources.
        :param pulumi.Input[_builtins.str] security_assessment_id: The OCID of the security assessment.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] target_ids: The list of database target OCIDs for which the user intends to unset the baseline.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if security_assessment_id is not None:
            pulumi.set(__self__, "security_assessment_id", security_assessment_id)
        if target_ids is not None:
            pulumi.set(__self__, "target_ids", target_ids)

    @_builtins.property
    @pulumi.getter(name="securityAssessmentId")
    def security_assessment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The OCID of the security assessment.
        """
        return pulumi.get(self, "security_assessment_id")

    @security_assessment_id.setter
    def security_assessment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "security_assessment_id", value)

    @_builtins.property
    @pulumi.getter(name="targetIds")
    def target_ids(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]:
        """
        The list of database target OCIDs for which the user intends to unset the baseline.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "target_ids")

    @target_ids.setter
    def target_ids(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "target_ids", value)


@pulumi.type_token("oci:DataSafe/unsetSecurityAssessmentBaseline:UnsetSecurityAssessmentBaseline")
class UnsetSecurityAssessmentBaseline(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 security_assessment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 target_ids: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 __props__=None):
        """
        This resource provides the Unset Security Assessment Baseline resource in Oracle Cloud Infrastructure Data Safe service.

        Removes the baseline setting for the saved security assessment associated with the targetId passed via body.
        If no body or empty body is passed then the baseline settings of all the saved security assessments pertaining to the baseline assessment OCID provided in the path will be removed.
        Sets the if-match parameter to the value of the etag from a previous GET or POST response for that resource.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_unset_security_assessment_baseline = oci.datasafe.UnsetSecurityAssessmentBaseline("test_unset_security_assessment_baseline",
            security_assessment_id=test_security_assessment["id"],
            target_ids=unset_security_assessment_baseline_target_ids)
        ```

        ## Import

        UnsetSecurityAssessmentBaseline can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:DataSafe/unsetSecurityAssessmentBaseline:UnsetSecurityAssessmentBaseline test_unset_security_assessment_baseline "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] security_assessment_id: The OCID of the security assessment.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] target_ids: The list of database target OCIDs for which the user intends to unset the baseline.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: UnsetSecurityAssessmentBaselineArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Unset Security Assessment Baseline resource in Oracle Cloud Infrastructure Data Safe service.

        Removes the baseline setting for the saved security assessment associated with the targetId passed via body.
        If no body or empty body is passed then the baseline settings of all the saved security assessments pertaining to the baseline assessment OCID provided in the path will be removed.
        Sets the if-match parameter to the value of the etag from a previous GET or POST response for that resource.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_unset_security_assessment_baseline = oci.datasafe.UnsetSecurityAssessmentBaseline("test_unset_security_assessment_baseline",
            security_assessment_id=test_security_assessment["id"],
            target_ids=unset_security_assessment_baseline_target_ids)
        ```

        ## Import

        UnsetSecurityAssessmentBaseline can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:DataSafe/unsetSecurityAssessmentBaseline:UnsetSecurityAssessmentBaseline test_unset_security_assessment_baseline "id"
        ```

        :param str resource_name: The name of the resource.
        :param UnsetSecurityAssessmentBaselineArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(UnsetSecurityAssessmentBaselineArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 security_assessment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 target_ids: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = UnsetSecurityAssessmentBaselineArgs.__new__(UnsetSecurityAssessmentBaselineArgs)

            if security_assessment_id is None and not opts.urn:
                raise TypeError("Missing required property 'security_assessment_id'")
            __props__.__dict__["security_assessment_id"] = security_assessment_id
            __props__.__dict__["target_ids"] = target_ids
        super(UnsetSecurityAssessmentBaseline, __self__).__init__(
            'oci:DataSafe/unsetSecurityAssessmentBaseline:UnsetSecurityAssessmentBaseline',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            security_assessment_id: Optional[pulumi.Input[_builtins.str]] = None,
            target_ids: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None) -> 'UnsetSecurityAssessmentBaseline':
        """
        Get an existing UnsetSecurityAssessmentBaseline resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] security_assessment_id: The OCID of the security assessment.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] target_ids: The list of database target OCIDs for which the user intends to unset the baseline.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _UnsetSecurityAssessmentBaselineState.__new__(_UnsetSecurityAssessmentBaselineState)

        __props__.__dict__["security_assessment_id"] = security_assessment_id
        __props__.__dict__["target_ids"] = target_ids
        return UnsetSecurityAssessmentBaseline(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="securityAssessmentId")
    def security_assessment_id(self) -> pulumi.Output[_builtins.str]:
        """
        The OCID of the security assessment.
        """
        return pulumi.get(self, "security_assessment_id")

    @_builtins.property
    @pulumi.getter(name="targetIds")
    def target_ids(self) -> pulumi.Output[Optional[Sequence[_builtins.str]]]:
        """
        The list of database target OCIDs for which the user intends to unset the baseline.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "target_ids")

