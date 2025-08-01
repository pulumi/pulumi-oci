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
from . import outputs
from ._inputs import *

__all__ = ['ObjectLifecyclePolicyArgs', 'ObjectLifecyclePolicy']

@pulumi.input_type
class ObjectLifecyclePolicyArgs:
    def __init__(__self__, *,
                 bucket: pulumi.Input[_builtins.str],
                 namespace: pulumi.Input[_builtins.str],
                 rules: Optional[pulumi.Input[Sequence[pulumi.Input['ObjectLifecyclePolicyRuleArgs']]]] = None):
        """
        The set of arguments for constructing a ObjectLifecyclePolicy resource.
        :param pulumi.Input[_builtins.str] bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        :param pulumi.Input[_builtins.str] namespace: The Object Storage namespace used for the request.
        :param pulumi.Input[Sequence[pulumi.Input['ObjectLifecyclePolicyRuleArgs']]] rules: (Updatable) The bucket's set of lifecycle policy rules.
        """
        pulumi.set(__self__, "bucket", bucket)
        pulumi.set(__self__, "namespace", namespace)
        if rules is not None:
            pulumi.set(__self__, "rules", rules)

    @_builtins.property
    @pulumi.getter
    def bucket(self) -> pulumi.Input[_builtins.str]:
        """
        The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        """
        return pulumi.get(self, "bucket")

    @bucket.setter
    def bucket(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "bucket", value)

    @_builtins.property
    @pulumi.getter
    def namespace(self) -> pulumi.Input[_builtins.str]:
        """
        The Object Storage namespace used for the request.
        """
        return pulumi.get(self, "namespace")

    @namespace.setter
    def namespace(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "namespace", value)

    @_builtins.property
    @pulumi.getter
    def rules(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ObjectLifecyclePolicyRuleArgs']]]]:
        """
        (Updatable) The bucket's set of lifecycle policy rules.
        """
        return pulumi.get(self, "rules")

    @rules.setter
    def rules(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ObjectLifecyclePolicyRuleArgs']]]]):
        pulumi.set(self, "rules", value)


@pulumi.input_type
class _ObjectLifecyclePolicyState:
    def __init__(__self__, *,
                 bucket: Optional[pulumi.Input[_builtins.str]] = None,
                 namespace: Optional[pulumi.Input[_builtins.str]] = None,
                 rules: Optional[pulumi.Input[Sequence[pulumi.Input['ObjectLifecyclePolicyRuleArgs']]]] = None,
                 time_created: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering ObjectLifecyclePolicy resources.
        :param pulumi.Input[_builtins.str] bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        :param pulumi.Input[_builtins.str] namespace: The Object Storage namespace used for the request.
        :param pulumi.Input[Sequence[pulumi.Input['ObjectLifecyclePolicyRuleArgs']]] rules: (Updatable) The bucket's set of lifecycle policy rules.
        :param pulumi.Input[_builtins.str] time_created: The date and time the object lifecycle policy was created, as described in [RFC 3339](https://tools.ietf.org/html/rfc3339).
        """
        if bucket is not None:
            pulumi.set(__self__, "bucket", bucket)
        if namespace is not None:
            pulumi.set(__self__, "namespace", namespace)
        if rules is not None:
            pulumi.set(__self__, "rules", rules)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)

    @_builtins.property
    @pulumi.getter
    def bucket(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        """
        return pulumi.get(self, "bucket")

    @bucket.setter
    def bucket(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "bucket", value)

    @_builtins.property
    @pulumi.getter
    def namespace(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The Object Storage namespace used for the request.
        """
        return pulumi.get(self, "namespace")

    @namespace.setter
    def namespace(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "namespace", value)

    @_builtins.property
    @pulumi.getter
    def rules(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ObjectLifecyclePolicyRuleArgs']]]]:
        """
        (Updatable) The bucket's set of lifecycle policy rules.
        """
        return pulumi.get(self, "rules")

    @rules.setter
    def rules(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ObjectLifecyclePolicyRuleArgs']]]]):
        pulumi.set(self, "rules", value)

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The date and time the object lifecycle policy was created, as described in [RFC 3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_created", value)


@pulumi.type_token("oci:ObjectStorage/objectLifecyclePolicy:ObjectLifecyclePolicy")
class ObjectLifecyclePolicy(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 bucket: Optional[pulumi.Input[_builtins.str]] = None,
                 namespace: Optional[pulumi.Input[_builtins.str]] = None,
                 rules: Optional[pulumi.Input[Sequence[pulumi.Input[Union['ObjectLifecyclePolicyRuleArgs', 'ObjectLifecyclePolicyRuleArgsDict']]]]] = None,
                 __props__=None):
        """
        This resource provides the Object Lifecycle Policy resource in Oracle Cloud Infrastructure Object Storage service.

        Creates or replaces the object lifecycle policy for the bucket.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_object_lifecycle_policy = oci.objectstorage.ObjectLifecyclePolicy("test_object_lifecycle_policy",
            bucket=object_lifecycle_policy_bucket,
            namespace=object_lifecycle_policy_namespace,
            rules=[{
                "action": object_lifecycle_policy_rules_action,
                "is_enabled": object_lifecycle_policy_rules_is_enabled,
                "name": object_lifecycle_policy_rules_name,
                "time_amount": object_lifecycle_policy_rules_time_amount,
                "time_unit": object_lifecycle_policy_rules_time_unit,
                "object_name_filter": {
                    "exclusion_patterns": object_lifecycle_policy_rules_object_name_filter_exclusion_patterns,
                    "inclusion_patterns": object_lifecycle_policy_rules_object_name_filter_inclusion_patterns,
                    "inclusion_prefixes": object_lifecycle_policy_rules_object_name_filter_inclusion_prefixes,
                },
                "target": object_lifecycle_policy_rules_target,
            }])
        ```

        ## Import

        ObjectLifecyclePolicies can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:ObjectStorage/objectLifecyclePolicy:ObjectLifecyclePolicy test_object_lifecycle_policy "n/{namespaceName}/b/{bucketName}/l"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        :param pulumi.Input[_builtins.str] namespace: The Object Storage namespace used for the request.
        :param pulumi.Input[Sequence[pulumi.Input[Union['ObjectLifecyclePolicyRuleArgs', 'ObjectLifecyclePolicyRuleArgsDict']]]] rules: (Updatable) The bucket's set of lifecycle policy rules.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ObjectLifecyclePolicyArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Object Lifecycle Policy resource in Oracle Cloud Infrastructure Object Storage service.

        Creates or replaces the object lifecycle policy for the bucket.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_object_lifecycle_policy = oci.objectstorage.ObjectLifecyclePolicy("test_object_lifecycle_policy",
            bucket=object_lifecycle_policy_bucket,
            namespace=object_lifecycle_policy_namespace,
            rules=[{
                "action": object_lifecycle_policy_rules_action,
                "is_enabled": object_lifecycle_policy_rules_is_enabled,
                "name": object_lifecycle_policy_rules_name,
                "time_amount": object_lifecycle_policy_rules_time_amount,
                "time_unit": object_lifecycle_policy_rules_time_unit,
                "object_name_filter": {
                    "exclusion_patterns": object_lifecycle_policy_rules_object_name_filter_exclusion_patterns,
                    "inclusion_patterns": object_lifecycle_policy_rules_object_name_filter_inclusion_patterns,
                    "inclusion_prefixes": object_lifecycle_policy_rules_object_name_filter_inclusion_prefixes,
                },
                "target": object_lifecycle_policy_rules_target,
            }])
        ```

        ## Import

        ObjectLifecyclePolicies can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:ObjectStorage/objectLifecyclePolicy:ObjectLifecyclePolicy test_object_lifecycle_policy "n/{namespaceName}/b/{bucketName}/l"
        ```

        :param str resource_name: The name of the resource.
        :param ObjectLifecyclePolicyArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ObjectLifecyclePolicyArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 bucket: Optional[pulumi.Input[_builtins.str]] = None,
                 namespace: Optional[pulumi.Input[_builtins.str]] = None,
                 rules: Optional[pulumi.Input[Sequence[pulumi.Input[Union['ObjectLifecyclePolicyRuleArgs', 'ObjectLifecyclePolicyRuleArgsDict']]]]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = ObjectLifecyclePolicyArgs.__new__(ObjectLifecyclePolicyArgs)

            if bucket is None and not opts.urn:
                raise TypeError("Missing required property 'bucket'")
            __props__.__dict__["bucket"] = bucket
            if namespace is None and not opts.urn:
                raise TypeError("Missing required property 'namespace'")
            __props__.__dict__["namespace"] = namespace
            __props__.__dict__["rules"] = rules
            __props__.__dict__["time_created"] = None
        super(ObjectLifecyclePolicy, __self__).__init__(
            'oci:ObjectStorage/objectLifecyclePolicy:ObjectLifecyclePolicy',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            bucket: Optional[pulumi.Input[_builtins.str]] = None,
            namespace: Optional[pulumi.Input[_builtins.str]] = None,
            rules: Optional[pulumi.Input[Sequence[pulumi.Input[Union['ObjectLifecyclePolicyRuleArgs', 'ObjectLifecyclePolicyRuleArgsDict']]]]] = None,
            time_created: Optional[pulumi.Input[_builtins.str]] = None) -> 'ObjectLifecyclePolicy':
        """
        Get an existing ObjectLifecyclePolicy resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        :param pulumi.Input[_builtins.str] namespace: The Object Storage namespace used for the request.
        :param pulumi.Input[Sequence[pulumi.Input[Union['ObjectLifecyclePolicyRuleArgs', 'ObjectLifecyclePolicyRuleArgsDict']]]] rules: (Updatable) The bucket's set of lifecycle policy rules.
        :param pulumi.Input[_builtins.str] time_created: The date and time the object lifecycle policy was created, as described in [RFC 3339](https://tools.ietf.org/html/rfc3339).
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ObjectLifecyclePolicyState.__new__(_ObjectLifecyclePolicyState)

        __props__.__dict__["bucket"] = bucket
        __props__.__dict__["namespace"] = namespace
        __props__.__dict__["rules"] = rules
        __props__.__dict__["time_created"] = time_created
        return ObjectLifecyclePolicy(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter
    def bucket(self) -> pulumi.Output[_builtins.str]:
        """
        The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        """
        return pulumi.get(self, "bucket")

    @_builtins.property
    @pulumi.getter
    def namespace(self) -> pulumi.Output[_builtins.str]:
        """
        The Object Storage namespace used for the request.
        """
        return pulumi.get(self, "namespace")

    @_builtins.property
    @pulumi.getter
    def rules(self) -> pulumi.Output[Sequence['outputs.ObjectLifecyclePolicyRule']]:
        """
        (Updatable) The bucket's set of lifecycle policy rules.
        """
        return pulumi.get(self, "rules")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[_builtins.str]:
        """
        The date and time the object lifecycle policy was created, as described in [RFC 3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

