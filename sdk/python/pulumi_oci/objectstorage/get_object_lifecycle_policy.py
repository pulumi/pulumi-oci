# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs

__all__ = [
    'GetObjectLifecyclePolicyResult',
    'AwaitableGetObjectLifecyclePolicyResult',
    'get_object_lifecycle_policy',
    'get_object_lifecycle_policy_output',
]

@pulumi.output_type
class GetObjectLifecyclePolicyResult:
    """
    A collection of values returned by getObjectLifecyclePolicy.
    """
    def __init__(__self__, bucket=None, id=None, namespace=None, rules=None, time_created=None):
        if bucket and not isinstance(bucket, str):
            raise TypeError("Expected argument 'bucket' to be a str")
        pulumi.set(__self__, "bucket", bucket)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if namespace and not isinstance(namespace, str):
            raise TypeError("Expected argument 'namespace' to be a str")
        pulumi.set(__self__, "namespace", namespace)
        if rules and not isinstance(rules, list):
            raise TypeError("Expected argument 'rules' to be a list")
        pulumi.set(__self__, "rules", rules)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter
    def bucket(self) -> str:
        return pulumi.get(self, "bucket")

    @property
    @pulumi.getter
    def id(self) -> str:
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def namespace(self) -> str:
        return pulumi.get(self, "namespace")

    @property
    @pulumi.getter
    def rules(self) -> Sequence['outputs.GetObjectLifecyclePolicyRuleResult']:
        """
        The live lifecycle policy on the bucket.
        """
        return pulumi.get(self, "rules")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the object lifecycle policy was created, as described in [RFC 3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_created")


class AwaitableGetObjectLifecyclePolicyResult(GetObjectLifecyclePolicyResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetObjectLifecyclePolicyResult(
            bucket=self.bucket,
            id=self.id,
            namespace=self.namespace,
            rules=self.rules,
            time_created=self.time_created)


def get_object_lifecycle_policy(bucket: Optional[str] = None,
                                namespace: Optional[str] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetObjectLifecyclePolicyResult:
    """
    This data source provides details about a specific Object Lifecycle Policy resource in Oracle Cloud Infrastructure Object Storage service.

    Gets the object lifecycle policy for the bucket.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_object_lifecycle_policy = oci.ObjectStorage.get_object_lifecycle_policy(bucket=var["object_lifecycle_policy_bucket"],
        namespace=var["object_lifecycle_policy_namespace"])
    ```


    :param str bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
    :param str namespace: The Object Storage namespace used for the request.
    """
    __args__ = dict()
    __args__['bucket'] = bucket
    __args__['namespace'] = namespace
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ObjectStorage/getObjectLifecyclePolicy:getObjectLifecyclePolicy', __args__, opts=opts, typ=GetObjectLifecyclePolicyResult).value

    return AwaitableGetObjectLifecyclePolicyResult(
        bucket=__ret__.bucket,
        id=__ret__.id,
        namespace=__ret__.namespace,
        rules=__ret__.rules,
        time_created=__ret__.time_created)


@_utilities.lift_output_func(get_object_lifecycle_policy)
def get_object_lifecycle_policy_output(bucket: Optional[pulumi.Input[str]] = None,
                                       namespace: Optional[pulumi.Input[str]] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetObjectLifecyclePolicyResult]:
    """
    This data source provides details about a specific Object Lifecycle Policy resource in Oracle Cloud Infrastructure Object Storage service.

    Gets the object lifecycle policy for the bucket.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_object_lifecycle_policy = oci.ObjectStorage.get_object_lifecycle_policy(bucket=var["object_lifecycle_policy_bucket"],
        namespace=var["object_lifecycle_policy_namespace"])
    ```


    :param str bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
    :param str namespace: The Object Storage namespace used for the request.
    """
    ...