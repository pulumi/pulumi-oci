# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetObjectHeadResult',
    'AwaitableGetObjectHeadResult',
    'get_object_head',
    'get_object_head_output',
]

@pulumi.output_type
class GetObjectHeadResult:
    """
    A collection of values returned by getObjectHead.
    """
    def __init__(__self__, archival_state=None, bucket=None, content_length=None, content_type=None, etag=None, id=None, metadata=None, namespace=None, object=None, storage_tier=None):
        if archival_state and not isinstance(archival_state, str):
            raise TypeError("Expected argument 'archival_state' to be a str")
        pulumi.set(__self__, "archival_state", archival_state)
        if bucket and not isinstance(bucket, str):
            raise TypeError("Expected argument 'bucket' to be a str")
        pulumi.set(__self__, "bucket", bucket)
        if content_length and not isinstance(content_length, int):
            raise TypeError("Expected argument 'content_length' to be a int")
        pulumi.set(__self__, "content_length", content_length)
        if content_type and not isinstance(content_type, str):
            raise TypeError("Expected argument 'content_type' to be a str")
        pulumi.set(__self__, "content_type", content_type)
        if etag and not isinstance(etag, str):
            raise TypeError("Expected argument 'etag' to be a str")
        pulumi.set(__self__, "etag", etag)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if metadata and not isinstance(metadata, dict):
            raise TypeError("Expected argument 'metadata' to be a dict")
        pulumi.set(__self__, "metadata", metadata)
        if namespace and not isinstance(namespace, str):
            raise TypeError("Expected argument 'namespace' to be a str")
        pulumi.set(__self__, "namespace", namespace)
        if object and not isinstance(object, str):
            raise TypeError("Expected argument 'object' to be a str")
        pulumi.set(__self__, "object", object)
        if storage_tier and not isinstance(storage_tier, str):
            raise TypeError("Expected argument 'storage_tier' to be a str")
        pulumi.set(__self__, "storage_tier", storage_tier)

    @property
    @pulumi.getter(name="archivalState")
    def archival_state(self) -> str:
        return pulumi.get(self, "archival_state")

    @property
    @pulumi.getter
    def bucket(self) -> str:
        return pulumi.get(self, "bucket")

    @property
    @pulumi.getter(name="contentLength")
    def content_length(self) -> int:
        """
        The content-length of the object
        """
        return pulumi.get(self, "content_length")

    @property
    @pulumi.getter(name="contentType")
    def content_type(self) -> str:
        """
        The content-type of the object
        """
        return pulumi.get(self, "content_type")

    @property
    @pulumi.getter
    def etag(self) -> str:
        """
        The etag of the object
        """
        return pulumi.get(self, "etag")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def metadata(self) -> Mapping[str, Any]:
        """
        The metadata of the object
        """
        return pulumi.get(self, "metadata")

    @property
    @pulumi.getter
    def namespace(self) -> str:
        return pulumi.get(self, "namespace")

    @property
    @pulumi.getter
    def object(self) -> str:
        return pulumi.get(self, "object")

    @property
    @pulumi.getter(name="storageTier")
    def storage_tier(self) -> str:
        """
        The storage tier that the object is stored in.
        * `archival-state` - Archival state of an object. This field is set only for objects in Archive tier.
        """
        return pulumi.get(self, "storage_tier")


class AwaitableGetObjectHeadResult(GetObjectHeadResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetObjectHeadResult(
            archival_state=self.archival_state,
            bucket=self.bucket,
            content_length=self.content_length,
            content_type=self.content_type,
            etag=self.etag,
            id=self.id,
            metadata=self.metadata,
            namespace=self.namespace,
            object=self.object,
            storage_tier=self.storage_tier)


def get_object_head(bucket: Optional[str] = None,
                    namespace: Optional[str] = None,
                    object: Optional[str] = None,
                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetObjectHeadResult:
    """
    This data source provides details about metadata of a specific Object resource in Oracle Cloud Infrastructure Object Storage service.

    Gets the metadata of an object.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_object_head = oci.ObjectStorage.get_object_head(bucket=var["object_bucket"],
        namespace=var["object_namespace"],
        object=var["object_object"])
    ```


    :param str bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
    :param str namespace: The top-level namespace used for the request.
    :param str object: The name of the object. Avoid entering confidential information. Example: `test/object1.log`
    """
    __args__ = dict()
    __args__['bucket'] = bucket
    __args__['namespace'] = namespace
    __args__['object'] = object
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:ObjectStorage/getObjectHead:getObjectHead', __args__, opts=opts, typ=GetObjectHeadResult).value

    return AwaitableGetObjectHeadResult(
        archival_state=__ret__.archival_state,
        bucket=__ret__.bucket,
        content_length=__ret__.content_length,
        content_type=__ret__.content_type,
        etag=__ret__.etag,
        id=__ret__.id,
        metadata=__ret__.metadata,
        namespace=__ret__.namespace,
        object=__ret__.object,
        storage_tier=__ret__.storage_tier)


@_utilities.lift_output_func(get_object_head)
def get_object_head_output(bucket: Optional[pulumi.Input[str]] = None,
                           namespace: Optional[pulumi.Input[str]] = None,
                           object: Optional[pulumi.Input[str]] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetObjectHeadResult]:
    """
    This data source provides details about metadata of a specific Object resource in Oracle Cloud Infrastructure Object Storage service.

    Gets the metadata of an object.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_object_head = oci.ObjectStorage.get_object_head(bucket=var["object_bucket"],
        namespace=var["object_namespace"],
        object=var["object_object"])
    ```


    :param str bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
    :param str namespace: The top-level namespace used for the request.
    :param str object: The name of the object. Avoid entering confidential information. Example: `test/object1.log`
    """
    ...
