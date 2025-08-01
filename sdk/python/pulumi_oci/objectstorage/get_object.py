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
    'GetObjectResult',
    'AwaitableGetObjectResult',
    'get_object',
    'get_object_output',
]

@pulumi.output_type
class GetObjectResult:
    """
    A collection of values returned by getObject.
    """
    def __init__(__self__, base64_encode_content=None, bucket=None, cache_control=None, content=None, content_disposition=None, content_encoding=None, content_language=None, content_length=None, content_length_limit=None, content_md5=None, content_type=None, http_response_cache_control=None, http_response_content_disposition=None, http_response_content_encoding=None, http_response_content_language=None, http_response_content_type=None, http_response_expires=None, id=None, metadata=None, namespace=None, object=None, storage_tier=None, version_id=None):
        if base64_encode_content and not isinstance(base64_encode_content, bool):
            raise TypeError("Expected argument 'base64_encode_content' to be a bool")
        pulumi.set(__self__, "base64_encode_content", base64_encode_content)
        if bucket and not isinstance(bucket, str):
            raise TypeError("Expected argument 'bucket' to be a str")
        pulumi.set(__self__, "bucket", bucket)
        if cache_control and not isinstance(cache_control, str):
            raise TypeError("Expected argument 'cache_control' to be a str")
        pulumi.set(__self__, "cache_control", cache_control)
        if content and not isinstance(content, str):
            raise TypeError("Expected argument 'content' to be a str")
        pulumi.set(__self__, "content", content)
        if content_disposition and not isinstance(content_disposition, str):
            raise TypeError("Expected argument 'content_disposition' to be a str")
        pulumi.set(__self__, "content_disposition", content_disposition)
        if content_encoding and not isinstance(content_encoding, str):
            raise TypeError("Expected argument 'content_encoding' to be a str")
        pulumi.set(__self__, "content_encoding", content_encoding)
        if content_language and not isinstance(content_language, str):
            raise TypeError("Expected argument 'content_language' to be a str")
        pulumi.set(__self__, "content_language", content_language)
        if content_length and not isinstance(content_length, str):
            raise TypeError("Expected argument 'content_length' to be a str")
        pulumi.set(__self__, "content_length", content_length)
        if content_length_limit and not isinstance(content_length_limit, int):
            raise TypeError("Expected argument 'content_length_limit' to be a int")
        pulumi.set(__self__, "content_length_limit", content_length_limit)
        if content_md5 and not isinstance(content_md5, str):
            raise TypeError("Expected argument 'content_md5' to be a str")
        pulumi.set(__self__, "content_md5", content_md5)
        if content_type and not isinstance(content_type, str):
            raise TypeError("Expected argument 'content_type' to be a str")
        pulumi.set(__self__, "content_type", content_type)
        if http_response_cache_control and not isinstance(http_response_cache_control, str):
            raise TypeError("Expected argument 'http_response_cache_control' to be a str")
        pulumi.set(__self__, "http_response_cache_control", http_response_cache_control)
        if http_response_content_disposition and not isinstance(http_response_content_disposition, str):
            raise TypeError("Expected argument 'http_response_content_disposition' to be a str")
        pulumi.set(__self__, "http_response_content_disposition", http_response_content_disposition)
        if http_response_content_encoding and not isinstance(http_response_content_encoding, str):
            raise TypeError("Expected argument 'http_response_content_encoding' to be a str")
        pulumi.set(__self__, "http_response_content_encoding", http_response_content_encoding)
        if http_response_content_language and not isinstance(http_response_content_language, str):
            raise TypeError("Expected argument 'http_response_content_language' to be a str")
        pulumi.set(__self__, "http_response_content_language", http_response_content_language)
        if http_response_content_type and not isinstance(http_response_content_type, str):
            raise TypeError("Expected argument 'http_response_content_type' to be a str")
        pulumi.set(__self__, "http_response_content_type", http_response_content_type)
        if http_response_expires and not isinstance(http_response_expires, str):
            raise TypeError("Expected argument 'http_response_expires' to be a str")
        pulumi.set(__self__, "http_response_expires", http_response_expires)
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
        if version_id and not isinstance(version_id, str):
            raise TypeError("Expected argument 'version_id' to be a str")
        pulumi.set(__self__, "version_id", version_id)

    @_builtins.property
    @pulumi.getter(name="base64EncodeContent")
    def base64_encode_content(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "base64_encode_content")

    @_builtins.property
    @pulumi.getter
    def bucket(self) -> _builtins.str:
        """
        The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        """
        return pulumi.get(self, "bucket")

    @_builtins.property
    @pulumi.getter(name="cacheControl")
    def cache_control(self) -> _builtins.str:
        return pulumi.get(self, "cache_control")

    @_builtins.property
    @pulumi.getter
    def content(self) -> _builtins.str:
        """
        The object to upload to the object store.
        """
        return pulumi.get(self, "content")

    @_builtins.property
    @pulumi.getter(name="contentDisposition")
    def content_disposition(self) -> _builtins.str:
        return pulumi.get(self, "content_disposition")

    @_builtins.property
    @pulumi.getter(name="contentEncoding")
    def content_encoding(self) -> _builtins.str:
        """
        The content encoding of the object.
        """
        return pulumi.get(self, "content_encoding")

    @_builtins.property
    @pulumi.getter(name="contentLanguage")
    def content_language(self) -> _builtins.str:
        """
        The content language of the object.
        """
        return pulumi.get(self, "content_language")

    @_builtins.property
    @pulumi.getter(name="contentLength")
    def content_length(self) -> _builtins.str:
        """
        The content length of the body.
        """
        return pulumi.get(self, "content_length")

    @_builtins.property
    @pulumi.getter(name="contentLengthLimit")
    def content_length_limit(self) -> Optional[_builtins.int]:
        return pulumi.get(self, "content_length_limit")

    @_builtins.property
    @pulumi.getter(name="contentMd5")
    def content_md5(self) -> _builtins.str:
        """
        The base-64 encoded MD5 hash of the body.
        """
        return pulumi.get(self, "content_md5")

    @_builtins.property
    @pulumi.getter(name="contentType")
    def content_type(self) -> _builtins.str:
        """
        The content type of the object.  Defaults to 'application/octet-stream' if not overridden during the PutObject call.
        """
        return pulumi.get(self, "content_type")

    @_builtins.property
    @pulumi.getter(name="httpResponseCacheControl")
    def http_response_cache_control(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "http_response_cache_control")

    @_builtins.property
    @pulumi.getter(name="httpResponseContentDisposition")
    def http_response_content_disposition(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "http_response_content_disposition")

    @_builtins.property
    @pulumi.getter(name="httpResponseContentEncoding")
    def http_response_content_encoding(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "http_response_content_encoding")

    @_builtins.property
    @pulumi.getter(name="httpResponseContentLanguage")
    def http_response_content_language(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "http_response_content_language")

    @_builtins.property
    @pulumi.getter(name="httpResponseContentType")
    def http_response_content_type(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "http_response_content_type")

    @_builtins.property
    @pulumi.getter(name="httpResponseExpires")
    def http_response_expires(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "http_response_expires")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def metadata(self) -> Mapping[str, _builtins.str]:
        """
        Optional user-defined metadata key and value. Note: Metadata keys are case-insensitive and all returned keys will be lower case.
        """
        return pulumi.get(self, "metadata")

    @_builtins.property
    @pulumi.getter
    def namespace(self) -> _builtins.str:
        """
        The top-level namespace used for the request.
        """
        return pulumi.get(self, "namespace")

    @_builtins.property
    @pulumi.getter
    def object(self) -> _builtins.str:
        """
        The name of the object. Avoid entering confidential information. Example: `test/object1.log`
        """
        return pulumi.get(self, "object")

    @_builtins.property
    @pulumi.getter(name="storageTier")
    def storage_tier(self) -> _builtins.str:
        """
        The storage tier that the object is stored in.
        """
        return pulumi.get(self, "storage_tier")

    @_builtins.property
    @pulumi.getter(name="versionId")
    def version_id(self) -> _builtins.str:
        return pulumi.get(self, "version_id")


class AwaitableGetObjectResult(GetObjectResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetObjectResult(
            base64_encode_content=self.base64_encode_content,
            bucket=self.bucket,
            cache_control=self.cache_control,
            content=self.content,
            content_disposition=self.content_disposition,
            content_encoding=self.content_encoding,
            content_language=self.content_language,
            content_length=self.content_length,
            content_length_limit=self.content_length_limit,
            content_md5=self.content_md5,
            content_type=self.content_type,
            http_response_cache_control=self.http_response_cache_control,
            http_response_content_disposition=self.http_response_content_disposition,
            http_response_content_encoding=self.http_response_content_encoding,
            http_response_content_language=self.http_response_content_language,
            http_response_content_type=self.http_response_content_type,
            http_response_expires=self.http_response_expires,
            id=self.id,
            metadata=self.metadata,
            namespace=self.namespace,
            object=self.object,
            storage_tier=self.storage_tier,
            version_id=self.version_id)


def get_object(base64_encode_content: Optional[_builtins.bool] = None,
               bucket: Optional[_builtins.str] = None,
               content_length_limit: Optional[_builtins.int] = None,
               http_response_cache_control: Optional[_builtins.str] = None,
               http_response_content_disposition: Optional[_builtins.str] = None,
               http_response_content_encoding: Optional[_builtins.str] = None,
               http_response_content_language: Optional[_builtins.str] = None,
               http_response_content_type: Optional[_builtins.str] = None,
               http_response_expires: Optional[_builtins.str] = None,
               namespace: Optional[_builtins.str] = None,
               object: Optional[_builtins.str] = None,
               version_id: Optional[_builtins.str] = None,
               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetObjectResult:
    """
    This data source provides details about a specific Object resource in Oracle Cloud Infrastructure Object Storage service.

    Gets the metadata and body of an object.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_object = oci.ObjectStorage.get_object(bucket=object_bucket,
        namespace=object_namespace,
        object=object_object,
        http_response_cache_control=object_http_response_cache_control,
        http_response_content_disposition=object_http_response_content_disposition,
        http_response_content_encoding=object_http_response_content_encoding,
        http_response_content_language=object_http_response_content_language,
        http_response_content_type=object_http_response_content_type,
        http_response_expires=object_http_response_expires,
        version_id=test_version["id"])
    ```


    :param _builtins.str bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
    :param _builtins.int content_length_limit: The limit of the content length of the object body to download from the object store. The default is 1Mb.
    :param _builtins.str http_response_cache_control: Specify this query parameter to override the Cache-Control response header in the GetObject response.
    :param _builtins.str http_response_content_disposition: Specify this query parameter to override the value of the Content-Disposition response header in the GetObject response.
    :param _builtins.str http_response_content_encoding: Specify this query parameter to override the Content-Encoding response header in the GetObject response.
    :param _builtins.str http_response_content_language: Specify this query parameter to override the Content-Language response header in the GetObject response.
    :param _builtins.str http_response_content_type: Specify this query parameter to override the Content-Type response header in the GetObject response.
    :param _builtins.str http_response_expires: Specify this query parameter to override the Expires response header in the GetObject response.
    :param _builtins.str namespace: The Object Storage namespace used for the request.
    :param _builtins.str object: The name of the object. Avoid entering confidential information. Example: `test/object1.log`
    :param _builtins.str version_id: VersionId used to identify a particular version of the object
    """
    __args__ = dict()
    __args__['base64EncodeContent'] = base64_encode_content
    __args__['bucket'] = bucket
    __args__['contentLengthLimit'] = content_length_limit
    __args__['httpResponseCacheControl'] = http_response_cache_control
    __args__['httpResponseContentDisposition'] = http_response_content_disposition
    __args__['httpResponseContentEncoding'] = http_response_content_encoding
    __args__['httpResponseContentLanguage'] = http_response_content_language
    __args__['httpResponseContentType'] = http_response_content_type
    __args__['httpResponseExpires'] = http_response_expires
    __args__['namespace'] = namespace
    __args__['object'] = object
    __args__['versionId'] = version_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ObjectStorage/getObject:getObject', __args__, opts=opts, typ=GetObjectResult).value

    return AwaitableGetObjectResult(
        base64_encode_content=pulumi.get(__ret__, 'base64_encode_content'),
        bucket=pulumi.get(__ret__, 'bucket'),
        cache_control=pulumi.get(__ret__, 'cache_control'),
        content=pulumi.get(__ret__, 'content'),
        content_disposition=pulumi.get(__ret__, 'content_disposition'),
        content_encoding=pulumi.get(__ret__, 'content_encoding'),
        content_language=pulumi.get(__ret__, 'content_language'),
        content_length=pulumi.get(__ret__, 'content_length'),
        content_length_limit=pulumi.get(__ret__, 'content_length_limit'),
        content_md5=pulumi.get(__ret__, 'content_md5'),
        content_type=pulumi.get(__ret__, 'content_type'),
        http_response_cache_control=pulumi.get(__ret__, 'http_response_cache_control'),
        http_response_content_disposition=pulumi.get(__ret__, 'http_response_content_disposition'),
        http_response_content_encoding=pulumi.get(__ret__, 'http_response_content_encoding'),
        http_response_content_language=pulumi.get(__ret__, 'http_response_content_language'),
        http_response_content_type=pulumi.get(__ret__, 'http_response_content_type'),
        http_response_expires=pulumi.get(__ret__, 'http_response_expires'),
        id=pulumi.get(__ret__, 'id'),
        metadata=pulumi.get(__ret__, 'metadata'),
        namespace=pulumi.get(__ret__, 'namespace'),
        object=pulumi.get(__ret__, 'object'),
        storage_tier=pulumi.get(__ret__, 'storage_tier'),
        version_id=pulumi.get(__ret__, 'version_id'))
def get_object_output(base64_encode_content: Optional[pulumi.Input[Optional[_builtins.bool]]] = None,
                      bucket: Optional[pulumi.Input[_builtins.str]] = None,
                      content_length_limit: Optional[pulumi.Input[Optional[_builtins.int]]] = None,
                      http_response_cache_control: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                      http_response_content_disposition: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                      http_response_content_encoding: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                      http_response_content_language: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                      http_response_content_type: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                      http_response_expires: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                      namespace: Optional[pulumi.Input[_builtins.str]] = None,
                      object: Optional[pulumi.Input[_builtins.str]] = None,
                      version_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                      opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetObjectResult]:
    """
    This data source provides details about a specific Object resource in Oracle Cloud Infrastructure Object Storage service.

    Gets the metadata and body of an object.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_object = oci.ObjectStorage.get_object(bucket=object_bucket,
        namespace=object_namespace,
        object=object_object,
        http_response_cache_control=object_http_response_cache_control,
        http_response_content_disposition=object_http_response_content_disposition,
        http_response_content_encoding=object_http_response_content_encoding,
        http_response_content_language=object_http_response_content_language,
        http_response_content_type=object_http_response_content_type,
        http_response_expires=object_http_response_expires,
        version_id=test_version["id"])
    ```


    :param _builtins.str bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
    :param _builtins.int content_length_limit: The limit of the content length of the object body to download from the object store. The default is 1Mb.
    :param _builtins.str http_response_cache_control: Specify this query parameter to override the Cache-Control response header in the GetObject response.
    :param _builtins.str http_response_content_disposition: Specify this query parameter to override the value of the Content-Disposition response header in the GetObject response.
    :param _builtins.str http_response_content_encoding: Specify this query parameter to override the Content-Encoding response header in the GetObject response.
    :param _builtins.str http_response_content_language: Specify this query parameter to override the Content-Language response header in the GetObject response.
    :param _builtins.str http_response_content_type: Specify this query parameter to override the Content-Type response header in the GetObject response.
    :param _builtins.str http_response_expires: Specify this query parameter to override the Expires response header in the GetObject response.
    :param _builtins.str namespace: The Object Storage namespace used for the request.
    :param _builtins.str object: The name of the object. Avoid entering confidential information. Example: `test/object1.log`
    :param _builtins.str version_id: VersionId used to identify a particular version of the object
    """
    __args__ = dict()
    __args__['base64EncodeContent'] = base64_encode_content
    __args__['bucket'] = bucket
    __args__['contentLengthLimit'] = content_length_limit
    __args__['httpResponseCacheControl'] = http_response_cache_control
    __args__['httpResponseContentDisposition'] = http_response_content_disposition
    __args__['httpResponseContentEncoding'] = http_response_content_encoding
    __args__['httpResponseContentLanguage'] = http_response_content_language
    __args__['httpResponseContentType'] = http_response_content_type
    __args__['httpResponseExpires'] = http_response_expires
    __args__['namespace'] = namespace
    __args__['object'] = object
    __args__['versionId'] = version_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:ObjectStorage/getObject:getObject', __args__, opts=opts, typ=GetObjectResult)
    return __ret__.apply(lambda __response__: GetObjectResult(
        base64_encode_content=pulumi.get(__response__, 'base64_encode_content'),
        bucket=pulumi.get(__response__, 'bucket'),
        cache_control=pulumi.get(__response__, 'cache_control'),
        content=pulumi.get(__response__, 'content'),
        content_disposition=pulumi.get(__response__, 'content_disposition'),
        content_encoding=pulumi.get(__response__, 'content_encoding'),
        content_language=pulumi.get(__response__, 'content_language'),
        content_length=pulumi.get(__response__, 'content_length'),
        content_length_limit=pulumi.get(__response__, 'content_length_limit'),
        content_md5=pulumi.get(__response__, 'content_md5'),
        content_type=pulumi.get(__response__, 'content_type'),
        http_response_cache_control=pulumi.get(__response__, 'http_response_cache_control'),
        http_response_content_disposition=pulumi.get(__response__, 'http_response_content_disposition'),
        http_response_content_encoding=pulumi.get(__response__, 'http_response_content_encoding'),
        http_response_content_language=pulumi.get(__response__, 'http_response_content_language'),
        http_response_content_type=pulumi.get(__response__, 'http_response_content_type'),
        http_response_expires=pulumi.get(__response__, 'http_response_expires'),
        id=pulumi.get(__response__, 'id'),
        metadata=pulumi.get(__response__, 'metadata'),
        namespace=pulumi.get(__response__, 'namespace'),
        object=pulumi.get(__response__, 'object'),
        storage_tier=pulumi.get(__response__, 'storage_tier'),
        version_id=pulumi.get(__response__, 'version_id')))
