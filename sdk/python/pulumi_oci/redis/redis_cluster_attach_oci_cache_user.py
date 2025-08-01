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

__all__ = ['RedisClusterAttachOciCacheUserArgs', 'RedisClusterAttachOciCacheUser']

@pulumi.input_type
class RedisClusterAttachOciCacheUserArgs:
    def __init__(__self__, *,
                 oci_cache_users: pulumi.Input[Sequence[pulumi.Input[_builtins.str]]],
                 redis_cluster_id: pulumi.Input[_builtins.str]):
        """
        The set of arguments for constructing a RedisClusterAttachOciCacheUser resource.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] oci_cache_users: List of Oracle Cloud Infrastructure cache user unique IDs (OCIDs).
        :param pulumi.Input[_builtins.str] redis_cluster_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "oci_cache_users", oci_cache_users)
        pulumi.set(__self__, "redis_cluster_id", redis_cluster_id)

    @_builtins.property
    @pulumi.getter(name="ociCacheUsers")
    def oci_cache_users(self) -> pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]:
        """
        List of Oracle Cloud Infrastructure cache user unique IDs (OCIDs).
        """
        return pulumi.get(self, "oci_cache_users")

    @oci_cache_users.setter
    def oci_cache_users(self, value: pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]):
        pulumi.set(self, "oci_cache_users", value)

    @_builtins.property
    @pulumi.getter(name="redisClusterId")
    def redis_cluster_id(self) -> pulumi.Input[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "redis_cluster_id")

    @redis_cluster_id.setter
    def redis_cluster_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "redis_cluster_id", value)


@pulumi.input_type
class _RedisClusterAttachOciCacheUserState:
    def __init__(__self__, *,
                 oci_cache_users: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 redis_cluster_id: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering RedisClusterAttachOciCacheUser resources.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] oci_cache_users: List of Oracle Cloud Infrastructure cache user unique IDs (OCIDs).
        :param pulumi.Input[_builtins.str] redis_cluster_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if oci_cache_users is not None:
            pulumi.set(__self__, "oci_cache_users", oci_cache_users)
        if redis_cluster_id is not None:
            pulumi.set(__self__, "redis_cluster_id", redis_cluster_id)

    @_builtins.property
    @pulumi.getter(name="ociCacheUsers")
    def oci_cache_users(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]:
        """
        List of Oracle Cloud Infrastructure cache user unique IDs (OCIDs).
        """
        return pulumi.get(self, "oci_cache_users")

    @oci_cache_users.setter
    def oci_cache_users(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "oci_cache_users", value)

    @_builtins.property
    @pulumi.getter(name="redisClusterId")
    def redis_cluster_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "redis_cluster_id")

    @redis_cluster_id.setter
    def redis_cluster_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "redis_cluster_id", value)


@pulumi.type_token("oci:Redis/redisClusterAttachOciCacheUser:RedisClusterAttachOciCacheUser")
class RedisClusterAttachOciCacheUser(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 oci_cache_users: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 redis_cluster_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Redis Cluster Attach Oci Cache User resource in Oracle Cloud Infrastructure Redis service.

        Attach existing Oracle Cloud Infrastructure cache users to a redis cluster.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_redis_cluster_attach_oci_cache_user = oci.redis.RedisClusterAttachOciCacheUser("test_redis_cluster_attach_oci_cache_user",
            oci_cache_users=redis_cluster_attach_oci_cache_user_oci_cache_users,
            redis_cluster_id=test_redis_cluster["id"])
        ```

        ## Import

        Import is not supported for this resource.

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] oci_cache_users: List of Oracle Cloud Infrastructure cache user unique IDs (OCIDs).
        :param pulumi.Input[_builtins.str] redis_cluster_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: RedisClusterAttachOciCacheUserArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Redis Cluster Attach Oci Cache User resource in Oracle Cloud Infrastructure Redis service.

        Attach existing Oracle Cloud Infrastructure cache users to a redis cluster.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_redis_cluster_attach_oci_cache_user = oci.redis.RedisClusterAttachOciCacheUser("test_redis_cluster_attach_oci_cache_user",
            oci_cache_users=redis_cluster_attach_oci_cache_user_oci_cache_users,
            redis_cluster_id=test_redis_cluster["id"])
        ```

        ## Import

        Import is not supported for this resource.

        :param str resource_name: The name of the resource.
        :param RedisClusterAttachOciCacheUserArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(RedisClusterAttachOciCacheUserArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 oci_cache_users: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 redis_cluster_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = RedisClusterAttachOciCacheUserArgs.__new__(RedisClusterAttachOciCacheUserArgs)

            if oci_cache_users is None and not opts.urn:
                raise TypeError("Missing required property 'oci_cache_users'")
            __props__.__dict__["oci_cache_users"] = oci_cache_users
            if redis_cluster_id is None and not opts.urn:
                raise TypeError("Missing required property 'redis_cluster_id'")
            __props__.__dict__["redis_cluster_id"] = redis_cluster_id
        super(RedisClusterAttachOciCacheUser, __self__).__init__(
            'oci:Redis/redisClusterAttachOciCacheUser:RedisClusterAttachOciCacheUser',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            oci_cache_users: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
            redis_cluster_id: Optional[pulumi.Input[_builtins.str]] = None) -> 'RedisClusterAttachOciCacheUser':
        """
        Get an existing RedisClusterAttachOciCacheUser resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] oci_cache_users: List of Oracle Cloud Infrastructure cache user unique IDs (OCIDs).
        :param pulumi.Input[_builtins.str] redis_cluster_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _RedisClusterAttachOciCacheUserState.__new__(_RedisClusterAttachOciCacheUserState)

        __props__.__dict__["oci_cache_users"] = oci_cache_users
        __props__.__dict__["redis_cluster_id"] = redis_cluster_id
        return RedisClusterAttachOciCacheUser(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="ociCacheUsers")
    def oci_cache_users(self) -> pulumi.Output[Sequence[_builtins.str]]:
        """
        List of Oracle Cloud Infrastructure cache user unique IDs (OCIDs).
        """
        return pulumi.get(self, "oci_cache_users")

    @_builtins.property
    @pulumi.getter(name="redisClusterId")
    def redis_cluster_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "redis_cluster_id")

