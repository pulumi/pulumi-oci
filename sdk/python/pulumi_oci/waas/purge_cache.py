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

__all__ = ['PurgeCacheArgs', 'PurgeCache']

@pulumi.input_type
class PurgeCacheArgs:
    def __init__(__self__, *,
                 waas_policy_id: pulumi.Input[_builtins.str],
                 resources: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None):
        """
        The set of arguments for constructing a PurgeCache resource.
        :param pulumi.Input[_builtins.str] waas_policy_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] resources: A resource to purge, specified by either a hostless absolute path starting with a single slash (Example: `/path/to/resource`) or by a relative path in which the first component will be interpreted as a domain protected by the WAAS policy (Example: `example.com/path/to/resource`).
        """
        pulumi.set(__self__, "waas_policy_id", waas_policy_id)
        if resources is not None:
            pulumi.set(__self__, "resources", resources)

    @_builtins.property
    @pulumi.getter(name="waasPolicyId")
    def waas_policy_id(self) -> pulumi.Input[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "waas_policy_id")

    @waas_policy_id.setter
    def waas_policy_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "waas_policy_id", value)

    @_builtins.property
    @pulumi.getter
    def resources(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]:
        """
        A resource to purge, specified by either a hostless absolute path starting with a single slash (Example: `/path/to/resource`) or by a relative path in which the first component will be interpreted as a domain protected by the WAAS policy (Example: `example.com/path/to/resource`).
        """
        return pulumi.get(self, "resources")

    @resources.setter
    def resources(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "resources", value)


@pulumi.input_type
class _PurgeCacheState:
    def __init__(__self__, *,
                 resources: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 waas_policy_id: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering PurgeCache resources.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] resources: A resource to purge, specified by either a hostless absolute path starting with a single slash (Example: `/path/to/resource`) or by a relative path in which the first component will be interpreted as a domain protected by the WAAS policy (Example: `example.com/path/to/resource`).
        :param pulumi.Input[_builtins.str] waas_policy_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if resources is not None:
            pulumi.set(__self__, "resources", resources)
        if waas_policy_id is not None:
            pulumi.set(__self__, "waas_policy_id", waas_policy_id)

    @_builtins.property
    @pulumi.getter
    def resources(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]:
        """
        A resource to purge, specified by either a hostless absolute path starting with a single slash (Example: `/path/to/resource`) or by a relative path in which the first component will be interpreted as a domain protected by the WAAS policy (Example: `example.com/path/to/resource`).
        """
        return pulumi.get(self, "resources")

    @resources.setter
    def resources(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "resources", value)

    @_builtins.property
    @pulumi.getter(name="waasPolicyId")
    def waas_policy_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "waas_policy_id")

    @waas_policy_id.setter
    def waas_policy_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "waas_policy_id", value)


@pulumi.type_token("oci:Waas/purgeCache:PurgeCache")
class PurgeCache(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 resources: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 waas_policy_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Purge Cache resource in Oracle Cloud Infrastructure Web Application Acceleration and Security service.

        Performs a purge of the cache for each specified resource. If no resources are passed, the cache for the entire Web Application Firewall will be purged.
        For more information, see [Caching Rules](https://docs.cloud.oracle.com/iaas/Content/WAF/Tasks/cachingrules.htm#purge).

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_purge_cache = oci.waas.PurgeCache("test_purge_cache",
            waas_policy_id=test_waas_policy["id"],
            resources=purge_cache_resources)
        ```

        ## Import

        Import is not supported for this resource.

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] resources: A resource to purge, specified by either a hostless absolute path starting with a single slash (Example: `/path/to/resource`) or by a relative path in which the first component will be interpreted as a domain protected by the WAAS policy (Example: `example.com/path/to/resource`).
        :param pulumi.Input[_builtins.str] waas_policy_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: PurgeCacheArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Purge Cache resource in Oracle Cloud Infrastructure Web Application Acceleration and Security service.

        Performs a purge of the cache for each specified resource. If no resources are passed, the cache for the entire Web Application Firewall will be purged.
        For more information, see [Caching Rules](https://docs.cloud.oracle.com/iaas/Content/WAF/Tasks/cachingrules.htm#purge).

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_purge_cache = oci.waas.PurgeCache("test_purge_cache",
            waas_policy_id=test_waas_policy["id"],
            resources=purge_cache_resources)
        ```

        ## Import

        Import is not supported for this resource.

        :param str resource_name: The name of the resource.
        :param PurgeCacheArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(PurgeCacheArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 resources: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 waas_policy_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = PurgeCacheArgs.__new__(PurgeCacheArgs)

            __props__.__dict__["resources"] = resources
            if waas_policy_id is None and not opts.urn:
                raise TypeError("Missing required property 'waas_policy_id'")
            __props__.__dict__["waas_policy_id"] = waas_policy_id
        super(PurgeCache, __self__).__init__(
            'oci:Waas/purgeCache:PurgeCache',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            resources: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
            waas_policy_id: Optional[pulumi.Input[_builtins.str]] = None) -> 'PurgeCache':
        """
        Get an existing PurgeCache resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] resources: A resource to purge, specified by either a hostless absolute path starting with a single slash (Example: `/path/to/resource`) or by a relative path in which the first component will be interpreted as a domain protected by the WAAS policy (Example: `example.com/path/to/resource`).
        :param pulumi.Input[_builtins.str] waas_policy_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _PurgeCacheState.__new__(_PurgeCacheState)

        __props__.__dict__["resources"] = resources
        __props__.__dict__["waas_policy_id"] = waas_policy_id
        return PurgeCache(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter
    def resources(self) -> pulumi.Output[Optional[Sequence[_builtins.str]]]:
        """
        A resource to purge, specified by either a hostless absolute path starting with a single slash (Example: `/path/to/resource`) or by a relative path in which the first component will be interpreted as a domain protected by the WAAS policy (Example: `example.com/path/to/resource`).
        """
        return pulumi.get(self, "resources")

    @_builtins.property
    @pulumi.getter(name="waasPolicyId")
    def waas_policy_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "waas_policy_id")

