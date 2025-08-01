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

__all__ = ['PathRouteSetArgs', 'PathRouteSet']

@pulumi.input_type
class PathRouteSetArgs:
    def __init__(__self__, *,
                 load_balancer_id: pulumi.Input[_builtins.str],
                 path_routes: pulumi.Input[Sequence[pulumi.Input['PathRouteSetPathRouteArgs']]],
                 name: Optional[pulumi.Input[_builtins.str]] = None):
        """
        The set of arguments for constructing a PathRouteSet resource.
        :param pulumi.Input[_builtins.str] load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the path route set to.
        :param pulumi.Input[Sequence[pulumi.Input['PathRouteSetPathRouteArgs']]] path_routes: (Updatable) The set of path route rules.
        :param pulumi.Input[_builtins.str] name: The name for this set of path route rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_path_route_set`
        """
        pulumi.set(__self__, "load_balancer_id", load_balancer_id)
        pulumi.set(__self__, "path_routes", path_routes)
        if name is not None:
            pulumi.set(__self__, "name", name)

    @_builtins.property
    @pulumi.getter(name="loadBalancerId")
    def load_balancer_id(self) -> pulumi.Input[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the path route set to.
        """
        return pulumi.get(self, "load_balancer_id")

    @load_balancer_id.setter
    def load_balancer_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "load_balancer_id", value)

    @_builtins.property
    @pulumi.getter(name="pathRoutes")
    def path_routes(self) -> pulumi.Input[Sequence[pulumi.Input['PathRouteSetPathRouteArgs']]]:
        """
        (Updatable) The set of path route rules.
        """
        return pulumi.get(self, "path_routes")

    @path_routes.setter
    def path_routes(self, value: pulumi.Input[Sequence[pulumi.Input['PathRouteSetPathRouteArgs']]]):
        pulumi.set(self, "path_routes", value)

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The name for this set of path route rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_path_route_set`
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "name", value)


@pulumi.input_type
class _PathRouteSetState:
    def __init__(__self__, *,
                 load_balancer_id: Optional[pulumi.Input[_builtins.str]] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 path_routes: Optional[pulumi.Input[Sequence[pulumi.Input['PathRouteSetPathRouteArgs']]]] = None,
                 state: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering PathRouteSet resources.
        :param pulumi.Input[_builtins.str] load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the path route set to.
        :param pulumi.Input[_builtins.str] name: The name for this set of path route rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_path_route_set`
        :param pulumi.Input[Sequence[pulumi.Input['PathRouteSetPathRouteArgs']]] path_routes: (Updatable) The set of path route rules.
        """
        if load_balancer_id is not None:
            pulumi.set(__self__, "load_balancer_id", load_balancer_id)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if path_routes is not None:
            pulumi.set(__self__, "path_routes", path_routes)
        if state is not None:
            pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="loadBalancerId")
    def load_balancer_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the path route set to.
        """
        return pulumi.get(self, "load_balancer_id")

    @load_balancer_id.setter
    def load_balancer_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "load_balancer_id", value)

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The name for this set of path route rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_path_route_set`
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter(name="pathRoutes")
    def path_routes(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['PathRouteSetPathRouteArgs']]]]:
        """
        (Updatable) The set of path route rules.
        """
        return pulumi.get(self, "path_routes")

    @path_routes.setter
    def path_routes(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['PathRouteSetPathRouteArgs']]]]):
        pulumi.set(self, "path_routes", value)

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[_builtins.str]]:
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "state", value)


@pulumi.type_token("oci:LoadBalancer/pathRouteSet:PathRouteSet")
class PathRouteSet(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 load_balancer_id: Optional[pulumi.Input[_builtins.str]] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 path_routes: Optional[pulumi.Input[Sequence[pulumi.Input[Union['PathRouteSetPathRouteArgs', 'PathRouteSetPathRouteArgsDict']]]]] = None,
                 __props__=None):
        """
        This resource provides the Path Route Set resource in Oracle Cloud Infrastructure Load Balancer service.

        Adds a path route set to a load balancer. For more information, see
        [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm).

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_path_route_set = oci.loadbalancer.PathRouteSet("test_path_route_set",
            load_balancer_id=test_load_balancer["id"],
            name=path_route_set_name,
            path_routes=[{
                "backend_set_name": test_backend_set["name"],
                "path": path_route_set_path_routes_path,
                "path_match_type": {
                    "match_type": path_route_set_path_routes_path_match_type_match_type,
                },
            }])
        ```

        ## Import

        PathRouteSets can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:LoadBalancer/pathRouteSet:PathRouteSet test_path_route_set "loadBalancers/{loadBalancerId}/pathRouteSets/{pathRouteSetName}"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the path route set to.
        :param pulumi.Input[_builtins.str] name: The name for this set of path route rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_path_route_set`
        :param pulumi.Input[Sequence[pulumi.Input[Union['PathRouteSetPathRouteArgs', 'PathRouteSetPathRouteArgsDict']]]] path_routes: (Updatable) The set of path route rules.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: PathRouteSetArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Path Route Set resource in Oracle Cloud Infrastructure Load Balancer service.

        Adds a path route set to a load balancer. For more information, see
        [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm).

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_path_route_set = oci.loadbalancer.PathRouteSet("test_path_route_set",
            load_balancer_id=test_load_balancer["id"],
            name=path_route_set_name,
            path_routes=[{
                "backend_set_name": test_backend_set["name"],
                "path": path_route_set_path_routes_path,
                "path_match_type": {
                    "match_type": path_route_set_path_routes_path_match_type_match_type,
                },
            }])
        ```

        ## Import

        PathRouteSets can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:LoadBalancer/pathRouteSet:PathRouteSet test_path_route_set "loadBalancers/{loadBalancerId}/pathRouteSets/{pathRouteSetName}"
        ```

        :param str resource_name: The name of the resource.
        :param PathRouteSetArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(PathRouteSetArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 load_balancer_id: Optional[pulumi.Input[_builtins.str]] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 path_routes: Optional[pulumi.Input[Sequence[pulumi.Input[Union['PathRouteSetPathRouteArgs', 'PathRouteSetPathRouteArgsDict']]]]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = PathRouteSetArgs.__new__(PathRouteSetArgs)

            if load_balancer_id is None and not opts.urn:
                raise TypeError("Missing required property 'load_balancer_id'")
            __props__.__dict__["load_balancer_id"] = load_balancer_id
            __props__.__dict__["name"] = name
            if path_routes is None and not opts.urn:
                raise TypeError("Missing required property 'path_routes'")
            __props__.__dict__["path_routes"] = path_routes
            __props__.__dict__["state"] = None
        super(PathRouteSet, __self__).__init__(
            'oci:LoadBalancer/pathRouteSet:PathRouteSet',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            load_balancer_id: Optional[pulumi.Input[_builtins.str]] = None,
            name: Optional[pulumi.Input[_builtins.str]] = None,
            path_routes: Optional[pulumi.Input[Sequence[pulumi.Input[Union['PathRouteSetPathRouteArgs', 'PathRouteSetPathRouteArgsDict']]]]] = None,
            state: Optional[pulumi.Input[_builtins.str]] = None) -> 'PathRouteSet':
        """
        Get an existing PathRouteSet resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the path route set to.
        :param pulumi.Input[_builtins.str] name: The name for this set of path route rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_path_route_set`
        :param pulumi.Input[Sequence[pulumi.Input[Union['PathRouteSetPathRouteArgs', 'PathRouteSetPathRouteArgsDict']]]] path_routes: (Updatable) The set of path route rules.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _PathRouteSetState.__new__(_PathRouteSetState)

        __props__.__dict__["load_balancer_id"] = load_balancer_id
        __props__.__dict__["name"] = name
        __props__.__dict__["path_routes"] = path_routes
        __props__.__dict__["state"] = state
        return PathRouteSet(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="loadBalancerId")
    def load_balancer_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the path route set to.
        """
        return pulumi.get(self, "load_balancer_id")

    @_builtins.property
    @pulumi.getter
    def name(self) -> pulumi.Output[_builtins.str]:
        """
        The name for this set of path route rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_path_route_set`
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="pathRoutes")
    def path_routes(self) -> pulumi.Output[Sequence['outputs.PathRouteSetPathRoute']]:
        """
        (Updatable) The set of path route rules.
        """
        return pulumi.get(self, "path_routes")

    @_builtins.property
    @pulumi.getter
    def state(self) -> pulumi.Output[_builtins.str]:
        return pulumi.get(self, "state")

