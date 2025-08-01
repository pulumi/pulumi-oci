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

__all__ = ['PeerArgs', 'Peer']

@pulumi.input_type
class PeerArgs:
    def __init__(__self__, *,
                 ad: pulumi.Input[_builtins.str],
                 blockchain_platform_id: pulumi.Input[_builtins.str],
                 ocpu_allocation_param: pulumi.Input['PeerOcpuAllocationParamArgs'],
                 role: pulumi.Input[_builtins.str],
                 alias: Optional[pulumi.Input[_builtins.str]] = None):
        """
        The set of arguments for constructing a Peer resource.
        :param pulumi.Input[_builtins.str] ad: Availability Domain to place new peer
        :param pulumi.Input[_builtins.str] blockchain_platform_id: Unique service identifier.
        :param pulumi.Input['PeerOcpuAllocationParamArgs'] ocpu_allocation_param: (Updatable) OCPU allocation parameter
        :param pulumi.Input[_builtins.str] role: Peer role
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] alias: peer alias
        """
        pulumi.set(__self__, "ad", ad)
        pulumi.set(__self__, "blockchain_platform_id", blockchain_platform_id)
        pulumi.set(__self__, "ocpu_allocation_param", ocpu_allocation_param)
        pulumi.set(__self__, "role", role)
        if alias is not None:
            pulumi.set(__self__, "alias", alias)

    @_builtins.property
    @pulumi.getter
    def ad(self) -> pulumi.Input[_builtins.str]:
        """
        Availability Domain to place new peer
        """
        return pulumi.get(self, "ad")

    @ad.setter
    def ad(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "ad", value)

    @_builtins.property
    @pulumi.getter(name="blockchainPlatformId")
    def blockchain_platform_id(self) -> pulumi.Input[_builtins.str]:
        """
        Unique service identifier.
        """
        return pulumi.get(self, "blockchain_platform_id")

    @blockchain_platform_id.setter
    def blockchain_platform_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "blockchain_platform_id", value)

    @_builtins.property
    @pulumi.getter(name="ocpuAllocationParam")
    def ocpu_allocation_param(self) -> pulumi.Input['PeerOcpuAllocationParamArgs']:
        """
        (Updatable) OCPU allocation parameter
        """
        return pulumi.get(self, "ocpu_allocation_param")

    @ocpu_allocation_param.setter
    def ocpu_allocation_param(self, value: pulumi.Input['PeerOcpuAllocationParamArgs']):
        pulumi.set(self, "ocpu_allocation_param", value)

    @_builtins.property
    @pulumi.getter
    def role(self) -> pulumi.Input[_builtins.str]:
        """
        Peer role


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "role")

    @role.setter
    def role(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "role", value)

    @_builtins.property
    @pulumi.getter
    def alias(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        peer alias
        """
        return pulumi.get(self, "alias")

    @alias.setter
    def alias(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "alias", value)


@pulumi.input_type
class _PeerState:
    def __init__(__self__, *,
                 ad: Optional[pulumi.Input[_builtins.str]] = None,
                 alias: Optional[pulumi.Input[_builtins.str]] = None,
                 blockchain_platform_id: Optional[pulumi.Input[_builtins.str]] = None,
                 host: Optional[pulumi.Input[_builtins.str]] = None,
                 ocpu_allocation_param: Optional[pulumi.Input['PeerOcpuAllocationParamArgs']] = None,
                 peer_key: Optional[pulumi.Input[_builtins.str]] = None,
                 role: Optional[pulumi.Input[_builtins.str]] = None,
                 state: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering Peer resources.
        :param pulumi.Input[_builtins.str] ad: Availability Domain to place new peer
        :param pulumi.Input[_builtins.str] alias: peer alias
        :param pulumi.Input[_builtins.str] blockchain_platform_id: Unique service identifier.
        :param pulumi.Input[_builtins.str] host: Host on which the Peer exists
        :param pulumi.Input['PeerOcpuAllocationParamArgs'] ocpu_allocation_param: (Updatable) OCPU allocation parameter
        :param pulumi.Input[_builtins.str] peer_key: peer identifier
        :param pulumi.Input[_builtins.str] role: Peer role
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] state: The current state of the peer.
        """
        if ad is not None:
            pulumi.set(__self__, "ad", ad)
        if alias is not None:
            pulumi.set(__self__, "alias", alias)
        if blockchain_platform_id is not None:
            pulumi.set(__self__, "blockchain_platform_id", blockchain_platform_id)
        if host is not None:
            pulumi.set(__self__, "host", host)
        if ocpu_allocation_param is not None:
            pulumi.set(__self__, "ocpu_allocation_param", ocpu_allocation_param)
        if peer_key is not None:
            pulumi.set(__self__, "peer_key", peer_key)
        if role is not None:
            pulumi.set(__self__, "role", role)
        if state is not None:
            pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter
    def ad(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Availability Domain to place new peer
        """
        return pulumi.get(self, "ad")

    @ad.setter
    def ad(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "ad", value)

    @_builtins.property
    @pulumi.getter
    def alias(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        peer alias
        """
        return pulumi.get(self, "alias")

    @alias.setter
    def alias(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "alias", value)

    @_builtins.property
    @pulumi.getter(name="blockchainPlatformId")
    def blockchain_platform_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Unique service identifier.
        """
        return pulumi.get(self, "blockchain_platform_id")

    @blockchain_platform_id.setter
    def blockchain_platform_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "blockchain_platform_id", value)

    @_builtins.property
    @pulumi.getter
    def host(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Host on which the Peer exists
        """
        return pulumi.get(self, "host")

    @host.setter
    def host(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "host", value)

    @_builtins.property
    @pulumi.getter(name="ocpuAllocationParam")
    def ocpu_allocation_param(self) -> Optional[pulumi.Input['PeerOcpuAllocationParamArgs']]:
        """
        (Updatable) OCPU allocation parameter
        """
        return pulumi.get(self, "ocpu_allocation_param")

    @ocpu_allocation_param.setter
    def ocpu_allocation_param(self, value: Optional[pulumi.Input['PeerOcpuAllocationParamArgs']]):
        pulumi.set(self, "ocpu_allocation_param", value)

    @_builtins.property
    @pulumi.getter(name="peerKey")
    def peer_key(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        peer identifier
        """
        return pulumi.get(self, "peer_key")

    @peer_key.setter
    def peer_key(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "peer_key", value)

    @_builtins.property
    @pulumi.getter
    def role(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Peer role


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "role")

    @role.setter
    def role(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "role", value)

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The current state of the peer.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "state", value)


@pulumi.type_token("oci:Blockchain/peer:Peer")
class Peer(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 ad: Optional[pulumi.Input[_builtins.str]] = None,
                 alias: Optional[pulumi.Input[_builtins.str]] = None,
                 blockchain_platform_id: Optional[pulumi.Input[_builtins.str]] = None,
                 ocpu_allocation_param: Optional[pulumi.Input[Union['PeerOcpuAllocationParamArgs', 'PeerOcpuAllocationParamArgsDict']]] = None,
                 role: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Peer resource in Oracle Cloud Infrastructure Blockchain service.

        Create Blockchain Platform Peer

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_peer = oci.blockchain.Peer("test_peer",
            ad=peer_ad,
            blockchain_platform_id=test_blockchain_platform["id"],
            ocpu_allocation_param={
                "ocpu_allocation_number": peer_ocpu_allocation_param_ocpu_allocation_number,
            },
            role=peer_role,
            alias=peer_alias)
        ```

        ## Import

        Peers can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:Blockchain/peer:Peer test_peer "blockchainPlatforms/{blockchainPlatformId}/peers/{peerId}"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] ad: Availability Domain to place new peer
        :param pulumi.Input[_builtins.str] alias: peer alias
        :param pulumi.Input[_builtins.str] blockchain_platform_id: Unique service identifier.
        :param pulumi.Input[Union['PeerOcpuAllocationParamArgs', 'PeerOcpuAllocationParamArgsDict']] ocpu_allocation_param: (Updatable) OCPU allocation parameter
        :param pulumi.Input[_builtins.str] role: Peer role
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: PeerArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Peer resource in Oracle Cloud Infrastructure Blockchain service.

        Create Blockchain Platform Peer

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_peer = oci.blockchain.Peer("test_peer",
            ad=peer_ad,
            blockchain_platform_id=test_blockchain_platform["id"],
            ocpu_allocation_param={
                "ocpu_allocation_number": peer_ocpu_allocation_param_ocpu_allocation_number,
            },
            role=peer_role,
            alias=peer_alias)
        ```

        ## Import

        Peers can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:Blockchain/peer:Peer test_peer "blockchainPlatforms/{blockchainPlatformId}/peers/{peerId}"
        ```

        :param str resource_name: The name of the resource.
        :param PeerArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(PeerArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 ad: Optional[pulumi.Input[_builtins.str]] = None,
                 alias: Optional[pulumi.Input[_builtins.str]] = None,
                 blockchain_platform_id: Optional[pulumi.Input[_builtins.str]] = None,
                 ocpu_allocation_param: Optional[pulumi.Input[Union['PeerOcpuAllocationParamArgs', 'PeerOcpuAllocationParamArgsDict']]] = None,
                 role: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = PeerArgs.__new__(PeerArgs)

            if ad is None and not opts.urn:
                raise TypeError("Missing required property 'ad'")
            __props__.__dict__["ad"] = ad
            __props__.__dict__["alias"] = alias
            if blockchain_platform_id is None and not opts.urn:
                raise TypeError("Missing required property 'blockchain_platform_id'")
            __props__.__dict__["blockchain_platform_id"] = blockchain_platform_id
            if ocpu_allocation_param is None and not opts.urn:
                raise TypeError("Missing required property 'ocpu_allocation_param'")
            __props__.__dict__["ocpu_allocation_param"] = ocpu_allocation_param
            if role is None and not opts.urn:
                raise TypeError("Missing required property 'role'")
            __props__.__dict__["role"] = role
            __props__.__dict__["host"] = None
            __props__.__dict__["peer_key"] = None
            __props__.__dict__["state"] = None
        super(Peer, __self__).__init__(
            'oci:Blockchain/peer:Peer',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            ad: Optional[pulumi.Input[_builtins.str]] = None,
            alias: Optional[pulumi.Input[_builtins.str]] = None,
            blockchain_platform_id: Optional[pulumi.Input[_builtins.str]] = None,
            host: Optional[pulumi.Input[_builtins.str]] = None,
            ocpu_allocation_param: Optional[pulumi.Input[Union['PeerOcpuAllocationParamArgs', 'PeerOcpuAllocationParamArgsDict']]] = None,
            peer_key: Optional[pulumi.Input[_builtins.str]] = None,
            role: Optional[pulumi.Input[_builtins.str]] = None,
            state: Optional[pulumi.Input[_builtins.str]] = None) -> 'Peer':
        """
        Get an existing Peer resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] ad: Availability Domain to place new peer
        :param pulumi.Input[_builtins.str] alias: peer alias
        :param pulumi.Input[_builtins.str] blockchain_platform_id: Unique service identifier.
        :param pulumi.Input[_builtins.str] host: Host on which the Peer exists
        :param pulumi.Input[Union['PeerOcpuAllocationParamArgs', 'PeerOcpuAllocationParamArgsDict']] ocpu_allocation_param: (Updatable) OCPU allocation parameter
        :param pulumi.Input[_builtins.str] peer_key: peer identifier
        :param pulumi.Input[_builtins.str] role: Peer role
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] state: The current state of the peer.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _PeerState.__new__(_PeerState)

        __props__.__dict__["ad"] = ad
        __props__.__dict__["alias"] = alias
        __props__.__dict__["blockchain_platform_id"] = blockchain_platform_id
        __props__.__dict__["host"] = host
        __props__.__dict__["ocpu_allocation_param"] = ocpu_allocation_param
        __props__.__dict__["peer_key"] = peer_key
        __props__.__dict__["role"] = role
        __props__.__dict__["state"] = state
        return Peer(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter
    def ad(self) -> pulumi.Output[_builtins.str]:
        """
        Availability Domain to place new peer
        """
        return pulumi.get(self, "ad")

    @_builtins.property
    @pulumi.getter
    def alias(self) -> pulumi.Output[_builtins.str]:
        """
        peer alias
        """
        return pulumi.get(self, "alias")

    @_builtins.property
    @pulumi.getter(name="blockchainPlatformId")
    def blockchain_platform_id(self) -> pulumi.Output[_builtins.str]:
        """
        Unique service identifier.
        """
        return pulumi.get(self, "blockchain_platform_id")

    @_builtins.property
    @pulumi.getter
    def host(self) -> pulumi.Output[_builtins.str]:
        """
        Host on which the Peer exists
        """
        return pulumi.get(self, "host")

    @_builtins.property
    @pulumi.getter(name="ocpuAllocationParam")
    def ocpu_allocation_param(self) -> pulumi.Output['outputs.PeerOcpuAllocationParam']:
        """
        (Updatable) OCPU allocation parameter
        """
        return pulumi.get(self, "ocpu_allocation_param")

    @_builtins.property
    @pulumi.getter(name="peerKey")
    def peer_key(self) -> pulumi.Output[_builtins.str]:
        """
        peer identifier
        """
        return pulumi.get(self, "peer_key")

    @_builtins.property
    @pulumi.getter
    def role(self) -> pulumi.Output[_builtins.str]:
        """
        Peer role


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "role")

    @_builtins.property
    @pulumi.getter
    def state(self) -> pulumi.Output[_builtins.str]:
        """
        The current state of the peer.
        """
        return pulumi.get(self, "state")

