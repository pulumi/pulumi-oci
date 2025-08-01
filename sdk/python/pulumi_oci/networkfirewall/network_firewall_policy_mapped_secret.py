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

__all__ = ['NetworkFirewallPolicyMappedSecretArgs', 'NetworkFirewallPolicyMappedSecret']

@pulumi.input_type
class NetworkFirewallPolicyMappedSecretArgs:
    def __init__(__self__, *,
                 network_firewall_policy_id: pulumi.Input[_builtins.str],
                 source: pulumi.Input[_builtins.str],
                 type: pulumi.Input[_builtins.str],
                 vault_secret_id: pulumi.Input[_builtins.str],
                 version_number: pulumi.Input[_builtins.int],
                 name: Optional[pulumi.Input[_builtins.str]] = None):
        """
        The set of arguments for constructing a NetworkFirewallPolicyMappedSecret resource.
        :param pulumi.Input[_builtins.str] network_firewall_policy_id: Unique Network Firewall Policy identifier
        :param pulumi.Input[_builtins.str] source: Source of the secrets, where the secrets are stored. The only accepted value is `OCI_VAULT`
        :param pulumi.Input[_builtins.str] type: Type of the secrets mapped based on the policy.
               * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
               * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
        :param pulumi.Input[_builtins.str] vault_secret_id: (Updatable) OCID for the Vault Secret to be used.
        :param pulumi.Input[_builtins.int] version_number: (Updatable) Version number of the secret to be used.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] name: Unique name to identify the group of urls to be used in the policy rules.
        """
        pulumi.set(__self__, "network_firewall_policy_id", network_firewall_policy_id)
        pulumi.set(__self__, "source", source)
        pulumi.set(__self__, "type", type)
        pulumi.set(__self__, "vault_secret_id", vault_secret_id)
        pulumi.set(__self__, "version_number", version_number)
        if name is not None:
            pulumi.set(__self__, "name", name)

    @_builtins.property
    @pulumi.getter(name="networkFirewallPolicyId")
    def network_firewall_policy_id(self) -> pulumi.Input[_builtins.str]:
        """
        Unique Network Firewall Policy identifier
        """
        return pulumi.get(self, "network_firewall_policy_id")

    @network_firewall_policy_id.setter
    def network_firewall_policy_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "network_firewall_policy_id", value)

    @_builtins.property
    @pulumi.getter
    def source(self) -> pulumi.Input[_builtins.str]:
        """
        Source of the secrets, where the secrets are stored. The only accepted value is `OCI_VAULT`
        """
        return pulumi.get(self, "source")

    @source.setter
    def source(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "source", value)

    @_builtins.property
    @pulumi.getter
    def type(self) -> pulumi.Input[_builtins.str]:
        """
        Type of the secrets mapped based on the policy.
        * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
        * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
        """
        return pulumi.get(self, "type")

    @type.setter
    def type(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "type", value)

    @_builtins.property
    @pulumi.getter(name="vaultSecretId")
    def vault_secret_id(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) OCID for the Vault Secret to be used.
        """
        return pulumi.get(self, "vault_secret_id")

    @vault_secret_id.setter
    def vault_secret_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "vault_secret_id", value)

    @_builtins.property
    @pulumi.getter(name="versionNumber")
    def version_number(self) -> pulumi.Input[_builtins.int]:
        """
        (Updatable) Version number of the secret to be used.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "version_number")

    @version_number.setter
    def version_number(self, value: pulumi.Input[_builtins.int]):
        pulumi.set(self, "version_number", value)

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Unique name to identify the group of urls to be used in the policy rules.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "name", value)


@pulumi.input_type
class _NetworkFirewallPolicyMappedSecretState:
    def __init__(__self__, *,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 network_firewall_policy_id: Optional[pulumi.Input[_builtins.str]] = None,
                 parent_resource_id: Optional[pulumi.Input[_builtins.str]] = None,
                 source: Optional[pulumi.Input[_builtins.str]] = None,
                 type: Optional[pulumi.Input[_builtins.str]] = None,
                 vault_secret_id: Optional[pulumi.Input[_builtins.str]] = None,
                 version_number: Optional[pulumi.Input[_builtins.int]] = None):
        """
        Input properties used for looking up and filtering NetworkFirewallPolicyMappedSecret resources.
        :param pulumi.Input[_builtins.str] name: Unique name to identify the group of urls to be used in the policy rules.
        :param pulumi.Input[_builtins.str] network_firewall_policy_id: Unique Network Firewall Policy identifier
        :param pulumi.Input[_builtins.str] parent_resource_id: OCID of the Network Firewall Policy this Mapped Secret belongs to.
        :param pulumi.Input[_builtins.str] source: Source of the secrets, where the secrets are stored. The only accepted value is `OCI_VAULT`
        :param pulumi.Input[_builtins.str] type: Type of the secrets mapped based on the policy.
               * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
               * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
        :param pulumi.Input[_builtins.str] vault_secret_id: (Updatable) OCID for the Vault Secret to be used.
        :param pulumi.Input[_builtins.int] version_number: (Updatable) Version number of the secret to be used.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if name is not None:
            pulumi.set(__self__, "name", name)
        if network_firewall_policy_id is not None:
            pulumi.set(__self__, "network_firewall_policy_id", network_firewall_policy_id)
        if parent_resource_id is not None:
            pulumi.set(__self__, "parent_resource_id", parent_resource_id)
        if source is not None:
            pulumi.set(__self__, "source", source)
        if type is not None:
            pulumi.set(__self__, "type", type)
        if vault_secret_id is not None:
            pulumi.set(__self__, "vault_secret_id", vault_secret_id)
        if version_number is not None:
            pulumi.set(__self__, "version_number", version_number)

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Unique name to identify the group of urls to be used in the policy rules.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter(name="networkFirewallPolicyId")
    def network_firewall_policy_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Unique Network Firewall Policy identifier
        """
        return pulumi.get(self, "network_firewall_policy_id")

    @network_firewall_policy_id.setter
    def network_firewall_policy_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "network_firewall_policy_id", value)

    @_builtins.property
    @pulumi.getter(name="parentResourceId")
    def parent_resource_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        OCID of the Network Firewall Policy this Mapped Secret belongs to.
        """
        return pulumi.get(self, "parent_resource_id")

    @parent_resource_id.setter
    def parent_resource_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "parent_resource_id", value)

    @_builtins.property
    @pulumi.getter
    def source(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Source of the secrets, where the secrets are stored. The only accepted value is `OCI_VAULT`
        """
        return pulumi.get(self, "source")

    @source.setter
    def source(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "source", value)

    @_builtins.property
    @pulumi.getter
    def type(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Type of the secrets mapped based on the policy.
        * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
        * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
        """
        return pulumi.get(self, "type")

    @type.setter
    def type(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "type", value)

    @_builtins.property
    @pulumi.getter(name="vaultSecretId")
    def vault_secret_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) OCID for the Vault Secret to be used.
        """
        return pulumi.get(self, "vault_secret_id")

    @vault_secret_id.setter
    def vault_secret_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "vault_secret_id", value)

    @_builtins.property
    @pulumi.getter(name="versionNumber")
    def version_number(self) -> Optional[pulumi.Input[_builtins.int]]:
        """
        (Updatable) Version number of the secret to be used.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "version_number")

    @version_number.setter
    def version_number(self, value: Optional[pulumi.Input[_builtins.int]]):
        pulumi.set(self, "version_number", value)


@pulumi.type_token("oci:NetworkFirewall/networkFirewallPolicyMappedSecret:NetworkFirewallPolicyMappedSecret")
class NetworkFirewallPolicyMappedSecret(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 network_firewall_policy_id: Optional[pulumi.Input[_builtins.str]] = None,
                 source: Optional[pulumi.Input[_builtins.str]] = None,
                 type: Optional[pulumi.Input[_builtins.str]] = None,
                 vault_secret_id: Optional[pulumi.Input[_builtins.str]] = None,
                 version_number: Optional[pulumi.Input[_builtins.int]] = None,
                 __props__=None):
        """
        This resource provides the Network Firewall Policy Mapped Secret resource in Oracle Cloud Infrastructure Network Firewall service.

        Creates a new Mapped Secret for the Network Firewall Policy.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_network_firewall_policy_mapped_secret = oci.networkfirewall.NetworkFirewallPolicyMappedSecret("test_network_firewall_policy_mapped_secret",
            name=network_firewall_policy_mapped_secret_name,
            network_firewall_policy_id=test_network_firewall_policy["id"],
            source=network_firewall_policy_mapped_secret_source,
            type=network_firewall_policy_mapped_secret_type,
            vault_secret_id=test_secret["id"],
            version_number=network_firewall_policy_mapped_secret_version_number)
        ```

        ## Import

        NetworkFirewallPolicyMappedSecrets can be imported using the `name`, e.g.

        ```sh
        $ pulumi import oci:NetworkFirewall/networkFirewallPolicyMappedSecret:NetworkFirewallPolicyMappedSecret test_network_firewall_policy_mapped_secret "networkFirewallPolicies/{networkFirewallPolicyId}/mappedSecrets/{mappedSecretName}"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] name: Unique name to identify the group of urls to be used in the policy rules.
        :param pulumi.Input[_builtins.str] network_firewall_policy_id: Unique Network Firewall Policy identifier
        :param pulumi.Input[_builtins.str] source: Source of the secrets, where the secrets are stored. The only accepted value is `OCI_VAULT`
        :param pulumi.Input[_builtins.str] type: Type of the secrets mapped based on the policy.
               * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
               * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
        :param pulumi.Input[_builtins.str] vault_secret_id: (Updatable) OCID for the Vault Secret to be used.
        :param pulumi.Input[_builtins.int] version_number: (Updatable) Version number of the secret to be used.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: NetworkFirewallPolicyMappedSecretArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Network Firewall Policy Mapped Secret resource in Oracle Cloud Infrastructure Network Firewall service.

        Creates a new Mapped Secret for the Network Firewall Policy.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_network_firewall_policy_mapped_secret = oci.networkfirewall.NetworkFirewallPolicyMappedSecret("test_network_firewall_policy_mapped_secret",
            name=network_firewall_policy_mapped_secret_name,
            network_firewall_policy_id=test_network_firewall_policy["id"],
            source=network_firewall_policy_mapped_secret_source,
            type=network_firewall_policy_mapped_secret_type,
            vault_secret_id=test_secret["id"],
            version_number=network_firewall_policy_mapped_secret_version_number)
        ```

        ## Import

        NetworkFirewallPolicyMappedSecrets can be imported using the `name`, e.g.

        ```sh
        $ pulumi import oci:NetworkFirewall/networkFirewallPolicyMappedSecret:NetworkFirewallPolicyMappedSecret test_network_firewall_policy_mapped_secret "networkFirewallPolicies/{networkFirewallPolicyId}/mappedSecrets/{mappedSecretName}"
        ```

        :param str resource_name: The name of the resource.
        :param NetworkFirewallPolicyMappedSecretArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(NetworkFirewallPolicyMappedSecretArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 network_firewall_policy_id: Optional[pulumi.Input[_builtins.str]] = None,
                 source: Optional[pulumi.Input[_builtins.str]] = None,
                 type: Optional[pulumi.Input[_builtins.str]] = None,
                 vault_secret_id: Optional[pulumi.Input[_builtins.str]] = None,
                 version_number: Optional[pulumi.Input[_builtins.int]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = NetworkFirewallPolicyMappedSecretArgs.__new__(NetworkFirewallPolicyMappedSecretArgs)

            __props__.__dict__["name"] = name
            if network_firewall_policy_id is None and not opts.urn:
                raise TypeError("Missing required property 'network_firewall_policy_id'")
            __props__.__dict__["network_firewall_policy_id"] = network_firewall_policy_id
            if source is None and not opts.urn:
                raise TypeError("Missing required property 'source'")
            __props__.__dict__["source"] = source
            if type is None and not opts.urn:
                raise TypeError("Missing required property 'type'")
            __props__.__dict__["type"] = type
            if vault_secret_id is None and not opts.urn:
                raise TypeError("Missing required property 'vault_secret_id'")
            __props__.__dict__["vault_secret_id"] = vault_secret_id
            if version_number is None and not opts.urn:
                raise TypeError("Missing required property 'version_number'")
            __props__.__dict__["version_number"] = version_number
            __props__.__dict__["parent_resource_id"] = None
        super(NetworkFirewallPolicyMappedSecret, __self__).__init__(
            'oci:NetworkFirewall/networkFirewallPolicyMappedSecret:NetworkFirewallPolicyMappedSecret',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            name: Optional[pulumi.Input[_builtins.str]] = None,
            network_firewall_policy_id: Optional[pulumi.Input[_builtins.str]] = None,
            parent_resource_id: Optional[pulumi.Input[_builtins.str]] = None,
            source: Optional[pulumi.Input[_builtins.str]] = None,
            type: Optional[pulumi.Input[_builtins.str]] = None,
            vault_secret_id: Optional[pulumi.Input[_builtins.str]] = None,
            version_number: Optional[pulumi.Input[_builtins.int]] = None) -> 'NetworkFirewallPolicyMappedSecret':
        """
        Get an existing NetworkFirewallPolicyMappedSecret resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] name: Unique name to identify the group of urls to be used in the policy rules.
        :param pulumi.Input[_builtins.str] network_firewall_policy_id: Unique Network Firewall Policy identifier
        :param pulumi.Input[_builtins.str] parent_resource_id: OCID of the Network Firewall Policy this Mapped Secret belongs to.
        :param pulumi.Input[_builtins.str] source: Source of the secrets, where the secrets are stored. The only accepted value is `OCI_VAULT`
        :param pulumi.Input[_builtins.str] type: Type of the secrets mapped based on the policy.
               * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
               * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
        :param pulumi.Input[_builtins.str] vault_secret_id: (Updatable) OCID for the Vault Secret to be used.
        :param pulumi.Input[_builtins.int] version_number: (Updatable) Version number of the secret to be used.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _NetworkFirewallPolicyMappedSecretState.__new__(_NetworkFirewallPolicyMappedSecretState)

        __props__.__dict__["name"] = name
        __props__.__dict__["network_firewall_policy_id"] = network_firewall_policy_id
        __props__.__dict__["parent_resource_id"] = parent_resource_id
        __props__.__dict__["source"] = source
        __props__.__dict__["type"] = type
        __props__.__dict__["vault_secret_id"] = vault_secret_id
        __props__.__dict__["version_number"] = version_number
        return NetworkFirewallPolicyMappedSecret(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter
    def name(self) -> pulumi.Output[_builtins.str]:
        """
        Unique name to identify the group of urls to be used in the policy rules.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="networkFirewallPolicyId")
    def network_firewall_policy_id(self) -> pulumi.Output[_builtins.str]:
        """
        Unique Network Firewall Policy identifier
        """
        return pulumi.get(self, "network_firewall_policy_id")

    @_builtins.property
    @pulumi.getter(name="parentResourceId")
    def parent_resource_id(self) -> pulumi.Output[_builtins.str]:
        """
        OCID of the Network Firewall Policy this Mapped Secret belongs to.
        """
        return pulumi.get(self, "parent_resource_id")

    @_builtins.property
    @pulumi.getter
    def source(self) -> pulumi.Output[_builtins.str]:
        """
        Source of the secrets, where the secrets are stored. The only accepted value is `OCI_VAULT`
        """
        return pulumi.get(self, "source")

    @_builtins.property
    @pulumi.getter
    def type(self) -> pulumi.Output[_builtins.str]:
        """
        Type of the secrets mapped based on the policy.
        * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
        * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
        """
        return pulumi.get(self, "type")

    @_builtins.property
    @pulumi.getter(name="vaultSecretId")
    def vault_secret_id(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) OCID for the Vault Secret to be used.
        """
        return pulumi.get(self, "vault_secret_id")

    @_builtins.property
    @pulumi.getter(name="versionNumber")
    def version_number(self) -> pulumi.Output[_builtins.int]:
        """
        (Updatable) Version number of the secret to be used.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "version_number")

