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
    'DatabaseToolsConnectionKeyStoreArgs',
    'DatabaseToolsConnectionKeyStoreArgsDict',
    'DatabaseToolsConnectionKeyStoreKeyStoreContentArgs',
    'DatabaseToolsConnectionKeyStoreKeyStoreContentArgsDict',
    'DatabaseToolsConnectionKeyStoreKeyStorePasswordArgs',
    'DatabaseToolsConnectionKeyStoreKeyStorePasswordArgsDict',
    'DatabaseToolsConnectionLockArgs',
    'DatabaseToolsConnectionLockArgsDict',
    'DatabaseToolsConnectionProxyClientArgs',
    'DatabaseToolsConnectionProxyClientArgsDict',
    'DatabaseToolsConnectionProxyClientUserPasswordArgs',
    'DatabaseToolsConnectionProxyClientUserPasswordArgsDict',
    'DatabaseToolsConnectionRelatedResourceArgs',
    'DatabaseToolsConnectionRelatedResourceArgsDict',
    'DatabaseToolsConnectionUserPasswordArgs',
    'DatabaseToolsConnectionUserPasswordArgsDict',
    'DatabaseToolsPrivateEndpointLockArgs',
    'DatabaseToolsPrivateEndpointLockArgsDict',
    'DatabaseToolsPrivateEndpointReverseConnectionConfigurationArgs',
    'DatabaseToolsPrivateEndpointReverseConnectionConfigurationArgsDict',
    'DatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIpArgs',
    'DatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIpArgsDict',
    'GetDatabaseToolsConnectionsFilterArgs',
    'GetDatabaseToolsConnectionsFilterArgsDict',
    'GetDatabaseToolsEndpointServicesFilterArgs',
    'GetDatabaseToolsEndpointServicesFilterArgsDict',
    'GetDatabaseToolsPrivateEndpointsFilterArgs',
    'GetDatabaseToolsPrivateEndpointsFilterArgsDict',
]

MYPY = False

if not MYPY:
    class DatabaseToolsConnectionKeyStoreArgsDict(TypedDict):
        key_store_content: NotRequired[pulumi.Input['DatabaseToolsConnectionKeyStoreKeyStoreContentArgsDict']]
        """
        (Updatable) The key store content.
        """
        key_store_password: NotRequired[pulumi.Input['DatabaseToolsConnectionKeyStoreKeyStorePasswordArgsDict']]
        """
        (Updatable) The key store password.
        """
        key_store_type: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The key store type.
        """
elif False:
    DatabaseToolsConnectionKeyStoreArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class DatabaseToolsConnectionKeyStoreArgs:
    def __init__(__self__, *,
                 key_store_content: Optional[pulumi.Input['DatabaseToolsConnectionKeyStoreKeyStoreContentArgs']] = None,
                 key_store_password: Optional[pulumi.Input['DatabaseToolsConnectionKeyStoreKeyStorePasswordArgs']] = None,
                 key_store_type: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input['DatabaseToolsConnectionKeyStoreKeyStoreContentArgs'] key_store_content: (Updatable) The key store content.
        :param pulumi.Input['DatabaseToolsConnectionKeyStoreKeyStorePasswordArgs'] key_store_password: (Updatable) The key store password.
        :param pulumi.Input[_builtins.str] key_store_type: (Updatable) The key store type.
        """
        if key_store_content is not None:
            pulumi.set(__self__, "key_store_content", key_store_content)
        if key_store_password is not None:
            pulumi.set(__self__, "key_store_password", key_store_password)
        if key_store_type is not None:
            pulumi.set(__self__, "key_store_type", key_store_type)

    @_builtins.property
    @pulumi.getter(name="keyStoreContent")
    def key_store_content(self) -> Optional[pulumi.Input['DatabaseToolsConnectionKeyStoreKeyStoreContentArgs']]:
        """
        (Updatable) The key store content.
        """
        return pulumi.get(self, "key_store_content")

    @key_store_content.setter
    def key_store_content(self, value: Optional[pulumi.Input['DatabaseToolsConnectionKeyStoreKeyStoreContentArgs']]):
        pulumi.set(self, "key_store_content", value)

    @_builtins.property
    @pulumi.getter(name="keyStorePassword")
    def key_store_password(self) -> Optional[pulumi.Input['DatabaseToolsConnectionKeyStoreKeyStorePasswordArgs']]:
        """
        (Updatable) The key store password.
        """
        return pulumi.get(self, "key_store_password")

    @key_store_password.setter
    def key_store_password(self, value: Optional[pulumi.Input['DatabaseToolsConnectionKeyStoreKeyStorePasswordArgs']]):
        pulumi.set(self, "key_store_password", value)

    @_builtins.property
    @pulumi.getter(name="keyStoreType")
    def key_store_type(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The key store type.
        """
        return pulumi.get(self, "key_store_type")

    @key_store_type.setter
    def key_store_type(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "key_store_type", value)


if not MYPY:
    class DatabaseToolsConnectionKeyStoreKeyStoreContentArgsDict(TypedDict):
        value_type: pulumi.Input[_builtins.str]
        """
        (Updatable) The value type of the key store content.
        """
        secret_id: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the key store.
        """
elif False:
    DatabaseToolsConnectionKeyStoreKeyStoreContentArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class DatabaseToolsConnectionKeyStoreKeyStoreContentArgs:
    def __init__(__self__, *,
                 value_type: pulumi.Input[_builtins.str],
                 secret_id: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input[_builtins.str] value_type: (Updatable) The value type of the key store content.
        :param pulumi.Input[_builtins.str] secret_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the key store.
        """
        pulumi.set(__self__, "value_type", value_type)
        if secret_id is not None:
            pulumi.set(__self__, "secret_id", secret_id)

    @_builtins.property
    @pulumi.getter(name="valueType")
    def value_type(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) The value type of the key store content.
        """
        return pulumi.get(self, "value_type")

    @value_type.setter
    def value_type(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "value_type", value)

    @_builtins.property
    @pulumi.getter(name="secretId")
    def secret_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the key store.
        """
        return pulumi.get(self, "secret_id")

    @secret_id.setter
    def secret_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "secret_id", value)


if not MYPY:
    class DatabaseToolsConnectionKeyStoreKeyStorePasswordArgsDict(TypedDict):
        value_type: pulumi.Input[_builtins.str]
        """
        (Updatable) The value type of the key store password.
        """
        secret_id: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the key store password.
        """
elif False:
    DatabaseToolsConnectionKeyStoreKeyStorePasswordArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class DatabaseToolsConnectionKeyStoreKeyStorePasswordArgs:
    def __init__(__self__, *,
                 value_type: pulumi.Input[_builtins.str],
                 secret_id: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input[_builtins.str] value_type: (Updatable) The value type of the key store password.
        :param pulumi.Input[_builtins.str] secret_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the key store password.
        """
        pulumi.set(__self__, "value_type", value_type)
        if secret_id is not None:
            pulumi.set(__self__, "secret_id", secret_id)

    @_builtins.property
    @pulumi.getter(name="valueType")
    def value_type(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) The value type of the key store password.
        """
        return pulumi.get(self, "value_type")

    @value_type.setter
    def value_type(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "value_type", value)

    @_builtins.property
    @pulumi.getter(name="secretId")
    def secret_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the key store password.
        """
        return pulumi.get(self, "secret_id")

    @secret_id.setter
    def secret_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "secret_id", value)


if not MYPY:
    class DatabaseToolsConnectionLockArgsDict(TypedDict):
        type: pulumi.Input[_builtins.str]
        """
        Type of the lock.
        """
        message: NotRequired[pulumi.Input[_builtins.str]]
        """
        A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
        """
        related_resource_id: NotRequired[pulumi.Input[_builtins.str]]
        """
        The id of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
        """
        time_created: NotRequired[pulumi.Input[_builtins.str]]
        """
        When the lock was created.
        """
elif False:
    DatabaseToolsConnectionLockArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class DatabaseToolsConnectionLockArgs:
    def __init__(__self__, *,
                 type: pulumi.Input[_builtins.str],
                 message: Optional[pulumi.Input[_builtins.str]] = None,
                 related_resource_id: Optional[pulumi.Input[_builtins.str]] = None,
                 time_created: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input[_builtins.str] type: Type of the lock.
        :param pulumi.Input[_builtins.str] message: A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
        :param pulumi.Input[_builtins.str] related_resource_id: The id of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
        :param pulumi.Input[_builtins.str] time_created: When the lock was created.
        """
        pulumi.set(__self__, "type", type)
        if message is not None:
            pulumi.set(__self__, "message", message)
        if related_resource_id is not None:
            pulumi.set(__self__, "related_resource_id", related_resource_id)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)

    @_builtins.property
    @pulumi.getter
    def type(self) -> pulumi.Input[_builtins.str]:
        """
        Type of the lock.
        """
        return pulumi.get(self, "type")

    @type.setter
    def type(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "type", value)

    @_builtins.property
    @pulumi.getter
    def message(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
        """
        return pulumi.get(self, "message")

    @message.setter
    def message(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "message", value)

    @_builtins.property
    @pulumi.getter(name="relatedResourceId")
    def related_resource_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The id of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
        """
        return pulumi.get(self, "related_resource_id")

    @related_resource_id.setter
    def related_resource_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "related_resource_id", value)

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        When the lock was created.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_created", value)


if not MYPY:
    class DatabaseToolsConnectionProxyClientArgsDict(TypedDict):
        proxy_authentication_type: pulumi.Input[_builtins.str]
        """
        (Updatable) The proxy authentication type.
        """
        roles: NotRequired[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]
        """
        (Updatable) A list of database roles for the client. These roles are enabled if the proxy is authorized to use the roles on behalf of the client.
        """
        user_name: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The user name.
        """
        user_password: NotRequired[pulumi.Input['DatabaseToolsConnectionProxyClientUserPasswordArgsDict']]
        """
        (Updatable) The user password.
        """
elif False:
    DatabaseToolsConnectionProxyClientArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class DatabaseToolsConnectionProxyClientArgs:
    def __init__(__self__, *,
                 proxy_authentication_type: pulumi.Input[_builtins.str],
                 roles: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 user_name: Optional[pulumi.Input[_builtins.str]] = None,
                 user_password: Optional[pulumi.Input['DatabaseToolsConnectionProxyClientUserPasswordArgs']] = None):
        """
        :param pulumi.Input[_builtins.str] proxy_authentication_type: (Updatable) The proxy authentication type.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] roles: (Updatable) A list of database roles for the client. These roles are enabled if the proxy is authorized to use the roles on behalf of the client.
        :param pulumi.Input[_builtins.str] user_name: (Updatable) The user name.
        :param pulumi.Input['DatabaseToolsConnectionProxyClientUserPasswordArgs'] user_password: (Updatable) The user password.
        """
        pulumi.set(__self__, "proxy_authentication_type", proxy_authentication_type)
        if roles is not None:
            pulumi.set(__self__, "roles", roles)
        if user_name is not None:
            pulumi.set(__self__, "user_name", user_name)
        if user_password is not None:
            pulumi.set(__self__, "user_password", user_password)

    @_builtins.property
    @pulumi.getter(name="proxyAuthenticationType")
    def proxy_authentication_type(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) The proxy authentication type.
        """
        return pulumi.get(self, "proxy_authentication_type")

    @proxy_authentication_type.setter
    def proxy_authentication_type(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "proxy_authentication_type", value)

    @_builtins.property
    @pulumi.getter
    def roles(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) A list of database roles for the client. These roles are enabled if the proxy is authorized to use the roles on behalf of the client.
        """
        return pulumi.get(self, "roles")

    @roles.setter
    def roles(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "roles", value)

    @_builtins.property
    @pulumi.getter(name="userName")
    def user_name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The user name.
        """
        return pulumi.get(self, "user_name")

    @user_name.setter
    def user_name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "user_name", value)

    @_builtins.property
    @pulumi.getter(name="userPassword")
    def user_password(self) -> Optional[pulumi.Input['DatabaseToolsConnectionProxyClientUserPasswordArgs']]:
        """
        (Updatable) The user password.
        """
        return pulumi.get(self, "user_password")

    @user_password.setter
    def user_password(self, value: Optional[pulumi.Input['DatabaseToolsConnectionProxyClientUserPasswordArgs']]):
        pulumi.set(self, "user_password", value)


if not MYPY:
    class DatabaseToolsConnectionProxyClientUserPasswordArgsDict(TypedDict):
        secret_id: pulumi.Input[_builtins.str]
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the user password.
        """
        value_type: pulumi.Input[_builtins.str]
        """
        (Updatable) The value type of the user password.
        """
elif False:
    DatabaseToolsConnectionProxyClientUserPasswordArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class DatabaseToolsConnectionProxyClientUserPasswordArgs:
    def __init__(__self__, *,
                 secret_id: pulumi.Input[_builtins.str],
                 value_type: pulumi.Input[_builtins.str]):
        """
        :param pulumi.Input[_builtins.str] secret_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the user password.
        :param pulumi.Input[_builtins.str] value_type: (Updatable) The value type of the user password.
        """
        pulumi.set(__self__, "secret_id", secret_id)
        pulumi.set(__self__, "value_type", value_type)

    @_builtins.property
    @pulumi.getter(name="secretId")
    def secret_id(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the user password.
        """
        return pulumi.get(self, "secret_id")

    @secret_id.setter
    def secret_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "secret_id", value)

    @_builtins.property
    @pulumi.getter(name="valueType")
    def value_type(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) The value type of the user password.
        """
        return pulumi.get(self, "value_type")

    @value_type.setter
    def value_type(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "value_type", value)


if not MYPY:
    class DatabaseToolsConnectionRelatedResourceArgsDict(TypedDict):
        entity_type: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The resource entity type.
        """
        identifier: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related resource.
        """
elif False:
    DatabaseToolsConnectionRelatedResourceArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class DatabaseToolsConnectionRelatedResourceArgs:
    def __init__(__self__, *,
                 entity_type: Optional[pulumi.Input[_builtins.str]] = None,
                 identifier: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input[_builtins.str] entity_type: (Updatable) The resource entity type.
        :param pulumi.Input[_builtins.str] identifier: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related resource.
        """
        if entity_type is not None:
            pulumi.set(__self__, "entity_type", entity_type)
        if identifier is not None:
            pulumi.set(__self__, "identifier", identifier)

    @_builtins.property
    @pulumi.getter(name="entityType")
    def entity_type(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The resource entity type.
        """
        return pulumi.get(self, "entity_type")

    @entity_type.setter
    def entity_type(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "entity_type", value)

    @_builtins.property
    @pulumi.getter
    def identifier(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related resource.
        """
        return pulumi.get(self, "identifier")

    @identifier.setter
    def identifier(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "identifier", value)


if not MYPY:
    class DatabaseToolsConnectionUserPasswordArgsDict(TypedDict):
        secret_id: pulumi.Input[_builtins.str]
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the user password.
        """
        value_type: pulumi.Input[_builtins.str]
        """
        (Updatable) The value type of the user password.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
elif False:
    DatabaseToolsConnectionUserPasswordArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class DatabaseToolsConnectionUserPasswordArgs:
    def __init__(__self__, *,
                 secret_id: pulumi.Input[_builtins.str],
                 value_type: pulumi.Input[_builtins.str]):
        """
        :param pulumi.Input[_builtins.str] secret_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the user password.
        :param pulumi.Input[_builtins.str] value_type: (Updatable) The value type of the user password.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "secret_id", secret_id)
        pulumi.set(__self__, "value_type", value_type)

    @_builtins.property
    @pulumi.getter(name="secretId")
    def secret_id(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the user password.
        """
        return pulumi.get(self, "secret_id")

    @secret_id.setter
    def secret_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "secret_id", value)

    @_builtins.property
    @pulumi.getter(name="valueType")
    def value_type(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) The value type of the user password.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "value_type")

    @value_type.setter
    def value_type(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "value_type", value)


if not MYPY:
    class DatabaseToolsPrivateEndpointLockArgsDict(TypedDict):
        type: pulumi.Input[_builtins.str]
        """
        Type of the lock.
        """
        message: NotRequired[pulumi.Input[_builtins.str]]
        """
        A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
        """
        related_resource_id: NotRequired[pulumi.Input[_builtins.str]]
        """
        The id of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
        """
        time_created: NotRequired[pulumi.Input[_builtins.str]]
        """
        When the lock was created.
        """
elif False:
    DatabaseToolsPrivateEndpointLockArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class DatabaseToolsPrivateEndpointLockArgs:
    def __init__(__self__, *,
                 type: pulumi.Input[_builtins.str],
                 message: Optional[pulumi.Input[_builtins.str]] = None,
                 related_resource_id: Optional[pulumi.Input[_builtins.str]] = None,
                 time_created: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input[_builtins.str] type: Type of the lock.
        :param pulumi.Input[_builtins.str] message: A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
        :param pulumi.Input[_builtins.str] related_resource_id: The id of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
        :param pulumi.Input[_builtins.str] time_created: When the lock was created.
        """
        pulumi.set(__self__, "type", type)
        if message is not None:
            pulumi.set(__self__, "message", message)
        if related_resource_id is not None:
            pulumi.set(__self__, "related_resource_id", related_resource_id)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)

    @_builtins.property
    @pulumi.getter
    def type(self) -> pulumi.Input[_builtins.str]:
        """
        Type of the lock.
        """
        return pulumi.get(self, "type")

    @type.setter
    def type(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "type", value)

    @_builtins.property
    @pulumi.getter
    def message(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
        """
        return pulumi.get(self, "message")

    @message.setter
    def message(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "message", value)

    @_builtins.property
    @pulumi.getter(name="relatedResourceId")
    def related_resource_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The id of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
        """
        return pulumi.get(self, "related_resource_id")

    @related_resource_id.setter
    def related_resource_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "related_resource_id", value)

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        When the lock was created.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_created", value)


if not MYPY:
    class DatabaseToolsPrivateEndpointReverseConnectionConfigurationArgsDict(TypedDict):
        reverse_connections_source_ips: NotRequired[pulumi.Input[Sequence[pulumi.Input['DatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIpArgsDict']]]]
        """
        A list of IP addresses in the customer VCN to be used as the source IPs for reverse connection packets traveling from the service's VCN to the customer's VCN.
        """
elif False:
    DatabaseToolsPrivateEndpointReverseConnectionConfigurationArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class DatabaseToolsPrivateEndpointReverseConnectionConfigurationArgs:
    def __init__(__self__, *,
                 reverse_connections_source_ips: Optional[pulumi.Input[Sequence[pulumi.Input['DatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIpArgs']]]] = None):
        """
        :param pulumi.Input[Sequence[pulumi.Input['DatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIpArgs']]] reverse_connections_source_ips: A list of IP addresses in the customer VCN to be used as the source IPs for reverse connection packets traveling from the service's VCN to the customer's VCN.
        """
        if reverse_connections_source_ips is not None:
            pulumi.set(__self__, "reverse_connections_source_ips", reverse_connections_source_ips)

    @_builtins.property
    @pulumi.getter(name="reverseConnectionsSourceIps")
    def reverse_connections_source_ips(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['DatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIpArgs']]]]:
        """
        A list of IP addresses in the customer VCN to be used as the source IPs for reverse connection packets traveling from the service's VCN to the customer's VCN.
        """
        return pulumi.get(self, "reverse_connections_source_ips")

    @reverse_connections_source_ips.setter
    def reverse_connections_source_ips(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['DatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIpArgs']]]]):
        pulumi.set(self, "reverse_connections_source_ips", value)


if not MYPY:
    class DatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIpArgsDict(TypedDict):
        source_ip: NotRequired[pulumi.Input[_builtins.str]]
        """
        The IP address in the customer's VCN to be used as the source IP for reverse connection packets traveling from the customer's VCN to the service's VCN.
        """
elif False:
    DatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIpArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class DatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIpArgs:
    def __init__(__self__, *,
                 source_ip: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input[_builtins.str] source_ip: The IP address in the customer's VCN to be used as the source IP for reverse connection packets traveling from the customer's VCN to the service's VCN.
        """
        if source_ip is not None:
            pulumi.set(__self__, "source_ip", source_ip)

    @_builtins.property
    @pulumi.getter(name="sourceIp")
    def source_ip(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The IP address in the customer's VCN to be used as the source IP for reverse connection packets traveling from the customer's VCN to the service's VCN.
        """
        return pulumi.get(self, "source_ip")

    @source_ip.setter
    def source_ip(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "source_ip", value)


if not MYPY:
    class GetDatabaseToolsConnectionsFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetDatabaseToolsConnectionsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetDatabaseToolsConnectionsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetDatabaseToolsEndpointServicesFilterArgsDict(TypedDict):
        name: _builtins.str
        """
        A filter to return only resources that match the entire specified name.
        """
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetDatabaseToolsEndpointServicesFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetDatabaseToolsEndpointServicesFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        """
        :param _builtins.str name: A filter to return only resources that match the entire specified name.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        A filter to return only resources that match the entire specified name.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetDatabaseToolsPrivateEndpointsFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetDatabaseToolsPrivateEndpointsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetDatabaseToolsPrivateEndpointsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


