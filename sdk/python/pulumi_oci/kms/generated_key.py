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
from ._inputs import *

__all__ = ['GeneratedKeyArgs', 'GeneratedKey']

@pulumi.input_type
class GeneratedKeyArgs:
    def __init__(__self__, *,
                 crypto_endpoint: pulumi.Input[str],
                 include_plaintext_key: pulumi.Input[bool],
                 key_id: pulumi.Input[str],
                 key_shape: pulumi.Input['GeneratedKeyKeyShapeArgs'],
                 associated_data: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 logging_context: Optional[pulumi.Input[Mapping[str, Any]]] = None):
        """
        The set of arguments for constructing a GeneratedKey resource.
        :param pulumi.Input[str] crypto_endpoint: The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
        :param pulumi.Input[bool] include_plaintext_key: If true, the generated key is also returned unencrypted.
        :param pulumi.Input[str] key_id: The OCID of the master encryption key to encrypt the generated data encryption key with.
        :param pulumi.Input['GeneratedKeyKeyShapeArgs'] key_shape: The cryptographic properties of a key.
        :param pulumi.Input[Mapping[str, Any]] associated_data: Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
        :param pulumi.Input[Mapping[str, Any]] logging_context: Information that provides context for audit logging. You can provide this additional data by formatting it as key-value pairs to include in audit logs when audit logging is enabled.
        """
        pulumi.set(__self__, "crypto_endpoint", crypto_endpoint)
        pulumi.set(__self__, "include_plaintext_key", include_plaintext_key)
        pulumi.set(__self__, "key_id", key_id)
        pulumi.set(__self__, "key_shape", key_shape)
        if associated_data is not None:
            pulumi.set(__self__, "associated_data", associated_data)
        if logging_context is not None:
            pulumi.set(__self__, "logging_context", logging_context)

    @property
    @pulumi.getter(name="cryptoEndpoint")
    def crypto_endpoint(self) -> pulumi.Input[str]:
        """
        The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
        """
        return pulumi.get(self, "crypto_endpoint")

    @crypto_endpoint.setter
    def crypto_endpoint(self, value: pulumi.Input[str]):
        pulumi.set(self, "crypto_endpoint", value)

    @property
    @pulumi.getter(name="includePlaintextKey")
    def include_plaintext_key(self) -> pulumi.Input[bool]:
        """
        If true, the generated key is also returned unencrypted.
        """
        return pulumi.get(self, "include_plaintext_key")

    @include_plaintext_key.setter
    def include_plaintext_key(self, value: pulumi.Input[bool]):
        pulumi.set(self, "include_plaintext_key", value)

    @property
    @pulumi.getter(name="keyId")
    def key_id(self) -> pulumi.Input[str]:
        """
        The OCID of the master encryption key to encrypt the generated data encryption key with.
        """
        return pulumi.get(self, "key_id")

    @key_id.setter
    def key_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "key_id", value)

    @property
    @pulumi.getter(name="keyShape")
    def key_shape(self) -> pulumi.Input['GeneratedKeyKeyShapeArgs']:
        """
        The cryptographic properties of a key.
        """
        return pulumi.get(self, "key_shape")

    @key_shape.setter
    def key_shape(self, value: pulumi.Input['GeneratedKeyKeyShapeArgs']):
        pulumi.set(self, "key_shape", value)

    @property
    @pulumi.getter(name="associatedData")
    def associated_data(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
        """
        return pulumi.get(self, "associated_data")

    @associated_data.setter
    def associated_data(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "associated_data", value)

    @property
    @pulumi.getter(name="loggingContext")
    def logging_context(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        Information that provides context for audit logging. You can provide this additional data by formatting it as key-value pairs to include in audit logs when audit logging is enabled.
        """
        return pulumi.get(self, "logging_context")

    @logging_context.setter
    def logging_context(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "logging_context", value)


@pulumi.input_type
class _GeneratedKeyState:
    def __init__(__self__, *,
                 associated_data: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 ciphertext: Optional[pulumi.Input[str]] = None,
                 crypto_endpoint: Optional[pulumi.Input[str]] = None,
                 include_plaintext_key: Optional[pulumi.Input[bool]] = None,
                 key_id: Optional[pulumi.Input[str]] = None,
                 key_shape: Optional[pulumi.Input['GeneratedKeyKeyShapeArgs']] = None,
                 logging_context: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 plaintext: Optional[pulumi.Input[str]] = None,
                 plaintext_checksum: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering GeneratedKey resources.
        :param pulumi.Input[Mapping[str, Any]] associated_data: Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
        :param pulumi.Input[str] ciphertext: The encrypted data encryption key generated from a master encryption key.
        :param pulumi.Input[str] crypto_endpoint: The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
        :param pulumi.Input[bool] include_plaintext_key: If true, the generated key is also returned unencrypted.
        :param pulumi.Input[str] key_id: The OCID of the master encryption key to encrypt the generated data encryption key with.
        :param pulumi.Input['GeneratedKeyKeyShapeArgs'] key_shape: The cryptographic properties of a key.
        :param pulumi.Input[Mapping[str, Any]] logging_context: Information that provides context for audit logging. You can provide this additional data by formatting it as key-value pairs to include in audit logs when audit logging is enabled.
        :param pulumi.Input[str] plaintext: The plaintext data encryption key, a base64-encoded sequence of random bytes, which is included if the [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) request includes the `includePlaintextKey` parameter and sets its value to "true".
        :param pulumi.Input[str] plaintext_checksum: The checksum of the plaintext data encryption key, which is included if the [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) request includes the `includePlaintextKey` parameter and sets its value to "true".
        """
        if associated_data is not None:
            pulumi.set(__self__, "associated_data", associated_data)
        if ciphertext is not None:
            pulumi.set(__self__, "ciphertext", ciphertext)
        if crypto_endpoint is not None:
            pulumi.set(__self__, "crypto_endpoint", crypto_endpoint)
        if include_plaintext_key is not None:
            pulumi.set(__self__, "include_plaintext_key", include_plaintext_key)
        if key_id is not None:
            pulumi.set(__self__, "key_id", key_id)
        if key_shape is not None:
            pulumi.set(__self__, "key_shape", key_shape)
        if logging_context is not None:
            pulumi.set(__self__, "logging_context", logging_context)
        if plaintext is not None:
            pulumi.set(__self__, "plaintext", plaintext)
        if plaintext_checksum is not None:
            pulumi.set(__self__, "plaintext_checksum", plaintext_checksum)

    @property
    @pulumi.getter(name="associatedData")
    def associated_data(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
        """
        return pulumi.get(self, "associated_data")

    @associated_data.setter
    def associated_data(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "associated_data", value)

    @property
    @pulumi.getter
    def ciphertext(self) -> Optional[pulumi.Input[str]]:
        """
        The encrypted data encryption key generated from a master encryption key.
        """
        return pulumi.get(self, "ciphertext")

    @ciphertext.setter
    def ciphertext(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "ciphertext", value)

    @property
    @pulumi.getter(name="cryptoEndpoint")
    def crypto_endpoint(self) -> Optional[pulumi.Input[str]]:
        """
        The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
        """
        return pulumi.get(self, "crypto_endpoint")

    @crypto_endpoint.setter
    def crypto_endpoint(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "crypto_endpoint", value)

    @property
    @pulumi.getter(name="includePlaintextKey")
    def include_plaintext_key(self) -> Optional[pulumi.Input[bool]]:
        """
        If true, the generated key is also returned unencrypted.
        """
        return pulumi.get(self, "include_plaintext_key")

    @include_plaintext_key.setter
    def include_plaintext_key(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "include_plaintext_key", value)

    @property
    @pulumi.getter(name="keyId")
    def key_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the master encryption key to encrypt the generated data encryption key with.
        """
        return pulumi.get(self, "key_id")

    @key_id.setter
    def key_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "key_id", value)

    @property
    @pulumi.getter(name="keyShape")
    def key_shape(self) -> Optional[pulumi.Input['GeneratedKeyKeyShapeArgs']]:
        """
        The cryptographic properties of a key.
        """
        return pulumi.get(self, "key_shape")

    @key_shape.setter
    def key_shape(self, value: Optional[pulumi.Input['GeneratedKeyKeyShapeArgs']]):
        pulumi.set(self, "key_shape", value)

    @property
    @pulumi.getter(name="loggingContext")
    def logging_context(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        Information that provides context for audit logging. You can provide this additional data by formatting it as key-value pairs to include in audit logs when audit logging is enabled.
        """
        return pulumi.get(self, "logging_context")

    @logging_context.setter
    def logging_context(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "logging_context", value)

    @property
    @pulumi.getter
    def plaintext(self) -> Optional[pulumi.Input[str]]:
        """
        The plaintext data encryption key, a base64-encoded sequence of random bytes, which is included if the [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) request includes the `includePlaintextKey` parameter and sets its value to "true".
        """
        return pulumi.get(self, "plaintext")

    @plaintext.setter
    def plaintext(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "plaintext", value)

    @property
    @pulumi.getter(name="plaintextChecksum")
    def plaintext_checksum(self) -> Optional[pulumi.Input[str]]:
        """
        The checksum of the plaintext data encryption key, which is included if the [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) request includes the `includePlaintextKey` parameter and sets its value to "true".
        """
        return pulumi.get(self, "plaintext_checksum")

    @plaintext_checksum.setter
    def plaintext_checksum(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "plaintext_checksum", value)


class GeneratedKey(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 associated_data: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 crypto_endpoint: Optional[pulumi.Input[str]] = None,
                 include_plaintext_key: Optional[pulumi.Input[bool]] = None,
                 key_id: Optional[pulumi.Input[str]] = None,
                 key_shape: Optional[pulumi.Input[pulumi.InputType['GeneratedKeyKeyShapeArgs']]] = None,
                 logging_context: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 __props__=None):
        """
        This resource provides the Generated Key resource in Oracle Cloud Infrastructure Kms service.

        Generates a key that you can use to encrypt or decrypt data.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_generated_key = oci.kms.GeneratedKey("testGeneratedKey",
            crypto_endpoint=var["generated_key_crypto_endpoint"],
            include_plaintext_key=var["generated_key_include_plaintext_key"],
            key_id=oci_kms_key["test_key"]["id"],
            key_shape=oci.kms.GeneratedKeyKeyShapeArgs(
                algorithm=var["generated_key_key_shape_algorithm"],
                length=var["generated_key_key_shape_length"],
                curve_id=oci_kms_curve["test_curve"]["id"],
            ),
            associated_data=var["generated_key_associated_data"],
            logging_context=var["generated_key_logging_context"])
        ```

        ## Import

        Import is not supported for this resource.

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Mapping[str, Any]] associated_data: Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
        :param pulumi.Input[str] crypto_endpoint: The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
        :param pulumi.Input[bool] include_plaintext_key: If true, the generated key is also returned unencrypted.
        :param pulumi.Input[str] key_id: The OCID of the master encryption key to encrypt the generated data encryption key with.
        :param pulumi.Input[pulumi.InputType['GeneratedKeyKeyShapeArgs']] key_shape: The cryptographic properties of a key.
        :param pulumi.Input[Mapping[str, Any]] logging_context: Information that provides context for audit logging. You can provide this additional data by formatting it as key-value pairs to include in audit logs when audit logging is enabled.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: GeneratedKeyArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Generated Key resource in Oracle Cloud Infrastructure Kms service.

        Generates a key that you can use to encrypt or decrypt data.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_generated_key = oci.kms.GeneratedKey("testGeneratedKey",
            crypto_endpoint=var["generated_key_crypto_endpoint"],
            include_plaintext_key=var["generated_key_include_plaintext_key"],
            key_id=oci_kms_key["test_key"]["id"],
            key_shape=oci.kms.GeneratedKeyKeyShapeArgs(
                algorithm=var["generated_key_key_shape_algorithm"],
                length=var["generated_key_key_shape_length"],
                curve_id=oci_kms_curve["test_curve"]["id"],
            ),
            associated_data=var["generated_key_associated_data"],
            logging_context=var["generated_key_logging_context"])
        ```

        ## Import

        Import is not supported for this resource.

        :param str resource_name: The name of the resource.
        :param GeneratedKeyArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(GeneratedKeyArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 associated_data: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 crypto_endpoint: Optional[pulumi.Input[str]] = None,
                 include_plaintext_key: Optional[pulumi.Input[bool]] = None,
                 key_id: Optional[pulumi.Input[str]] = None,
                 key_shape: Optional[pulumi.Input[pulumi.InputType['GeneratedKeyKeyShapeArgs']]] = None,
                 logging_context: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = GeneratedKeyArgs.__new__(GeneratedKeyArgs)

            __props__.__dict__["associated_data"] = associated_data
            if crypto_endpoint is None and not opts.urn:
                raise TypeError("Missing required property 'crypto_endpoint'")
            __props__.__dict__["crypto_endpoint"] = crypto_endpoint
            if include_plaintext_key is None and not opts.urn:
                raise TypeError("Missing required property 'include_plaintext_key'")
            __props__.__dict__["include_plaintext_key"] = include_plaintext_key
            if key_id is None and not opts.urn:
                raise TypeError("Missing required property 'key_id'")
            __props__.__dict__["key_id"] = key_id
            if key_shape is None and not opts.urn:
                raise TypeError("Missing required property 'key_shape'")
            __props__.__dict__["key_shape"] = key_shape
            __props__.__dict__["logging_context"] = logging_context
            __props__.__dict__["ciphertext"] = None
            __props__.__dict__["plaintext"] = None
            __props__.__dict__["plaintext_checksum"] = None
        super(GeneratedKey, __self__).__init__(
            'oci:Kms/generatedKey:GeneratedKey',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            associated_data: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            ciphertext: Optional[pulumi.Input[str]] = None,
            crypto_endpoint: Optional[pulumi.Input[str]] = None,
            include_plaintext_key: Optional[pulumi.Input[bool]] = None,
            key_id: Optional[pulumi.Input[str]] = None,
            key_shape: Optional[pulumi.Input[pulumi.InputType['GeneratedKeyKeyShapeArgs']]] = None,
            logging_context: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            plaintext: Optional[pulumi.Input[str]] = None,
            plaintext_checksum: Optional[pulumi.Input[str]] = None) -> 'GeneratedKey':
        """
        Get an existing GeneratedKey resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Mapping[str, Any]] associated_data: Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
        :param pulumi.Input[str] ciphertext: The encrypted data encryption key generated from a master encryption key.
        :param pulumi.Input[str] crypto_endpoint: The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
        :param pulumi.Input[bool] include_plaintext_key: If true, the generated key is also returned unencrypted.
        :param pulumi.Input[str] key_id: The OCID of the master encryption key to encrypt the generated data encryption key with.
        :param pulumi.Input[pulumi.InputType['GeneratedKeyKeyShapeArgs']] key_shape: The cryptographic properties of a key.
        :param pulumi.Input[Mapping[str, Any]] logging_context: Information that provides context for audit logging. You can provide this additional data by formatting it as key-value pairs to include in audit logs when audit logging is enabled.
        :param pulumi.Input[str] plaintext: The plaintext data encryption key, a base64-encoded sequence of random bytes, which is included if the [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) request includes the `includePlaintextKey` parameter and sets its value to "true".
        :param pulumi.Input[str] plaintext_checksum: The checksum of the plaintext data encryption key, which is included if the [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) request includes the `includePlaintextKey` parameter and sets its value to "true".
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _GeneratedKeyState.__new__(_GeneratedKeyState)

        __props__.__dict__["associated_data"] = associated_data
        __props__.__dict__["ciphertext"] = ciphertext
        __props__.__dict__["crypto_endpoint"] = crypto_endpoint
        __props__.__dict__["include_plaintext_key"] = include_plaintext_key
        __props__.__dict__["key_id"] = key_id
        __props__.__dict__["key_shape"] = key_shape
        __props__.__dict__["logging_context"] = logging_context
        __props__.__dict__["plaintext"] = plaintext
        __props__.__dict__["plaintext_checksum"] = plaintext_checksum
        return GeneratedKey(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="associatedData")
    def associated_data(self) -> pulumi.Output[Optional[Mapping[str, Any]]]:
        """
        Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
        """
        return pulumi.get(self, "associated_data")

    @property
    @pulumi.getter
    def ciphertext(self) -> pulumi.Output[str]:
        """
        The encrypted data encryption key generated from a master encryption key.
        """
        return pulumi.get(self, "ciphertext")

    @property
    @pulumi.getter(name="cryptoEndpoint")
    def crypto_endpoint(self) -> pulumi.Output[str]:
        """
        The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
        """
        return pulumi.get(self, "crypto_endpoint")

    @property
    @pulumi.getter(name="includePlaintextKey")
    def include_plaintext_key(self) -> pulumi.Output[bool]:
        """
        If true, the generated key is also returned unencrypted.
        """
        return pulumi.get(self, "include_plaintext_key")

    @property
    @pulumi.getter(name="keyId")
    def key_id(self) -> pulumi.Output[str]:
        """
        The OCID of the master encryption key to encrypt the generated data encryption key with.
        """
        return pulumi.get(self, "key_id")

    @property
    @pulumi.getter(name="keyShape")
    def key_shape(self) -> pulumi.Output['outputs.GeneratedKeyKeyShape']:
        """
        The cryptographic properties of a key.
        """
        return pulumi.get(self, "key_shape")

    @property
    @pulumi.getter(name="loggingContext")
    def logging_context(self) -> pulumi.Output[Optional[Mapping[str, Any]]]:
        """
        Information that provides context for audit logging. You can provide this additional data by formatting it as key-value pairs to include in audit logs when audit logging is enabled.
        """
        return pulumi.get(self, "logging_context")

    @property
    @pulumi.getter
    def plaintext(self) -> pulumi.Output[str]:
        """
        The plaintext data encryption key, a base64-encoded sequence of random bytes, which is included if the [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) request includes the `includePlaintextKey` parameter and sets its value to "true".
        """
        return pulumi.get(self, "plaintext")

    @property
    @pulumi.getter(name="plaintextChecksum")
    def plaintext_checksum(self) -> pulumi.Output[str]:
        """
        The checksum of the plaintext data encryption key, which is included if the [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) request includes the `includePlaintextKey` parameter and sets its value to "true".
        """
        return pulumi.get(self, "plaintext_checksum")
