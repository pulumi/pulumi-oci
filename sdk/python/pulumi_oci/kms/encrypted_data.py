# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['EncryptedDataArgs', 'EncryptedData']

@pulumi.input_type
class EncryptedDataArgs:
    def __init__(__self__, *,
                 crypto_endpoint: pulumi.Input[str],
                 key_id: pulumi.Input[str],
                 plaintext: pulumi.Input[str],
                 associated_data: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 encryption_algorithm: Optional[pulumi.Input[str]] = None,
                 key_version_id: Optional[pulumi.Input[str]] = None,
                 logging_context: Optional[pulumi.Input[Mapping[str, Any]]] = None):
        """
        The set of arguments for constructing a EncryptedData resource.
        :param pulumi.Input[str] crypto_endpoint: The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
        :param pulumi.Input[str] key_id: The OCID of the key to encrypt with.
        :param pulumi.Input[str] plaintext: The plaintext data to encrypt.
        :param pulumi.Input[Mapping[str, Any]] associated_data: Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
        :param pulumi.Input[str] encryption_algorithm: The encryption algorithm to use to encrypt and decrypt data with a customer-managed key. `AES_256_GCM` indicates that the key is a symmetric key that uses the Advanced Encryption Standard (AES) algorithm and  that the mode of encryption is the Galois/Counter Mode (GCM). `RSA_OAEP_SHA_1` indicates that the  key is an asymmetric key that uses the RSA encryption algorithm and uses Optimal Asymmetric Encryption Padding (OAEP).  `RSA_OAEP_SHA_256` indicates that the key is an asymmetric key that uses the RSA encryption algorithm with a SHA-256 hash  and uses OAEP.
        :param pulumi.Input[str] key_version_id: The OCID of the key version used to encrypt the ciphertext.
        :param pulumi.Input[Mapping[str, Any]] logging_context: Information that provides context for audit logging. You can provide this additional data as key-value pairs to include in the audit logs when audit logging is enabled.
        """
        pulumi.set(__self__, "crypto_endpoint", crypto_endpoint)
        pulumi.set(__self__, "key_id", key_id)
        pulumi.set(__self__, "plaintext", plaintext)
        if associated_data is not None:
            pulumi.set(__self__, "associated_data", associated_data)
        if encryption_algorithm is not None:
            pulumi.set(__self__, "encryption_algorithm", encryption_algorithm)
        if key_version_id is not None:
            pulumi.set(__self__, "key_version_id", key_version_id)
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
    @pulumi.getter(name="keyId")
    def key_id(self) -> pulumi.Input[str]:
        """
        The OCID of the key to encrypt with.
        """
        return pulumi.get(self, "key_id")

    @key_id.setter
    def key_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "key_id", value)

    @property
    @pulumi.getter
    def plaintext(self) -> pulumi.Input[str]:
        """
        The plaintext data to encrypt.
        """
        return pulumi.get(self, "plaintext")

    @plaintext.setter
    def plaintext(self, value: pulumi.Input[str]):
        pulumi.set(self, "plaintext", value)

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
    @pulumi.getter(name="encryptionAlgorithm")
    def encryption_algorithm(self) -> Optional[pulumi.Input[str]]:
        """
        The encryption algorithm to use to encrypt and decrypt data with a customer-managed key. `AES_256_GCM` indicates that the key is a symmetric key that uses the Advanced Encryption Standard (AES) algorithm and  that the mode of encryption is the Galois/Counter Mode (GCM). `RSA_OAEP_SHA_1` indicates that the  key is an asymmetric key that uses the RSA encryption algorithm and uses Optimal Asymmetric Encryption Padding (OAEP).  `RSA_OAEP_SHA_256` indicates that the key is an asymmetric key that uses the RSA encryption algorithm with a SHA-256 hash  and uses OAEP.
        """
        return pulumi.get(self, "encryption_algorithm")

    @encryption_algorithm.setter
    def encryption_algorithm(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "encryption_algorithm", value)

    @property
    @pulumi.getter(name="keyVersionId")
    def key_version_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the key version used to encrypt the ciphertext.
        """
        return pulumi.get(self, "key_version_id")

    @key_version_id.setter
    def key_version_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "key_version_id", value)

    @property
    @pulumi.getter(name="loggingContext")
    def logging_context(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        Information that provides context for audit logging. You can provide this additional data as key-value pairs to include in the audit logs when audit logging is enabled.
        """
        return pulumi.get(self, "logging_context")

    @logging_context.setter
    def logging_context(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "logging_context", value)


@pulumi.input_type
class _EncryptedDataState:
    def __init__(__self__, *,
                 associated_data: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 ciphertext: Optional[pulumi.Input[str]] = None,
                 crypto_endpoint: Optional[pulumi.Input[str]] = None,
                 encryption_algorithm: Optional[pulumi.Input[str]] = None,
                 key_id: Optional[pulumi.Input[str]] = None,
                 key_version_id: Optional[pulumi.Input[str]] = None,
                 logging_context: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 plaintext: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering EncryptedData resources.
        :param pulumi.Input[Mapping[str, Any]] associated_data: Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
        :param pulumi.Input[str] ciphertext: The encrypted data.
        :param pulumi.Input[str] crypto_endpoint: The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
        :param pulumi.Input[str] encryption_algorithm: The encryption algorithm to use to encrypt and decrypt data with a customer-managed key. `AES_256_GCM` indicates that the key is a symmetric key that uses the Advanced Encryption Standard (AES) algorithm and  that the mode of encryption is the Galois/Counter Mode (GCM). `RSA_OAEP_SHA_1` indicates that the  key is an asymmetric key that uses the RSA encryption algorithm and uses Optimal Asymmetric Encryption Padding (OAEP).  `RSA_OAEP_SHA_256` indicates that the key is an asymmetric key that uses the RSA encryption algorithm with a SHA-256 hash  and uses OAEP.
        :param pulumi.Input[str] key_id: The OCID of the key to encrypt with.
        :param pulumi.Input[str] key_version_id: The OCID of the key version used to encrypt the ciphertext.
        :param pulumi.Input[Mapping[str, Any]] logging_context: Information that provides context for audit logging. You can provide this additional data as key-value pairs to include in the audit logs when audit logging is enabled.
        :param pulumi.Input[str] plaintext: The plaintext data to encrypt.
        """
        if associated_data is not None:
            pulumi.set(__self__, "associated_data", associated_data)
        if ciphertext is not None:
            pulumi.set(__self__, "ciphertext", ciphertext)
        if crypto_endpoint is not None:
            pulumi.set(__self__, "crypto_endpoint", crypto_endpoint)
        if encryption_algorithm is not None:
            pulumi.set(__self__, "encryption_algorithm", encryption_algorithm)
        if key_id is not None:
            pulumi.set(__self__, "key_id", key_id)
        if key_version_id is not None:
            pulumi.set(__self__, "key_version_id", key_version_id)
        if logging_context is not None:
            pulumi.set(__self__, "logging_context", logging_context)
        if plaintext is not None:
            pulumi.set(__self__, "plaintext", plaintext)

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
        The encrypted data.
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
    @pulumi.getter(name="encryptionAlgorithm")
    def encryption_algorithm(self) -> Optional[pulumi.Input[str]]:
        """
        The encryption algorithm to use to encrypt and decrypt data with a customer-managed key. `AES_256_GCM` indicates that the key is a symmetric key that uses the Advanced Encryption Standard (AES) algorithm and  that the mode of encryption is the Galois/Counter Mode (GCM). `RSA_OAEP_SHA_1` indicates that the  key is an asymmetric key that uses the RSA encryption algorithm and uses Optimal Asymmetric Encryption Padding (OAEP).  `RSA_OAEP_SHA_256` indicates that the key is an asymmetric key that uses the RSA encryption algorithm with a SHA-256 hash  and uses OAEP.
        """
        return pulumi.get(self, "encryption_algorithm")

    @encryption_algorithm.setter
    def encryption_algorithm(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "encryption_algorithm", value)

    @property
    @pulumi.getter(name="keyId")
    def key_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the key to encrypt with.
        """
        return pulumi.get(self, "key_id")

    @key_id.setter
    def key_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "key_id", value)

    @property
    @pulumi.getter(name="keyVersionId")
    def key_version_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the key version used to encrypt the ciphertext.
        """
        return pulumi.get(self, "key_version_id")

    @key_version_id.setter
    def key_version_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "key_version_id", value)

    @property
    @pulumi.getter(name="loggingContext")
    def logging_context(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        Information that provides context for audit logging. You can provide this additional data as key-value pairs to include in the audit logs when audit logging is enabled.
        """
        return pulumi.get(self, "logging_context")

    @logging_context.setter
    def logging_context(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "logging_context", value)

    @property
    @pulumi.getter
    def plaintext(self) -> Optional[pulumi.Input[str]]:
        """
        The plaintext data to encrypt.
        """
        return pulumi.get(self, "plaintext")

    @plaintext.setter
    def plaintext(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "plaintext", value)


class EncryptedData(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 associated_data: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 crypto_endpoint: Optional[pulumi.Input[str]] = None,
                 encryption_algorithm: Optional[pulumi.Input[str]] = None,
                 key_id: Optional[pulumi.Input[str]] = None,
                 key_version_id: Optional[pulumi.Input[str]] = None,
                 logging_context: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 plaintext: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Encrypted Data resource in Oracle Cloud Infrastructure Kms service.

        Encrypts data using the given [EncryptDataDetails](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/datatypes/EncryptDataDetails) resource.
        Plaintext included in the example request is a base64-encoded value of a UTF-8 string.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_encrypted_data = oci.kms.EncryptedData("testEncryptedData",
            crypto_endpoint=var["encrypted_data_crypto_endpoint"],
            key_id=oci_kms_key["test_key"]["id"],
            plaintext=var["encrypted_data_plaintext"],
            associated_data=var["encrypted_data_associated_data"],
            encryption_algorithm=var["encrypted_data_encryption_algorithm"],
            key_version_id=oci_kms_key_version["test_key_version"]["id"],
            logging_context=var["encrypted_data_logging_context"])
        ```

        ## Import

        Import is not supported for this resource.

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Mapping[str, Any]] associated_data: Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
        :param pulumi.Input[str] crypto_endpoint: The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
        :param pulumi.Input[str] encryption_algorithm: The encryption algorithm to use to encrypt and decrypt data with a customer-managed key. `AES_256_GCM` indicates that the key is a symmetric key that uses the Advanced Encryption Standard (AES) algorithm and  that the mode of encryption is the Galois/Counter Mode (GCM). `RSA_OAEP_SHA_1` indicates that the  key is an asymmetric key that uses the RSA encryption algorithm and uses Optimal Asymmetric Encryption Padding (OAEP).  `RSA_OAEP_SHA_256` indicates that the key is an asymmetric key that uses the RSA encryption algorithm with a SHA-256 hash  and uses OAEP.
        :param pulumi.Input[str] key_id: The OCID of the key to encrypt with.
        :param pulumi.Input[str] key_version_id: The OCID of the key version used to encrypt the ciphertext.
        :param pulumi.Input[Mapping[str, Any]] logging_context: Information that provides context for audit logging. You can provide this additional data as key-value pairs to include in the audit logs when audit logging is enabled.
        :param pulumi.Input[str] plaintext: The plaintext data to encrypt.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: EncryptedDataArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Encrypted Data resource in Oracle Cloud Infrastructure Kms service.

        Encrypts data using the given [EncryptDataDetails](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/datatypes/EncryptDataDetails) resource.
        Plaintext included in the example request is a base64-encoded value of a UTF-8 string.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_encrypted_data = oci.kms.EncryptedData("testEncryptedData",
            crypto_endpoint=var["encrypted_data_crypto_endpoint"],
            key_id=oci_kms_key["test_key"]["id"],
            plaintext=var["encrypted_data_plaintext"],
            associated_data=var["encrypted_data_associated_data"],
            encryption_algorithm=var["encrypted_data_encryption_algorithm"],
            key_version_id=oci_kms_key_version["test_key_version"]["id"],
            logging_context=var["encrypted_data_logging_context"])
        ```

        ## Import

        Import is not supported for this resource.

        :param str resource_name: The name of the resource.
        :param EncryptedDataArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(EncryptedDataArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 associated_data: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 crypto_endpoint: Optional[pulumi.Input[str]] = None,
                 encryption_algorithm: Optional[pulumi.Input[str]] = None,
                 key_id: Optional[pulumi.Input[str]] = None,
                 key_version_id: Optional[pulumi.Input[str]] = None,
                 logging_context: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 plaintext: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = EncryptedDataArgs.__new__(EncryptedDataArgs)

            __props__.__dict__["associated_data"] = associated_data
            if crypto_endpoint is None and not opts.urn:
                raise TypeError("Missing required property 'crypto_endpoint'")
            __props__.__dict__["crypto_endpoint"] = crypto_endpoint
            __props__.__dict__["encryption_algorithm"] = encryption_algorithm
            if key_id is None and not opts.urn:
                raise TypeError("Missing required property 'key_id'")
            __props__.__dict__["key_id"] = key_id
            __props__.__dict__["key_version_id"] = key_version_id
            __props__.__dict__["logging_context"] = logging_context
            if plaintext is None and not opts.urn:
                raise TypeError("Missing required property 'plaintext'")
            __props__.__dict__["plaintext"] = plaintext
            __props__.__dict__["ciphertext"] = None
        super(EncryptedData, __self__).__init__(
            'oci:Kms/encryptedData:EncryptedData',
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
            encryption_algorithm: Optional[pulumi.Input[str]] = None,
            key_id: Optional[pulumi.Input[str]] = None,
            key_version_id: Optional[pulumi.Input[str]] = None,
            logging_context: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            plaintext: Optional[pulumi.Input[str]] = None) -> 'EncryptedData':
        """
        Get an existing EncryptedData resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Mapping[str, Any]] associated_data: Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
        :param pulumi.Input[str] ciphertext: The encrypted data.
        :param pulumi.Input[str] crypto_endpoint: The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
        :param pulumi.Input[str] encryption_algorithm: The encryption algorithm to use to encrypt and decrypt data with a customer-managed key. `AES_256_GCM` indicates that the key is a symmetric key that uses the Advanced Encryption Standard (AES) algorithm and  that the mode of encryption is the Galois/Counter Mode (GCM). `RSA_OAEP_SHA_1` indicates that the  key is an asymmetric key that uses the RSA encryption algorithm and uses Optimal Asymmetric Encryption Padding (OAEP).  `RSA_OAEP_SHA_256` indicates that the key is an asymmetric key that uses the RSA encryption algorithm with a SHA-256 hash  and uses OAEP.
        :param pulumi.Input[str] key_id: The OCID of the key to encrypt with.
        :param pulumi.Input[str] key_version_id: The OCID of the key version used to encrypt the ciphertext.
        :param pulumi.Input[Mapping[str, Any]] logging_context: Information that provides context for audit logging. You can provide this additional data as key-value pairs to include in the audit logs when audit logging is enabled.
        :param pulumi.Input[str] plaintext: The plaintext data to encrypt.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _EncryptedDataState.__new__(_EncryptedDataState)

        __props__.__dict__["associated_data"] = associated_data
        __props__.__dict__["ciphertext"] = ciphertext
        __props__.__dict__["crypto_endpoint"] = crypto_endpoint
        __props__.__dict__["encryption_algorithm"] = encryption_algorithm
        __props__.__dict__["key_id"] = key_id
        __props__.__dict__["key_version_id"] = key_version_id
        __props__.__dict__["logging_context"] = logging_context
        __props__.__dict__["plaintext"] = plaintext
        return EncryptedData(resource_name, opts=opts, __props__=__props__)

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
        The encrypted data.
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
    @pulumi.getter(name="encryptionAlgorithm")
    def encryption_algorithm(self) -> pulumi.Output[str]:
        """
        The encryption algorithm to use to encrypt and decrypt data with a customer-managed key. `AES_256_GCM` indicates that the key is a symmetric key that uses the Advanced Encryption Standard (AES) algorithm and  that the mode of encryption is the Galois/Counter Mode (GCM). `RSA_OAEP_SHA_1` indicates that the  key is an asymmetric key that uses the RSA encryption algorithm and uses Optimal Asymmetric Encryption Padding (OAEP).  `RSA_OAEP_SHA_256` indicates that the key is an asymmetric key that uses the RSA encryption algorithm with a SHA-256 hash  and uses OAEP.
        """
        return pulumi.get(self, "encryption_algorithm")

    @property
    @pulumi.getter(name="keyId")
    def key_id(self) -> pulumi.Output[str]:
        """
        The OCID of the key to encrypt with.
        """
        return pulumi.get(self, "key_id")

    @property
    @pulumi.getter(name="keyVersionId")
    def key_version_id(self) -> pulumi.Output[str]:
        """
        The OCID of the key version used to encrypt the ciphertext.
        """
        return pulumi.get(self, "key_version_id")

    @property
    @pulumi.getter(name="loggingContext")
    def logging_context(self) -> pulumi.Output[Optional[Mapping[str, Any]]]:
        """
        Information that provides context for audit logging. You can provide this additional data as key-value pairs to include in the audit logs when audit logging is enabled.
        """
        return pulumi.get(self, "logging_context")

    @property
    @pulumi.getter
    def plaintext(self) -> pulumi.Output[str]:
        """
        The plaintext data to encrypt.
        """
        return pulumi.get(self, "plaintext")
