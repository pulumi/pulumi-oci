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

__all__ = ['CertificateArgs', 'Certificate']

@pulumi.input_type
class CertificateArgs:
    def __init__(__self__, *,
                 certificate_name: pulumi.Input[_builtins.str],
                 load_balancer_id: pulumi.Input[_builtins.str],
                 ca_certificate: Optional[pulumi.Input[_builtins.str]] = None,
                 passphrase: Optional[pulumi.Input[_builtins.str]] = None,
                 private_key: Optional[pulumi.Input[_builtins.str]] = None,
                 public_certificate: Optional[pulumi.Input[_builtins.str]] = None):
        """
        The set of arguments for constructing a Certificate resource.
        :param pulumi.Input[_builtins.str] certificate_name: A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
        :param pulumi.Input[_builtins.str] load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add the certificate bundle.
        :param pulumi.Input[_builtins.str] ca_certificate: The Certificate Authority certificate, or any interim certificate, that you received from your SSL certificate provider.
               
               Example:
               
               -----BEGIN CERTIFICATE-----
               MIIEczCCA1ugAwIBAgIBADANBgkqhkiG9w0BAQQFAD..AkGA1UEBhMCR0Ix
               EzARBgNVBAgTClNvbWUtU3RhdGUxFDASBgNVBAoTC0..0EgTHRkMTcwNQYD
               VQQLEy5DbGFzcyAxIFB1YmxpYyBQcmltYXJ5IENlcn..XRpb24gQXV0aG9y
               aXR5MRQwEgYDVQQDEwtCZXN0IENBIEx0ZDAeFw0wMD..TUwMTZaFw0wMTAy
               ...
               -----END CERTIFICATE-----
        :param pulumi.Input[_builtins.str] passphrase: A passphrase for encrypted private keys. This is needed only if you created your certificate with a passphrase.
        :param pulumi.Input[_builtins.str] private_key: The SSL private key for your certificate, in PEM format.
               
               Example:
               
               -----BEGIN RSA PRIVATE KEY-----
               jO1O1v2ftXMsawM90tnXwc6xhOAT1gDBC9S8DKeca..JZNUgYYwNS0dP2UK
               tmyN+XqVcAKw4HqVmChXy5b5msu8eIq3uc2NqNVtR..2ksSLukP8pxXcHyb
               +sEwvM4uf8qbnHAqwnOnP9+KV9vds6BaH1eRA4CHz..n+NVZlzBsTxTlS16
               /Umr7wJzVrMqK5sDiSu4WuaaBdqMGfL5hLsTjcBFD..Da2iyQmSKuVD4lIZ
               ...
               -----END RSA PRIVATE KEY-----
        :param pulumi.Input[_builtins.str] public_certificate: The public certificate, in PEM format, that you received from your SSL certificate provider.
               
               Example:
               
               -----BEGIN CERTIFICATE-----
               MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbM..QswCQYDVQQGEwJKU
               A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxE..TAPBgNVBAoTCEZyY
               MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWB..gNVBAMTD0ZyYW5rN
               YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmc..mFuazRkZC5jb20wH
               ...
               -----END CERTIFICATE-----
               
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "certificate_name", certificate_name)
        pulumi.set(__self__, "load_balancer_id", load_balancer_id)
        if ca_certificate is not None:
            pulumi.set(__self__, "ca_certificate", ca_certificate)
        if passphrase is not None:
            pulumi.set(__self__, "passphrase", passphrase)
        if private_key is not None:
            pulumi.set(__self__, "private_key", private_key)
        if public_certificate is not None:
            pulumi.set(__self__, "public_certificate", public_certificate)

    @_builtins.property
    @pulumi.getter(name="certificateName")
    def certificate_name(self) -> pulumi.Input[_builtins.str]:
        """
        A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
        """
        return pulumi.get(self, "certificate_name")

    @certificate_name.setter
    def certificate_name(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "certificate_name", value)

    @_builtins.property
    @pulumi.getter(name="loadBalancerId")
    def load_balancer_id(self) -> pulumi.Input[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add the certificate bundle.
        """
        return pulumi.get(self, "load_balancer_id")

    @load_balancer_id.setter
    def load_balancer_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "load_balancer_id", value)

    @_builtins.property
    @pulumi.getter(name="caCertificate")
    def ca_certificate(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The Certificate Authority certificate, or any interim certificate, that you received from your SSL certificate provider.

        Example:

        -----BEGIN CERTIFICATE-----
        MIIEczCCA1ugAwIBAgIBADANBgkqhkiG9w0BAQQFAD..AkGA1UEBhMCR0Ix
        EzARBgNVBAgTClNvbWUtU3RhdGUxFDASBgNVBAoTC0..0EgTHRkMTcwNQYD
        VQQLEy5DbGFzcyAxIFB1YmxpYyBQcmltYXJ5IENlcn..XRpb24gQXV0aG9y
        aXR5MRQwEgYDVQQDEwtCZXN0IENBIEx0ZDAeFw0wMD..TUwMTZaFw0wMTAy
        ...
        -----END CERTIFICATE-----
        """
        return pulumi.get(self, "ca_certificate")

    @ca_certificate.setter
    def ca_certificate(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "ca_certificate", value)

    @_builtins.property
    @pulumi.getter
    def passphrase(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        A passphrase for encrypted private keys. This is needed only if you created your certificate with a passphrase.
        """
        return pulumi.get(self, "passphrase")

    @passphrase.setter
    def passphrase(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "passphrase", value)

    @_builtins.property
    @pulumi.getter(name="privateKey")
    def private_key(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The SSL private key for your certificate, in PEM format.

        Example:

        -----BEGIN RSA PRIVATE KEY-----
        jO1O1v2ftXMsawM90tnXwc6xhOAT1gDBC9S8DKeca..JZNUgYYwNS0dP2UK
        tmyN+XqVcAKw4HqVmChXy5b5msu8eIq3uc2NqNVtR..2ksSLukP8pxXcHyb
        +sEwvM4uf8qbnHAqwnOnP9+KV9vds6BaH1eRA4CHz..n+NVZlzBsTxTlS16
        /Umr7wJzVrMqK5sDiSu4WuaaBdqMGfL5hLsTjcBFD..Da2iyQmSKuVD4lIZ
        ...
        -----END RSA PRIVATE KEY-----
        """
        return pulumi.get(self, "private_key")

    @private_key.setter
    def private_key(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "private_key", value)

    @_builtins.property
    @pulumi.getter(name="publicCertificate")
    def public_certificate(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The public certificate, in PEM format, that you received from your SSL certificate provider.

        Example:

        -----BEGIN CERTIFICATE-----
        MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbM..QswCQYDVQQGEwJKU
        A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxE..TAPBgNVBAoTCEZyY
        MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWB..gNVBAMTD0ZyYW5rN
        YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmc..mFuazRkZC5jb20wH
        ...
        -----END CERTIFICATE-----



        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "public_certificate")

    @public_certificate.setter
    def public_certificate(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "public_certificate", value)


@pulumi.input_type
class _CertificateState:
    def __init__(__self__, *,
                 ca_certificate: Optional[pulumi.Input[_builtins.str]] = None,
                 certificate_name: Optional[pulumi.Input[_builtins.str]] = None,
                 load_balancer_id: Optional[pulumi.Input[_builtins.str]] = None,
                 passphrase: Optional[pulumi.Input[_builtins.str]] = None,
                 private_key: Optional[pulumi.Input[_builtins.str]] = None,
                 public_certificate: Optional[pulumi.Input[_builtins.str]] = None,
                 state: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering Certificate resources.
        :param pulumi.Input[_builtins.str] ca_certificate: The Certificate Authority certificate, or any interim certificate, that you received from your SSL certificate provider.
               
               Example:
               
               -----BEGIN CERTIFICATE-----
               MIIEczCCA1ugAwIBAgIBADANBgkqhkiG9w0BAQQFAD..AkGA1UEBhMCR0Ix
               EzARBgNVBAgTClNvbWUtU3RhdGUxFDASBgNVBAoTC0..0EgTHRkMTcwNQYD
               VQQLEy5DbGFzcyAxIFB1YmxpYyBQcmltYXJ5IENlcn..XRpb24gQXV0aG9y
               aXR5MRQwEgYDVQQDEwtCZXN0IENBIEx0ZDAeFw0wMD..TUwMTZaFw0wMTAy
               ...
               -----END CERTIFICATE-----
        :param pulumi.Input[_builtins.str] certificate_name: A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
        :param pulumi.Input[_builtins.str] load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add the certificate bundle.
        :param pulumi.Input[_builtins.str] passphrase: A passphrase for encrypted private keys. This is needed only if you created your certificate with a passphrase.
        :param pulumi.Input[_builtins.str] private_key: The SSL private key for your certificate, in PEM format.
               
               Example:
               
               -----BEGIN RSA PRIVATE KEY-----
               jO1O1v2ftXMsawM90tnXwc6xhOAT1gDBC9S8DKeca..JZNUgYYwNS0dP2UK
               tmyN+XqVcAKw4HqVmChXy5b5msu8eIq3uc2NqNVtR..2ksSLukP8pxXcHyb
               +sEwvM4uf8qbnHAqwnOnP9+KV9vds6BaH1eRA4CHz..n+NVZlzBsTxTlS16
               /Umr7wJzVrMqK5sDiSu4WuaaBdqMGfL5hLsTjcBFD..Da2iyQmSKuVD4lIZ
               ...
               -----END RSA PRIVATE KEY-----
        :param pulumi.Input[_builtins.str] public_certificate: The public certificate, in PEM format, that you received from your SSL certificate provider.
               
               Example:
               
               -----BEGIN CERTIFICATE-----
               MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbM..QswCQYDVQQGEwJKU
               A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxE..TAPBgNVBAoTCEZyY
               MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWB..gNVBAMTD0ZyYW5rN
               YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmc..mFuazRkZC5jb20wH
               ...
               -----END CERTIFICATE-----
               
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if ca_certificate is not None:
            pulumi.set(__self__, "ca_certificate", ca_certificate)
        if certificate_name is not None:
            pulumi.set(__self__, "certificate_name", certificate_name)
        if load_balancer_id is not None:
            pulumi.set(__self__, "load_balancer_id", load_balancer_id)
        if passphrase is not None:
            pulumi.set(__self__, "passphrase", passphrase)
        if private_key is not None:
            pulumi.set(__self__, "private_key", private_key)
        if public_certificate is not None:
            pulumi.set(__self__, "public_certificate", public_certificate)
        if state is not None:
            pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="caCertificate")
    def ca_certificate(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The Certificate Authority certificate, or any interim certificate, that you received from your SSL certificate provider.

        Example:

        -----BEGIN CERTIFICATE-----
        MIIEczCCA1ugAwIBAgIBADANBgkqhkiG9w0BAQQFAD..AkGA1UEBhMCR0Ix
        EzARBgNVBAgTClNvbWUtU3RhdGUxFDASBgNVBAoTC0..0EgTHRkMTcwNQYD
        VQQLEy5DbGFzcyAxIFB1YmxpYyBQcmltYXJ5IENlcn..XRpb24gQXV0aG9y
        aXR5MRQwEgYDVQQDEwtCZXN0IENBIEx0ZDAeFw0wMD..TUwMTZaFw0wMTAy
        ...
        -----END CERTIFICATE-----
        """
        return pulumi.get(self, "ca_certificate")

    @ca_certificate.setter
    def ca_certificate(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "ca_certificate", value)

    @_builtins.property
    @pulumi.getter(name="certificateName")
    def certificate_name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
        """
        return pulumi.get(self, "certificate_name")

    @certificate_name.setter
    def certificate_name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "certificate_name", value)

    @_builtins.property
    @pulumi.getter(name="loadBalancerId")
    def load_balancer_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add the certificate bundle.
        """
        return pulumi.get(self, "load_balancer_id")

    @load_balancer_id.setter
    def load_balancer_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "load_balancer_id", value)

    @_builtins.property
    @pulumi.getter
    def passphrase(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        A passphrase for encrypted private keys. This is needed only if you created your certificate with a passphrase.
        """
        return pulumi.get(self, "passphrase")

    @passphrase.setter
    def passphrase(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "passphrase", value)

    @_builtins.property
    @pulumi.getter(name="privateKey")
    def private_key(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The SSL private key for your certificate, in PEM format.

        Example:

        -----BEGIN RSA PRIVATE KEY-----
        jO1O1v2ftXMsawM90tnXwc6xhOAT1gDBC9S8DKeca..JZNUgYYwNS0dP2UK
        tmyN+XqVcAKw4HqVmChXy5b5msu8eIq3uc2NqNVtR..2ksSLukP8pxXcHyb
        +sEwvM4uf8qbnHAqwnOnP9+KV9vds6BaH1eRA4CHz..n+NVZlzBsTxTlS16
        /Umr7wJzVrMqK5sDiSu4WuaaBdqMGfL5hLsTjcBFD..Da2iyQmSKuVD4lIZ
        ...
        -----END RSA PRIVATE KEY-----
        """
        return pulumi.get(self, "private_key")

    @private_key.setter
    def private_key(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "private_key", value)

    @_builtins.property
    @pulumi.getter(name="publicCertificate")
    def public_certificate(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The public certificate, in PEM format, that you received from your SSL certificate provider.

        Example:

        -----BEGIN CERTIFICATE-----
        MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbM..QswCQYDVQQGEwJKU
        A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxE..TAPBgNVBAoTCEZyY
        MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWB..gNVBAMTD0ZyYW5rN
        YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmc..mFuazRkZC5jb20wH
        ...
        -----END CERTIFICATE-----



        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "public_certificate")

    @public_certificate.setter
    def public_certificate(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "public_certificate", value)

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[_builtins.str]]:
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "state", value)


@pulumi.type_token("oci:LoadBalancer/certificate:Certificate")
class Certificate(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 ca_certificate: Optional[pulumi.Input[_builtins.str]] = None,
                 certificate_name: Optional[pulumi.Input[_builtins.str]] = None,
                 load_balancer_id: Optional[pulumi.Input[_builtins.str]] = None,
                 passphrase: Optional[pulumi.Input[_builtins.str]] = None,
                 private_key: Optional[pulumi.Input[_builtins.str]] = None,
                 public_certificate: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        ## Example Usage

        ## Import

        Certificates can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:LoadBalancer/certificate:Certificate test_certificate "loadBalancers/{loadBalancerId}/certificates/{certificateName}"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] ca_certificate: The Certificate Authority certificate, or any interim certificate, that you received from your SSL certificate provider.
               
               Example:
               
               -----BEGIN CERTIFICATE-----
               MIIEczCCA1ugAwIBAgIBADANBgkqhkiG9w0BAQQFAD..AkGA1UEBhMCR0Ix
               EzARBgNVBAgTClNvbWUtU3RhdGUxFDASBgNVBAoTC0..0EgTHRkMTcwNQYD
               VQQLEy5DbGFzcyAxIFB1YmxpYyBQcmltYXJ5IENlcn..XRpb24gQXV0aG9y
               aXR5MRQwEgYDVQQDEwtCZXN0IENBIEx0ZDAeFw0wMD..TUwMTZaFw0wMTAy
               ...
               -----END CERTIFICATE-----
        :param pulumi.Input[_builtins.str] certificate_name: A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
        :param pulumi.Input[_builtins.str] load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add the certificate bundle.
        :param pulumi.Input[_builtins.str] passphrase: A passphrase for encrypted private keys. This is needed only if you created your certificate with a passphrase.
        :param pulumi.Input[_builtins.str] private_key: The SSL private key for your certificate, in PEM format.
               
               Example:
               
               -----BEGIN RSA PRIVATE KEY-----
               jO1O1v2ftXMsawM90tnXwc6xhOAT1gDBC9S8DKeca..JZNUgYYwNS0dP2UK
               tmyN+XqVcAKw4HqVmChXy5b5msu8eIq3uc2NqNVtR..2ksSLukP8pxXcHyb
               +sEwvM4uf8qbnHAqwnOnP9+KV9vds6BaH1eRA4CHz..n+NVZlzBsTxTlS16
               /Umr7wJzVrMqK5sDiSu4WuaaBdqMGfL5hLsTjcBFD..Da2iyQmSKuVD4lIZ
               ...
               -----END RSA PRIVATE KEY-----
        :param pulumi.Input[_builtins.str] public_certificate: The public certificate, in PEM format, that you received from your SSL certificate provider.
               
               Example:
               
               -----BEGIN CERTIFICATE-----
               MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbM..QswCQYDVQQGEwJKU
               A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxE..TAPBgNVBAoTCEZyY
               MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWB..gNVBAMTD0ZyYW5rN
               YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmc..mFuazRkZC5jb20wH
               ...
               -----END CERTIFICATE-----
               
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: CertificateArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        ## Example Usage

        ## Import

        Certificates can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:LoadBalancer/certificate:Certificate test_certificate "loadBalancers/{loadBalancerId}/certificates/{certificateName}"
        ```

        :param str resource_name: The name of the resource.
        :param CertificateArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(CertificateArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 ca_certificate: Optional[pulumi.Input[_builtins.str]] = None,
                 certificate_name: Optional[pulumi.Input[_builtins.str]] = None,
                 load_balancer_id: Optional[pulumi.Input[_builtins.str]] = None,
                 passphrase: Optional[pulumi.Input[_builtins.str]] = None,
                 private_key: Optional[pulumi.Input[_builtins.str]] = None,
                 public_certificate: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = CertificateArgs.__new__(CertificateArgs)

            __props__.__dict__["ca_certificate"] = ca_certificate
            if certificate_name is None and not opts.urn:
                raise TypeError("Missing required property 'certificate_name'")
            __props__.__dict__["certificate_name"] = certificate_name
            if load_balancer_id is None and not opts.urn:
                raise TypeError("Missing required property 'load_balancer_id'")
            __props__.__dict__["load_balancer_id"] = load_balancer_id
            __props__.__dict__["passphrase"] = None if passphrase is None else pulumi.Output.secret(passphrase)
            __props__.__dict__["private_key"] = None if private_key is None else pulumi.Output.secret(private_key)
            __props__.__dict__["public_certificate"] = public_certificate
            __props__.__dict__["state"] = None
        secret_opts = pulumi.ResourceOptions(additional_secret_outputs=["passphrase", "privateKey"])
        opts = pulumi.ResourceOptions.merge(opts, secret_opts)
        super(Certificate, __self__).__init__(
            'oci:LoadBalancer/certificate:Certificate',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            ca_certificate: Optional[pulumi.Input[_builtins.str]] = None,
            certificate_name: Optional[pulumi.Input[_builtins.str]] = None,
            load_balancer_id: Optional[pulumi.Input[_builtins.str]] = None,
            passphrase: Optional[pulumi.Input[_builtins.str]] = None,
            private_key: Optional[pulumi.Input[_builtins.str]] = None,
            public_certificate: Optional[pulumi.Input[_builtins.str]] = None,
            state: Optional[pulumi.Input[_builtins.str]] = None) -> 'Certificate':
        """
        Get an existing Certificate resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] ca_certificate: The Certificate Authority certificate, or any interim certificate, that you received from your SSL certificate provider.
               
               Example:
               
               -----BEGIN CERTIFICATE-----
               MIIEczCCA1ugAwIBAgIBADANBgkqhkiG9w0BAQQFAD..AkGA1UEBhMCR0Ix
               EzARBgNVBAgTClNvbWUtU3RhdGUxFDASBgNVBAoTC0..0EgTHRkMTcwNQYD
               VQQLEy5DbGFzcyAxIFB1YmxpYyBQcmltYXJ5IENlcn..XRpb24gQXV0aG9y
               aXR5MRQwEgYDVQQDEwtCZXN0IENBIEx0ZDAeFw0wMD..TUwMTZaFw0wMTAy
               ...
               -----END CERTIFICATE-----
        :param pulumi.Input[_builtins.str] certificate_name: A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
        :param pulumi.Input[_builtins.str] load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add the certificate bundle.
        :param pulumi.Input[_builtins.str] passphrase: A passphrase for encrypted private keys. This is needed only if you created your certificate with a passphrase.
        :param pulumi.Input[_builtins.str] private_key: The SSL private key for your certificate, in PEM format.
               
               Example:
               
               -----BEGIN RSA PRIVATE KEY-----
               jO1O1v2ftXMsawM90tnXwc6xhOAT1gDBC9S8DKeca..JZNUgYYwNS0dP2UK
               tmyN+XqVcAKw4HqVmChXy5b5msu8eIq3uc2NqNVtR..2ksSLukP8pxXcHyb
               +sEwvM4uf8qbnHAqwnOnP9+KV9vds6BaH1eRA4CHz..n+NVZlzBsTxTlS16
               /Umr7wJzVrMqK5sDiSu4WuaaBdqMGfL5hLsTjcBFD..Da2iyQmSKuVD4lIZ
               ...
               -----END RSA PRIVATE KEY-----
        :param pulumi.Input[_builtins.str] public_certificate: The public certificate, in PEM format, that you received from your SSL certificate provider.
               
               Example:
               
               -----BEGIN CERTIFICATE-----
               MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbM..QswCQYDVQQGEwJKU
               A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxE..TAPBgNVBAoTCEZyY
               MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWB..gNVBAMTD0ZyYW5rN
               YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmc..mFuazRkZC5jb20wH
               ...
               -----END CERTIFICATE-----
               
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _CertificateState.__new__(_CertificateState)

        __props__.__dict__["ca_certificate"] = ca_certificate
        __props__.__dict__["certificate_name"] = certificate_name
        __props__.__dict__["load_balancer_id"] = load_balancer_id
        __props__.__dict__["passphrase"] = passphrase
        __props__.__dict__["private_key"] = private_key
        __props__.__dict__["public_certificate"] = public_certificate
        __props__.__dict__["state"] = state
        return Certificate(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="caCertificate")
    def ca_certificate(self) -> pulumi.Output[_builtins.str]:
        """
        The Certificate Authority certificate, or any interim certificate, that you received from your SSL certificate provider.

        Example:

        -----BEGIN CERTIFICATE-----
        MIIEczCCA1ugAwIBAgIBADANBgkqhkiG9w0BAQQFAD..AkGA1UEBhMCR0Ix
        EzARBgNVBAgTClNvbWUtU3RhdGUxFDASBgNVBAoTC0..0EgTHRkMTcwNQYD
        VQQLEy5DbGFzcyAxIFB1YmxpYyBQcmltYXJ5IENlcn..XRpb24gQXV0aG9y
        aXR5MRQwEgYDVQQDEwtCZXN0IENBIEx0ZDAeFw0wMD..TUwMTZaFw0wMTAy
        ...
        -----END CERTIFICATE-----
        """
        return pulumi.get(self, "ca_certificate")

    @_builtins.property
    @pulumi.getter(name="certificateName")
    def certificate_name(self) -> pulumi.Output[_builtins.str]:
        """
        A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
        """
        return pulumi.get(self, "certificate_name")

    @_builtins.property
    @pulumi.getter(name="loadBalancerId")
    def load_balancer_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add the certificate bundle.
        """
        return pulumi.get(self, "load_balancer_id")

    @_builtins.property
    @pulumi.getter
    def passphrase(self) -> pulumi.Output[Optional[_builtins.str]]:
        """
        A passphrase for encrypted private keys. This is needed only if you created your certificate with a passphrase.
        """
        return pulumi.get(self, "passphrase")

    @_builtins.property
    @pulumi.getter(name="privateKey")
    def private_key(self) -> pulumi.Output[_builtins.str]:
        """
        The SSL private key for your certificate, in PEM format.

        Example:

        -----BEGIN RSA PRIVATE KEY-----
        jO1O1v2ftXMsawM90tnXwc6xhOAT1gDBC9S8DKeca..JZNUgYYwNS0dP2UK
        tmyN+XqVcAKw4HqVmChXy5b5msu8eIq3uc2NqNVtR..2ksSLukP8pxXcHyb
        +sEwvM4uf8qbnHAqwnOnP9+KV9vds6BaH1eRA4CHz..n+NVZlzBsTxTlS16
        /Umr7wJzVrMqK5sDiSu4WuaaBdqMGfL5hLsTjcBFD..Da2iyQmSKuVD4lIZ
        ...
        -----END RSA PRIVATE KEY-----
        """
        return pulumi.get(self, "private_key")

    @_builtins.property
    @pulumi.getter(name="publicCertificate")
    def public_certificate(self) -> pulumi.Output[_builtins.str]:
        """
        The public certificate, in PEM format, that you received from your SSL certificate provider.

        Example:

        -----BEGIN CERTIFICATE-----
        MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbM..QswCQYDVQQGEwJKU
        A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxE..TAPBgNVBAoTCEZyY
        MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWB..gNVBAMTD0ZyYW5rN
        YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmc..mFuazRkZC5jb20wH
        ...
        -----END CERTIFICATE-----



        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "public_certificate")

    @_builtins.property
    @pulumi.getter
    def state(self) -> pulumi.Output[_builtins.str]:
        return pulumi.get(self, "state")

