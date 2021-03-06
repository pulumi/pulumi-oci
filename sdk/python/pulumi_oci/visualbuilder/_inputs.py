# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'VbInstanceAlternateCustomEndpointArgs',
    'VbInstanceCustomEndpointArgs',
    'GetVbInstancesFilterArgs',
]

@pulumi.input_type
class VbInstanceAlternateCustomEndpointArgs:
    def __init__(__self__, *,
                 hostname: pulumi.Input[str],
                 certificate_secret_id: Optional[pulumi.Input[str]] = None,
                 certificate_secret_version: Optional[pulumi.Input[int]] = None):
        """
        :param pulumi.Input[str] hostname: (Updatable) A custom hostname to be used for the vb instance URL, in FQDN format.
        :param pulumi.Input[str] certificate_secret_id: (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
        :param pulumi.Input[int] certificate_secret_version: The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        pulumi.set(__self__, "hostname", hostname)
        if certificate_secret_id is not None:
            pulumi.set(__self__, "certificate_secret_id", certificate_secret_id)
        if certificate_secret_version is not None:
            pulumi.set(__self__, "certificate_secret_version", certificate_secret_version)

    @property
    @pulumi.getter
    def hostname(self) -> pulumi.Input[str]:
        """
        (Updatable) A custom hostname to be used for the vb instance URL, in FQDN format.
        """
        return pulumi.get(self, "hostname")

    @hostname.setter
    def hostname(self, value: pulumi.Input[str]):
        pulumi.set(self, "hostname", value)

    @property
    @pulumi.getter(name="certificateSecretId")
    def certificate_secret_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
        """
        return pulumi.get(self, "certificate_secret_id")

    @certificate_secret_id.setter
    def certificate_secret_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "certificate_secret_id", value)

    @property
    @pulumi.getter(name="certificateSecretVersion")
    def certificate_secret_version(self) -> Optional[pulumi.Input[int]]:
        """
        The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        return pulumi.get(self, "certificate_secret_version")

    @certificate_secret_version.setter
    def certificate_secret_version(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "certificate_secret_version", value)


@pulumi.input_type
class VbInstanceCustomEndpointArgs:
    def __init__(__self__, *,
                 hostname: pulumi.Input[str],
                 certificate_secret_id: Optional[pulumi.Input[str]] = None,
                 certificate_secret_version: Optional[pulumi.Input[int]] = None):
        """
        :param pulumi.Input[str] hostname: (Updatable) A custom hostname to be used for the vb instance URL, in FQDN format.
        :param pulumi.Input[str] certificate_secret_id: (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
        :param pulumi.Input[int] certificate_secret_version: The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        pulumi.set(__self__, "hostname", hostname)
        if certificate_secret_id is not None:
            pulumi.set(__self__, "certificate_secret_id", certificate_secret_id)
        if certificate_secret_version is not None:
            pulumi.set(__self__, "certificate_secret_version", certificate_secret_version)

    @property
    @pulumi.getter
    def hostname(self) -> pulumi.Input[str]:
        """
        (Updatable) A custom hostname to be used for the vb instance URL, in FQDN format.
        """
        return pulumi.get(self, "hostname")

    @hostname.setter
    def hostname(self, value: pulumi.Input[str]):
        pulumi.set(self, "hostname", value)

    @property
    @pulumi.getter(name="certificateSecretId")
    def certificate_secret_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
        """
        return pulumi.get(self, "certificate_secret_id")

    @certificate_secret_id.setter
    def certificate_secret_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "certificate_secret_id", value)

    @property
    @pulumi.getter(name="certificateSecretVersion")
    def certificate_secret_version(self) -> Optional[pulumi.Input[int]]:
        """
        The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        return pulumi.get(self, "certificate_secret_version")

    @certificate_secret_version.setter
    def certificate_secret_version(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "certificate_secret_version", value)


@pulumi.input_type
class GetVbInstancesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


