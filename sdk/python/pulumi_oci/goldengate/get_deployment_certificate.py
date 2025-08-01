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
    'GetDeploymentCertificateResult',
    'AwaitableGetDeploymentCertificateResult',
    'get_deployment_certificate',
    'get_deployment_certificate_output',
]

@pulumi.output_type
class GetDeploymentCertificateResult:
    """
    A collection of values returned by getDeploymentCertificate.
    """
    def __init__(__self__, authority_key_id=None, certificate_content=None, certificate_key=None, deployment_id=None, id=None, is_ca=None, is_lock_override=None, is_self_signed=None, issuer=None, key=None, md5hash=None, public_key=None, public_key_algorithm=None, public_key_size=None, serial=None, sha1hash=None, state=None, subject=None, subject_key_id=None, time_created=None, time_valid_from=None, time_valid_to=None, version=None):
        if authority_key_id and not isinstance(authority_key_id, str):
            raise TypeError("Expected argument 'authority_key_id' to be a str")
        pulumi.set(__self__, "authority_key_id", authority_key_id)
        if certificate_content and not isinstance(certificate_content, str):
            raise TypeError("Expected argument 'certificate_content' to be a str")
        pulumi.set(__self__, "certificate_content", certificate_content)
        if certificate_key and not isinstance(certificate_key, str):
            raise TypeError("Expected argument 'certificate_key' to be a str")
        pulumi.set(__self__, "certificate_key", certificate_key)
        if deployment_id and not isinstance(deployment_id, str):
            raise TypeError("Expected argument 'deployment_id' to be a str")
        pulumi.set(__self__, "deployment_id", deployment_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_ca and not isinstance(is_ca, bool):
            raise TypeError("Expected argument 'is_ca' to be a bool")
        pulumi.set(__self__, "is_ca", is_ca)
        if is_lock_override and not isinstance(is_lock_override, bool):
            raise TypeError("Expected argument 'is_lock_override' to be a bool")
        pulumi.set(__self__, "is_lock_override", is_lock_override)
        if is_self_signed and not isinstance(is_self_signed, bool):
            raise TypeError("Expected argument 'is_self_signed' to be a bool")
        pulumi.set(__self__, "is_self_signed", is_self_signed)
        if issuer and not isinstance(issuer, str):
            raise TypeError("Expected argument 'issuer' to be a str")
        pulumi.set(__self__, "issuer", issuer)
        if key and not isinstance(key, str):
            raise TypeError("Expected argument 'key' to be a str")
        pulumi.set(__self__, "key", key)
        if md5hash and not isinstance(md5hash, str):
            raise TypeError("Expected argument 'md5hash' to be a str")
        pulumi.set(__self__, "md5hash", md5hash)
        if public_key and not isinstance(public_key, str):
            raise TypeError("Expected argument 'public_key' to be a str")
        pulumi.set(__self__, "public_key", public_key)
        if public_key_algorithm and not isinstance(public_key_algorithm, str):
            raise TypeError("Expected argument 'public_key_algorithm' to be a str")
        pulumi.set(__self__, "public_key_algorithm", public_key_algorithm)
        if public_key_size and not isinstance(public_key_size, str):
            raise TypeError("Expected argument 'public_key_size' to be a str")
        pulumi.set(__self__, "public_key_size", public_key_size)
        if serial and not isinstance(serial, str):
            raise TypeError("Expected argument 'serial' to be a str")
        pulumi.set(__self__, "serial", serial)
        if sha1hash and not isinstance(sha1hash, str):
            raise TypeError("Expected argument 'sha1hash' to be a str")
        pulumi.set(__self__, "sha1hash", sha1hash)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if subject and not isinstance(subject, str):
            raise TypeError("Expected argument 'subject' to be a str")
        pulumi.set(__self__, "subject", subject)
        if subject_key_id and not isinstance(subject_key_id, str):
            raise TypeError("Expected argument 'subject_key_id' to be a str")
        pulumi.set(__self__, "subject_key_id", subject_key_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_valid_from and not isinstance(time_valid_from, str):
            raise TypeError("Expected argument 'time_valid_from' to be a str")
        pulumi.set(__self__, "time_valid_from", time_valid_from)
        if time_valid_to and not isinstance(time_valid_to, str):
            raise TypeError("Expected argument 'time_valid_to' to be a str")
        pulumi.set(__self__, "time_valid_to", time_valid_to)
        if version and not isinstance(version, str):
            raise TypeError("Expected argument 'version' to be a str")
        pulumi.set(__self__, "version", version)

    @_builtins.property
    @pulumi.getter(name="authorityKeyId")
    def authority_key_id(self) -> _builtins.str:
        """
        The Certificate authority key id.
        """
        return pulumi.get(self, "authority_key_id")

    @_builtins.property
    @pulumi.getter(name="certificateContent")
    def certificate_content(self) -> _builtins.str:
        """
        The base64 encoded content of the PEM file containing the SSL certificate.
        """
        return pulumi.get(self, "certificate_content")

    @_builtins.property
    @pulumi.getter(name="certificateKey")
    def certificate_key(self) -> _builtins.str:
        return pulumi.get(self, "certificate_key")

    @_builtins.property
    @pulumi.getter(name="deploymentId")
    def deployment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
        """
        return pulumi.get(self, "deployment_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isCa")
    def is_ca(self) -> _builtins.bool:
        """
        Indicates if the certificate is ca.
        """
        return pulumi.get(self, "is_ca")

    @_builtins.property
    @pulumi.getter(name="isLockOverride")
    def is_lock_override(self) -> _builtins.bool:
        return pulumi.get(self, "is_lock_override")

    @_builtins.property
    @pulumi.getter(name="isSelfSigned")
    def is_self_signed(self) -> _builtins.bool:
        """
        Indicates if the certificate is self signed.
        """
        return pulumi.get(self, "is_self_signed")

    @_builtins.property
    @pulumi.getter
    def issuer(self) -> _builtins.str:
        """
        The Certificate issuer.
        """
        return pulumi.get(self, "issuer")

    @_builtins.property
    @pulumi.getter
    def key(self) -> _builtins.str:
        """
        The identifier key (unique name in the scope of the deployment) of the certificate being referenced.  It must be 1 to 32 characters long, must contain only alphanumeric characters and must start with a letter.
        """
        return pulumi.get(self, "key")

    @_builtins.property
    @pulumi.getter
    def md5hash(self) -> _builtins.str:
        """
        The Certificate md5Hash.
        """
        return pulumi.get(self, "md5hash")

    @_builtins.property
    @pulumi.getter(name="publicKey")
    def public_key(self) -> _builtins.str:
        """
        The Certificate public key.
        """
        return pulumi.get(self, "public_key")

    @_builtins.property
    @pulumi.getter(name="publicKeyAlgorithm")
    def public_key_algorithm(self) -> _builtins.str:
        """
        The Certificate public key algorithm.
        """
        return pulumi.get(self, "public_key_algorithm")

    @_builtins.property
    @pulumi.getter(name="publicKeySize")
    def public_key_size(self) -> _builtins.str:
        """
        The Certificate public key size.
        """
        return pulumi.get(self, "public_key_size")

    @_builtins.property
    @pulumi.getter
    def serial(self) -> _builtins.str:
        """
        The Certificate serial.
        """
        return pulumi.get(self, "serial")

    @_builtins.property
    @pulumi.getter
    def sha1hash(self) -> _builtins.str:
        """
        The Certificate sha1 hash.
        """
        return pulumi.get(self, "sha1hash")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        Possible certificate lifecycle states.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter
    def subject(self) -> _builtins.str:
        """
        The Certificate subject.
        """
        return pulumi.get(self, "subject")

    @_builtins.property
    @pulumi.getter(name="subjectKeyId")
    def subject_key_id(self) -> _builtins.str:
        """
        The Certificate subject key id.
        """
        return pulumi.get(self, "subject_key_id")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeValidFrom")
    def time_valid_from(self) -> _builtins.str:
        """
        The time the certificate is valid from. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        """
        return pulumi.get(self, "time_valid_from")

    @_builtins.property
    @pulumi.getter(name="timeValidTo")
    def time_valid_to(self) -> _builtins.str:
        """
        The time the certificate is valid to. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        """
        return pulumi.get(self, "time_valid_to")

    @_builtins.property
    @pulumi.getter
    def version(self) -> _builtins.str:
        """
        The Certificate version.
        """
        return pulumi.get(self, "version")


class AwaitableGetDeploymentCertificateResult(GetDeploymentCertificateResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDeploymentCertificateResult(
            authority_key_id=self.authority_key_id,
            certificate_content=self.certificate_content,
            certificate_key=self.certificate_key,
            deployment_id=self.deployment_id,
            id=self.id,
            is_ca=self.is_ca,
            is_lock_override=self.is_lock_override,
            is_self_signed=self.is_self_signed,
            issuer=self.issuer,
            key=self.key,
            md5hash=self.md5hash,
            public_key=self.public_key,
            public_key_algorithm=self.public_key_algorithm,
            public_key_size=self.public_key_size,
            serial=self.serial,
            sha1hash=self.sha1hash,
            state=self.state,
            subject=self.subject,
            subject_key_id=self.subject_key_id,
            time_created=self.time_created,
            time_valid_from=self.time_valid_from,
            time_valid_to=self.time_valid_to,
            version=self.version)


def get_deployment_certificate(certificate_key: Optional[_builtins.str] = None,
                               deployment_id: Optional[_builtins.str] = None,
                               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDeploymentCertificateResult:
    """
    This data source provides details about a specific Deployment Certificate resource in Oracle Cloud Infrastructure Golden Gate service.

    Retrieves a Certificate.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deployment_certificate = oci.GoldenGate.get_deployment_certificate(certificate_key=deployment_certificate_certificate_key,
        deployment_id=test_deployment["id"])
    ```


    :param _builtins.str certificate_key: A unique certificate identifier.
    :param _builtins.str deployment_id: A unique Deployment identifier.
    """
    __args__ = dict()
    __args__['certificateKey'] = certificate_key
    __args__['deploymentId'] = deployment_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:GoldenGate/getDeploymentCertificate:getDeploymentCertificate', __args__, opts=opts, typ=GetDeploymentCertificateResult).value

    return AwaitableGetDeploymentCertificateResult(
        authority_key_id=pulumi.get(__ret__, 'authority_key_id'),
        certificate_content=pulumi.get(__ret__, 'certificate_content'),
        certificate_key=pulumi.get(__ret__, 'certificate_key'),
        deployment_id=pulumi.get(__ret__, 'deployment_id'),
        id=pulumi.get(__ret__, 'id'),
        is_ca=pulumi.get(__ret__, 'is_ca'),
        is_lock_override=pulumi.get(__ret__, 'is_lock_override'),
        is_self_signed=pulumi.get(__ret__, 'is_self_signed'),
        issuer=pulumi.get(__ret__, 'issuer'),
        key=pulumi.get(__ret__, 'key'),
        md5hash=pulumi.get(__ret__, 'md5hash'),
        public_key=pulumi.get(__ret__, 'public_key'),
        public_key_algorithm=pulumi.get(__ret__, 'public_key_algorithm'),
        public_key_size=pulumi.get(__ret__, 'public_key_size'),
        serial=pulumi.get(__ret__, 'serial'),
        sha1hash=pulumi.get(__ret__, 'sha1hash'),
        state=pulumi.get(__ret__, 'state'),
        subject=pulumi.get(__ret__, 'subject'),
        subject_key_id=pulumi.get(__ret__, 'subject_key_id'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_valid_from=pulumi.get(__ret__, 'time_valid_from'),
        time_valid_to=pulumi.get(__ret__, 'time_valid_to'),
        version=pulumi.get(__ret__, 'version'))
def get_deployment_certificate_output(certificate_key: Optional[pulumi.Input[_builtins.str]] = None,
                                      deployment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                      opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDeploymentCertificateResult]:
    """
    This data source provides details about a specific Deployment Certificate resource in Oracle Cloud Infrastructure Golden Gate service.

    Retrieves a Certificate.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deployment_certificate = oci.GoldenGate.get_deployment_certificate(certificate_key=deployment_certificate_certificate_key,
        deployment_id=test_deployment["id"])
    ```


    :param _builtins.str certificate_key: A unique certificate identifier.
    :param _builtins.str deployment_id: A unique Deployment identifier.
    """
    __args__ = dict()
    __args__['certificateKey'] = certificate_key
    __args__['deploymentId'] = deployment_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:GoldenGate/getDeploymentCertificate:getDeploymentCertificate', __args__, opts=opts, typ=GetDeploymentCertificateResult)
    return __ret__.apply(lambda __response__: GetDeploymentCertificateResult(
        authority_key_id=pulumi.get(__response__, 'authority_key_id'),
        certificate_content=pulumi.get(__response__, 'certificate_content'),
        certificate_key=pulumi.get(__response__, 'certificate_key'),
        deployment_id=pulumi.get(__response__, 'deployment_id'),
        id=pulumi.get(__response__, 'id'),
        is_ca=pulumi.get(__response__, 'is_ca'),
        is_lock_override=pulumi.get(__response__, 'is_lock_override'),
        is_self_signed=pulumi.get(__response__, 'is_self_signed'),
        issuer=pulumi.get(__response__, 'issuer'),
        key=pulumi.get(__response__, 'key'),
        md5hash=pulumi.get(__response__, 'md5hash'),
        public_key=pulumi.get(__response__, 'public_key'),
        public_key_algorithm=pulumi.get(__response__, 'public_key_algorithm'),
        public_key_size=pulumi.get(__response__, 'public_key_size'),
        serial=pulumi.get(__response__, 'serial'),
        sha1hash=pulumi.get(__response__, 'sha1hash'),
        state=pulumi.get(__response__, 'state'),
        subject=pulumi.get(__response__, 'subject'),
        subject_key_id=pulumi.get(__response__, 'subject_key_id'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_valid_from=pulumi.get(__response__, 'time_valid_from'),
        time_valid_to=pulumi.get(__response__, 'time_valid_to'),
        version=pulumi.get(__response__, 'version')))
