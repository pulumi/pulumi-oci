# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetContainerImageSignatureResult',
    'AwaitableGetContainerImageSignatureResult',
    'get_container_image_signature',
    'get_container_image_signature_output',
]

@pulumi.output_type
class GetContainerImageSignatureResult:
    """
    A collection of values returned by getContainerImageSignature.
    """
    def __init__(__self__, compartment_id=None, created_by=None, display_name=None, id=None, image_id=None, image_signature_id=None, kms_key_id=None, kms_key_version_id=None, message=None, signature=None, signing_algorithm=None, time_created=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if created_by and not isinstance(created_by, str):
            raise TypeError("Expected argument 'created_by' to be a str")
        pulumi.set(__self__, "created_by", created_by)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if image_id and not isinstance(image_id, str):
            raise TypeError("Expected argument 'image_id' to be a str")
        pulumi.set(__self__, "image_id", image_id)
        if image_signature_id and not isinstance(image_signature_id, str):
            raise TypeError("Expected argument 'image_signature_id' to be a str")
        pulumi.set(__self__, "image_signature_id", image_signature_id)
        if kms_key_id and not isinstance(kms_key_id, str):
            raise TypeError("Expected argument 'kms_key_id' to be a str")
        pulumi.set(__self__, "kms_key_id", kms_key_id)
        if kms_key_version_id and not isinstance(kms_key_version_id, str):
            raise TypeError("Expected argument 'kms_key_version_id' to be a str")
        pulumi.set(__self__, "kms_key_version_id", kms_key_version_id)
        if message and not isinstance(message, str):
            raise TypeError("Expected argument 'message' to be a str")
        pulumi.set(__self__, "message", message)
        if signature and not isinstance(signature, str):
            raise TypeError("Expected argument 'signature' to be a str")
        pulumi.set(__self__, "signature", signature)
        if signing_algorithm and not isinstance(signing_algorithm, str):
            raise TypeError("Expected argument 'signing_algorithm' to be a str")
        pulumi.set(__self__, "signing_algorithm", signing_algorithm)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the container repository exists.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> str:
        """
        The id of the user or principal that created the resource.
        """
        return pulumi.get(self, "created_by")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        The last 10 characters of the kmsKeyId, the last 10 characters of the kmsKeyVersionId, the signingAlgorithm, and the last 10 characters of the signatureId.  Example: `wrmz22sixa::qdwyc2ptun::SHA_256_RSA_PKCS_PSS::2vwmobasva`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image signature.  Example: `ocid1.containerimagesignature.oc1..exampleuniqueID`
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="imageId")
    def image_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image.  Example: `ocid1.containerimage.oc1..exampleuniqueID`
        """
        return pulumi.get(self, "image_id")

    @property
    @pulumi.getter(name="imageSignatureId")
    def image_signature_id(self) -> str:
        return pulumi.get(self, "image_signature_id")

    @property
    @pulumi.getter(name="kmsKeyId")
    def kms_key_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyId used to sign the container image.  Example: `ocid1.key.oc1..exampleuniqueID`
        """
        return pulumi.get(self, "kms_key_id")

    @property
    @pulumi.getter(name="kmsKeyVersionId")
    def kms_key_version_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyVersionId used to sign the container image.  Example: `ocid1.keyversion.oc1..exampleuniqueID`
        """
        return pulumi.get(self, "kms_key_version_id")

    @property
    @pulumi.getter
    def message(self) -> str:
        """
        The base64 encoded signature payload that was signed.
        """
        return pulumi.get(self, "message")

    @property
    @pulumi.getter
    def signature(self) -> str:
        """
        The signature of the message field using the kmsKeyId, the kmsKeyVersionId, and the signingAlgorithm.
        """
        return pulumi.get(self, "signature")

    @property
    @pulumi.getter(name="signingAlgorithm")
    def signing_algorithm(self) -> str:
        """
        The algorithm to be used for signing. These are the only supported signing algorithms for container images.
        """
        return pulumi.get(self, "signing_algorithm")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        An RFC 3339 timestamp indicating when the image was created.
        """
        return pulumi.get(self, "time_created")


class AwaitableGetContainerImageSignatureResult(GetContainerImageSignatureResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetContainerImageSignatureResult(
            compartment_id=self.compartment_id,
            created_by=self.created_by,
            display_name=self.display_name,
            id=self.id,
            image_id=self.image_id,
            image_signature_id=self.image_signature_id,
            kms_key_id=self.kms_key_id,
            kms_key_version_id=self.kms_key_version_id,
            message=self.message,
            signature=self.signature,
            signing_algorithm=self.signing_algorithm,
            time_created=self.time_created)


def get_container_image_signature(image_signature_id: Optional[str] = None,
                                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetContainerImageSignatureResult:
    """
    This data source provides details about a specific Container Image Signature resource in Oracle Cloud Infrastructure Artifacts service.

    Get container image signature metadata.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_container_image_signature = oci.Artifacts.get_container_image_signature(image_signature_id=oci_artifacts_image_signature["test_image_signature"]["id"])
    ```


    :param str image_signature_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image signature.  Example: `ocid1.containersignature.oc1..exampleuniqueID`
    """
    __args__ = dict()
    __args__['imageSignatureId'] = image_signature_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Artifacts/getContainerImageSignature:getContainerImageSignature', __args__, opts=opts, typ=GetContainerImageSignatureResult).value

    return AwaitableGetContainerImageSignatureResult(
        compartment_id=__ret__.compartment_id,
        created_by=__ret__.created_by,
        display_name=__ret__.display_name,
        id=__ret__.id,
        image_id=__ret__.image_id,
        image_signature_id=__ret__.image_signature_id,
        kms_key_id=__ret__.kms_key_id,
        kms_key_version_id=__ret__.kms_key_version_id,
        message=__ret__.message,
        signature=__ret__.signature,
        signing_algorithm=__ret__.signing_algorithm,
        time_created=__ret__.time_created)


@_utilities.lift_output_func(get_container_image_signature)
def get_container_image_signature_output(image_signature_id: Optional[pulumi.Input[str]] = None,
                                         opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetContainerImageSignatureResult]:
    """
    This data source provides details about a specific Container Image Signature resource in Oracle Cloud Infrastructure Artifacts service.

    Get container image signature metadata.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_container_image_signature = oci.Artifacts.get_container_image_signature(image_signature_id=oci_artifacts_image_signature["test_image_signature"]["id"])
    ```


    :param str image_signature_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image signature.  Example: `ocid1.containersignature.oc1..exampleuniqueID`
    """
    ...