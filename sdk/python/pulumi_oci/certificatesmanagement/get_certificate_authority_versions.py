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

__all__ = [
    'GetCertificateAuthorityVersionsResult',
    'AwaitableGetCertificateAuthorityVersionsResult',
    'get_certificate_authority_versions',
    'get_certificate_authority_versions_output',
]

@pulumi.output_type
class GetCertificateAuthorityVersionsResult:
    """
    A collection of values returned by getCertificateAuthorityVersions.
    """
    def __init__(__self__, certificate_authority_id=None, certificate_authority_version_collections=None, filters=None, id=None, version_number=None):
        if certificate_authority_id and not isinstance(certificate_authority_id, str):
            raise TypeError("Expected argument 'certificate_authority_id' to be a str")
        pulumi.set(__self__, "certificate_authority_id", certificate_authority_id)
        if certificate_authority_version_collections and not isinstance(certificate_authority_version_collections, list):
            raise TypeError("Expected argument 'certificate_authority_version_collections' to be a list")
        pulumi.set(__self__, "certificate_authority_version_collections", certificate_authority_version_collections)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if version_number and not isinstance(version_number, str):
            raise TypeError("Expected argument 'version_number' to be a str")
        pulumi.set(__self__, "version_number", version_number)

    @property
    @pulumi.getter(name="certificateAuthorityId")
    def certificate_authority_id(self) -> str:
        """
        The OCID of the CA.
        """
        return pulumi.get(self, "certificate_authority_id")

    @property
    @pulumi.getter(name="certificateAuthorityVersionCollections")
    def certificate_authority_version_collections(self) -> Sequence['outputs.GetCertificateAuthorityVersionsCertificateAuthorityVersionCollectionResult']:
        """
        The list of certificate_authority_version_collection.
        """
        return pulumi.get(self, "certificate_authority_version_collections")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetCertificateAuthorityVersionsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="versionNumber")
    def version_number(self) -> Optional[str]:
        """
        The version number of the CA.
        """
        return pulumi.get(self, "version_number")


class AwaitableGetCertificateAuthorityVersionsResult(GetCertificateAuthorityVersionsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetCertificateAuthorityVersionsResult(
            certificate_authority_id=self.certificate_authority_id,
            certificate_authority_version_collections=self.certificate_authority_version_collections,
            filters=self.filters,
            id=self.id,
            version_number=self.version_number)


def get_certificate_authority_versions(certificate_authority_id: Optional[str] = None,
                                       filters: Optional[Sequence[pulumi.InputType['GetCertificateAuthorityVersionsFilterArgs']]] = None,
                                       version_number: Optional[str] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetCertificateAuthorityVersionsResult:
    """
    This data source provides the list of Certificate Authority Versions in Oracle Cloud Infrastructure Certificates Management service.

    Lists all versions for the specified certificate authority (CA).
    Optionally, you can use the parameter `FilterByVersionNumberQueryParam` to limit the results to a single item that matches the specified version number.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_certificate_authority_versions = oci.CertificatesManagement.get_certificate_authority_versions(certificate_authority_id=oci_certificates_management_certificate_authority["test_certificate_authority"]["id"],
        version_number=var["certificate_authority_version_version_number"])
    ```


    :param str certificate_authority_id: The OCID of the certificate authority (CA).
    :param str version_number: A filter that returns only resources that match the specified version number. The default value is 0, which means that this filter is not applied.
    """
    __args__ = dict()
    __args__['certificateAuthorityId'] = certificate_authority_id
    __args__['filters'] = filters
    __args__['versionNumber'] = version_number
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:CertificatesManagement/getCertificateAuthorityVersions:getCertificateAuthorityVersions', __args__, opts=opts, typ=GetCertificateAuthorityVersionsResult).value

    return AwaitableGetCertificateAuthorityVersionsResult(
        certificate_authority_id=__ret__.certificate_authority_id,
        certificate_authority_version_collections=__ret__.certificate_authority_version_collections,
        filters=__ret__.filters,
        id=__ret__.id,
        version_number=__ret__.version_number)


@_utilities.lift_output_func(get_certificate_authority_versions)
def get_certificate_authority_versions_output(certificate_authority_id: Optional[pulumi.Input[str]] = None,
                                              filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetCertificateAuthorityVersionsFilterArgs']]]]] = None,
                                              version_number: Optional[pulumi.Input[Optional[str]]] = None,
                                              opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetCertificateAuthorityVersionsResult]:
    """
    This data source provides the list of Certificate Authority Versions in Oracle Cloud Infrastructure Certificates Management service.

    Lists all versions for the specified certificate authority (CA).
    Optionally, you can use the parameter `FilterByVersionNumberQueryParam` to limit the results to a single item that matches the specified version number.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_certificate_authority_versions = oci.CertificatesManagement.get_certificate_authority_versions(certificate_authority_id=oci_certificates_management_certificate_authority["test_certificate_authority"]["id"],
        version_number=var["certificate_authority_version_version_number"])
    ```


    :param str certificate_authority_id: The OCID of the certificate authority (CA).
    :param str version_number: A filter that returns only resources that match the specified version number. The default value is 0, which means that this filter is not applied.
    """
    ...