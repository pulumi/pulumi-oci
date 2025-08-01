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

__all__ = [
    'GetCertificateAuthoritiesResult',
    'AwaitableGetCertificateAuthoritiesResult',
    'get_certificate_authorities',
    'get_certificate_authorities_output',
]

@pulumi.output_type
class GetCertificateAuthoritiesResult:
    """
    A collection of values returned by getCertificateAuthorities.
    """
    def __init__(__self__, certificate_authority_collections=None, certificate_authority_id=None, compartment_id=None, filters=None, id=None, issuer_certificate_authority_id=None, name=None, state=None):
        if certificate_authority_collections and not isinstance(certificate_authority_collections, list):
            raise TypeError("Expected argument 'certificate_authority_collections' to be a list")
        pulumi.set(__self__, "certificate_authority_collections", certificate_authority_collections)
        if certificate_authority_id and not isinstance(certificate_authority_id, str):
            raise TypeError("Expected argument 'certificate_authority_id' to be a str")
        pulumi.set(__self__, "certificate_authority_id", certificate_authority_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if issuer_certificate_authority_id and not isinstance(issuer_certificate_authority_id, str):
            raise TypeError("Expected argument 'issuer_certificate_authority_id' to be a str")
        pulumi.set(__self__, "issuer_certificate_authority_id", issuer_certificate_authority_id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="certificateAuthorityCollections")
    def certificate_authority_collections(self) -> Sequence['outputs.GetCertificateAuthoritiesCertificateAuthorityCollectionResult']:
        """
        The list of certificate_authority_collection.
        """
        return pulumi.get(self, "certificate_authority_collections")

    @_builtins.property
    @pulumi.getter(name="certificateAuthorityId")
    def certificate_authority_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the CA.
        """
        return pulumi.get(self, "certificate_authority_id")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the compartment under which the CA is created.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetCertificateAuthoritiesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="issuerCertificateAuthorityId")
    def issuer_certificate_authority_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the parent CA that issued this CA. If this is the root CA, then this value is null.
        """
        return pulumi.get(self, "issuer_certificate_authority_id")

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[_builtins.str]:
        """
        A user-friendly name for the CA. Names are unique within a compartment. Avoid entering confidential information. Valid characters include uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current lifecycle state of the certificate authority.
        """
        return pulumi.get(self, "state")


class AwaitableGetCertificateAuthoritiesResult(GetCertificateAuthoritiesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetCertificateAuthoritiesResult(
            certificate_authority_collections=self.certificate_authority_collections,
            certificate_authority_id=self.certificate_authority_id,
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            issuer_certificate_authority_id=self.issuer_certificate_authority_id,
            name=self.name,
            state=self.state)


def get_certificate_authorities(certificate_authority_id: Optional[_builtins.str] = None,
                                compartment_id: Optional[_builtins.str] = None,
                                filters: Optional[Sequence[Union['GetCertificateAuthoritiesFilterArgs', 'GetCertificateAuthoritiesFilterArgsDict']]] = None,
                                issuer_certificate_authority_id: Optional[_builtins.str] = None,
                                name: Optional[_builtins.str] = None,
                                state: Optional[_builtins.str] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetCertificateAuthoritiesResult:
    """
    This data source provides the list of Certificate Authorities in Oracle Cloud Infrastructure Certificates Management service.

    Lists all certificate authorities (CAs) in the specified compartment.
    Optionally, you can use the parameter `FilterByCertificateAuthorityIdQueryParam` to limit the results to a single item that matches the specified CA.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_certificate_authorities = oci.CertificatesManagement.get_certificate_authorities(certificate_authority_id=test_certificate_authority["id"],
        compartment_id=compartment_id,
        issuer_certificate_authority_id=test_certificate_authority["id"],
        name=certificate_authority_name,
        state=certificate_authority_state)
    ```


    :param _builtins.str certificate_authority_id: The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
    :param _builtins.str compartment_id: A filter that returns only resources that match the given compartment OCID.
    :param _builtins.str issuer_certificate_authority_id: The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
    :param _builtins.str name: A filter that returns only resources that match the specified name.
    :param _builtins.str state: A filter that returns only resources that match the given lifecycle state. The state value is case-insensitive.
    """
    __args__ = dict()
    __args__['certificateAuthorityId'] = certificate_authority_id
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['issuerCertificateAuthorityId'] = issuer_certificate_authority_id
    __args__['name'] = name
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:CertificatesManagement/getCertificateAuthorities:getCertificateAuthorities', __args__, opts=opts, typ=GetCertificateAuthoritiesResult).value

    return AwaitableGetCertificateAuthoritiesResult(
        certificate_authority_collections=pulumi.get(__ret__, 'certificate_authority_collections'),
        certificate_authority_id=pulumi.get(__ret__, 'certificate_authority_id'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        issuer_certificate_authority_id=pulumi.get(__ret__, 'issuer_certificate_authority_id'),
        name=pulumi.get(__ret__, 'name'),
        state=pulumi.get(__ret__, 'state'))
def get_certificate_authorities_output(certificate_authority_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                       compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                       filters: Optional[pulumi.Input[Optional[Sequence[Union['GetCertificateAuthoritiesFilterArgs', 'GetCertificateAuthoritiesFilterArgsDict']]]]] = None,
                                       issuer_certificate_authority_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                       name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                       state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                       opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetCertificateAuthoritiesResult]:
    """
    This data source provides the list of Certificate Authorities in Oracle Cloud Infrastructure Certificates Management service.

    Lists all certificate authorities (CAs) in the specified compartment.
    Optionally, you can use the parameter `FilterByCertificateAuthorityIdQueryParam` to limit the results to a single item that matches the specified CA.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_certificate_authorities = oci.CertificatesManagement.get_certificate_authorities(certificate_authority_id=test_certificate_authority["id"],
        compartment_id=compartment_id,
        issuer_certificate_authority_id=test_certificate_authority["id"],
        name=certificate_authority_name,
        state=certificate_authority_state)
    ```


    :param _builtins.str certificate_authority_id: The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
    :param _builtins.str compartment_id: A filter that returns only resources that match the given compartment OCID.
    :param _builtins.str issuer_certificate_authority_id: The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
    :param _builtins.str name: A filter that returns only resources that match the specified name.
    :param _builtins.str state: A filter that returns only resources that match the given lifecycle state. The state value is case-insensitive.
    """
    __args__ = dict()
    __args__['certificateAuthorityId'] = certificate_authority_id
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['issuerCertificateAuthorityId'] = issuer_certificate_authority_id
    __args__['name'] = name
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:CertificatesManagement/getCertificateAuthorities:getCertificateAuthorities', __args__, opts=opts, typ=GetCertificateAuthoritiesResult)
    return __ret__.apply(lambda __response__: GetCertificateAuthoritiesResult(
        certificate_authority_collections=pulumi.get(__response__, 'certificate_authority_collections'),
        certificate_authority_id=pulumi.get(__response__, 'certificate_authority_id'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        issuer_certificate_authority_id=pulumi.get(__response__, 'issuer_certificate_authority_id'),
        name=pulumi.get(__response__, 'name'),
        state=pulumi.get(__response__, 'state')))
