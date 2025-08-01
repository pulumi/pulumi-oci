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

__all__ = [
    'GetDomainsOciConsoleSignOnPolicyConsentResult',
    'AwaitableGetDomainsOciConsoleSignOnPolicyConsentResult',
    'get_domains_oci_console_sign_on_policy_consent',
    'get_domains_oci_console_sign_on_policy_consent_output',
]

@pulumi.output_type
class GetDomainsOciConsoleSignOnPolicyConsentResult:
    """
    A collection of values returned by getDomainsOciConsoleSignOnPolicyConsent.
    """
    def __init__(__self__, attribute_sets=None, attributes=None, authorization=None, change_type=None, client_ip=None, compartment_ocid=None, consent_signed_bies=None, delete_in_progress=None, domain_ocid=None, id=None, idcs_created_bies=None, idcs_endpoint=None, idcs_last_modified_bies=None, idcs_last_upgraded_in_release=None, idcs_prevented_operations=None, justification=None, metas=None, modified_resources=None, notification_recipients=None, oci_console_sign_on_policy_consent_id=None, ocid=None, policy_resources=None, reason=None, resource_type_schema_version=None, schemas=None, tags=None, tenancy_ocid=None, time_consent_signed=None):
        if attribute_sets and not isinstance(attribute_sets, list):
            raise TypeError("Expected argument 'attribute_sets' to be a list")
        pulumi.set(__self__, "attribute_sets", attribute_sets)
        if attributes and not isinstance(attributes, str):
            raise TypeError("Expected argument 'attributes' to be a str")
        pulumi.set(__self__, "attributes", attributes)
        if authorization and not isinstance(authorization, str):
            raise TypeError("Expected argument 'authorization' to be a str")
        pulumi.set(__self__, "authorization", authorization)
        if change_type and not isinstance(change_type, str):
            raise TypeError("Expected argument 'change_type' to be a str")
        pulumi.set(__self__, "change_type", change_type)
        if client_ip and not isinstance(client_ip, str):
            raise TypeError("Expected argument 'client_ip' to be a str")
        pulumi.set(__self__, "client_ip", client_ip)
        if compartment_ocid and not isinstance(compartment_ocid, str):
            raise TypeError("Expected argument 'compartment_ocid' to be a str")
        pulumi.set(__self__, "compartment_ocid", compartment_ocid)
        if consent_signed_bies and not isinstance(consent_signed_bies, list):
            raise TypeError("Expected argument 'consent_signed_bies' to be a list")
        pulumi.set(__self__, "consent_signed_bies", consent_signed_bies)
        if delete_in_progress and not isinstance(delete_in_progress, bool):
            raise TypeError("Expected argument 'delete_in_progress' to be a bool")
        pulumi.set(__self__, "delete_in_progress", delete_in_progress)
        if domain_ocid and not isinstance(domain_ocid, str):
            raise TypeError("Expected argument 'domain_ocid' to be a str")
        pulumi.set(__self__, "domain_ocid", domain_ocid)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if idcs_created_bies and not isinstance(idcs_created_bies, list):
            raise TypeError("Expected argument 'idcs_created_bies' to be a list")
        pulumi.set(__self__, "idcs_created_bies", idcs_created_bies)
        if idcs_endpoint and not isinstance(idcs_endpoint, str):
            raise TypeError("Expected argument 'idcs_endpoint' to be a str")
        pulumi.set(__self__, "idcs_endpoint", idcs_endpoint)
        if idcs_last_modified_bies and not isinstance(idcs_last_modified_bies, list):
            raise TypeError("Expected argument 'idcs_last_modified_bies' to be a list")
        pulumi.set(__self__, "idcs_last_modified_bies", idcs_last_modified_bies)
        if idcs_last_upgraded_in_release and not isinstance(idcs_last_upgraded_in_release, str):
            raise TypeError("Expected argument 'idcs_last_upgraded_in_release' to be a str")
        pulumi.set(__self__, "idcs_last_upgraded_in_release", idcs_last_upgraded_in_release)
        if idcs_prevented_operations and not isinstance(idcs_prevented_operations, list):
            raise TypeError("Expected argument 'idcs_prevented_operations' to be a list")
        pulumi.set(__self__, "idcs_prevented_operations", idcs_prevented_operations)
        if justification and not isinstance(justification, str):
            raise TypeError("Expected argument 'justification' to be a str")
        pulumi.set(__self__, "justification", justification)
        if metas and not isinstance(metas, list):
            raise TypeError("Expected argument 'metas' to be a list")
        pulumi.set(__self__, "metas", metas)
        if modified_resources and not isinstance(modified_resources, list):
            raise TypeError("Expected argument 'modified_resources' to be a list")
        pulumi.set(__self__, "modified_resources", modified_resources)
        if notification_recipients and not isinstance(notification_recipients, list):
            raise TypeError("Expected argument 'notification_recipients' to be a list")
        pulumi.set(__self__, "notification_recipients", notification_recipients)
        if oci_console_sign_on_policy_consent_id and not isinstance(oci_console_sign_on_policy_consent_id, str):
            raise TypeError("Expected argument 'oci_console_sign_on_policy_consent_id' to be a str")
        pulumi.set(__self__, "oci_console_sign_on_policy_consent_id", oci_console_sign_on_policy_consent_id)
        if ocid and not isinstance(ocid, str):
            raise TypeError("Expected argument 'ocid' to be a str")
        pulumi.set(__self__, "ocid", ocid)
        if policy_resources and not isinstance(policy_resources, list):
            raise TypeError("Expected argument 'policy_resources' to be a list")
        pulumi.set(__self__, "policy_resources", policy_resources)
        if reason and not isinstance(reason, str):
            raise TypeError("Expected argument 'reason' to be a str")
        pulumi.set(__self__, "reason", reason)
        if resource_type_schema_version and not isinstance(resource_type_schema_version, str):
            raise TypeError("Expected argument 'resource_type_schema_version' to be a str")
        pulumi.set(__self__, "resource_type_schema_version", resource_type_schema_version)
        if schemas and not isinstance(schemas, list):
            raise TypeError("Expected argument 'schemas' to be a list")
        pulumi.set(__self__, "schemas", schemas)
        if tags and not isinstance(tags, list):
            raise TypeError("Expected argument 'tags' to be a list")
        pulumi.set(__self__, "tags", tags)
        if tenancy_ocid and not isinstance(tenancy_ocid, str):
            raise TypeError("Expected argument 'tenancy_ocid' to be a str")
        pulumi.set(__self__, "tenancy_ocid", tenancy_ocid)
        if time_consent_signed and not isinstance(time_consent_signed, str):
            raise TypeError("Expected argument 'time_consent_signed' to be a str")
        pulumi.set(__self__, "time_consent_signed", time_consent_signed)

    @_builtins.property
    @pulumi.getter(name="attributeSets")
    def attribute_sets(self) -> Optional[Sequence[_builtins.str]]:
        return pulumi.get(self, "attribute_sets")

    @_builtins.property
    @pulumi.getter
    def attributes(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "attributes")

    @_builtins.property
    @pulumi.getter
    def authorization(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "authorization")

    @_builtins.property
    @pulumi.getter(name="changeType")
    def change_type(self) -> _builtins.str:
        """
        Change Type - MODIFIED or RESTORED_TO_FACTORY_DEFAULT
        """
        return pulumi.get(self, "change_type")

    @_builtins.property
    @pulumi.getter(name="clientIp")
    def client_ip(self) -> _builtins.str:
        """
        Client IP of the Consent Signer
        """
        return pulumi.get(self, "client_ip")

    @_builtins.property
    @pulumi.getter(name="compartmentOcid")
    def compartment_ocid(self) -> _builtins.str:
        """
        Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        """
        return pulumi.get(self, "compartment_ocid")

    @_builtins.property
    @pulumi.getter(name="consentSignedBies")
    def consent_signed_bies(self) -> Sequence['outputs.GetDomainsOciConsoleSignOnPolicyConsentConsentSignedByResult']:
        """
        User or App that signs the consent.
        """
        return pulumi.get(self, "consent_signed_bies")

    @_builtins.property
    @pulumi.getter(name="deleteInProgress")
    def delete_in_progress(self) -> _builtins.bool:
        """
        A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
        """
        return pulumi.get(self, "delete_in_progress")

    @_builtins.property
    @pulumi.getter(name="domainOcid")
    def domain_ocid(self) -> _builtins.str:
        """
        Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
        """
        return pulumi.get(self, "domain_ocid")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="idcsCreatedBies")
    def idcs_created_bies(self) -> Sequence['outputs.GetDomainsOciConsoleSignOnPolicyConsentIdcsCreatedByResult']:
        """
        The User or App who created the Resource
        """
        return pulumi.get(self, "idcs_created_bies")

    @_builtins.property
    @pulumi.getter(name="idcsEndpoint")
    def idcs_endpoint(self) -> _builtins.str:
        return pulumi.get(self, "idcs_endpoint")

    @_builtins.property
    @pulumi.getter(name="idcsLastModifiedBies")
    def idcs_last_modified_bies(self) -> Sequence['outputs.GetDomainsOciConsoleSignOnPolicyConsentIdcsLastModifiedByResult']:
        """
        The User or App who modified the Resource
        """
        return pulumi.get(self, "idcs_last_modified_bies")

    @_builtins.property
    @pulumi.getter(name="idcsLastUpgradedInRelease")
    def idcs_last_upgraded_in_release(self) -> _builtins.str:
        """
        The release number when the resource was upgraded.
        """
        return pulumi.get(self, "idcs_last_upgraded_in_release")

    @_builtins.property
    @pulumi.getter(name="idcsPreventedOperations")
    def idcs_prevented_operations(self) -> Sequence[_builtins.str]:
        """
        Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
        """
        return pulumi.get(self, "idcs_prevented_operations")

    @_builtins.property
    @pulumi.getter
    def justification(self) -> _builtins.str:
        """
        The justification for the change when an identity domain administrator opts to modify the Oracle security defaults for the "Security Policy for Oracle Cloud Infrastructure Console" sign-on policy shipped by Oracle.
        """
        return pulumi.get(self, "justification")

    @_builtins.property
    @pulumi.getter
    def metas(self) -> Sequence['outputs.GetDomainsOciConsoleSignOnPolicyConsentMetaResult']:
        """
        A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        """
        return pulumi.get(self, "metas")

    @_builtins.property
    @pulumi.getter(name="modifiedResources")
    def modified_resources(self) -> Sequence['outputs.GetDomainsOciConsoleSignOnPolicyConsentModifiedResourceResult']:
        """
        The modified Policy, Rule, ConditionGroup or Condition during consent signing.
        """
        return pulumi.get(self, "modified_resources")

    @_builtins.property
    @pulumi.getter(name="notificationRecipients")
    def notification_recipients(self) -> Sequence[_builtins.str]:
        """
        The recipients of the email notification for the change in consent.
        """
        return pulumi.get(self, "notification_recipients")

    @_builtins.property
    @pulumi.getter(name="ociConsoleSignOnPolicyConsentId")
    def oci_console_sign_on_policy_consent_id(self) -> _builtins.str:
        return pulumi.get(self, "oci_console_sign_on_policy_consent_id")

    @_builtins.property
    @pulumi.getter
    def ocid(self) -> _builtins.str:
        """
        Policy Resource Ocid
        """
        return pulumi.get(self, "ocid")

    @_builtins.property
    @pulumi.getter(name="policyResources")
    def policy_resources(self) -> Sequence['outputs.GetDomainsOciConsoleSignOnPolicyConsentPolicyResourceResult']:
        """
        Policy Resource
        """
        return pulumi.get(self, "policy_resources")

    @_builtins.property
    @pulumi.getter
    def reason(self) -> _builtins.str:
        """
        The detailed reason for the change when an identity domain administrator opts to modify the Oracle security defaults for the "Security Policy for Oracle Cloud Infrastructure Console" sign-on policy shipped by Oracle.
        """
        return pulumi.get(self, "reason")

    @_builtins.property
    @pulumi.getter(name="resourceTypeSchemaVersion")
    def resource_type_schema_version(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "resource_type_schema_version")

    @_builtins.property
    @pulumi.getter
    def schemas(self) -> Sequence[_builtins.str]:
        """
        REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \\"enterprise\\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
        """
        return pulumi.get(self, "schemas")

    @_builtins.property
    @pulumi.getter
    def tags(self) -> Sequence['outputs.GetDomainsOciConsoleSignOnPolicyConsentTagResult']:
        """
        A list of tags on this resource.
        """
        return pulumi.get(self, "tags")

    @_builtins.property
    @pulumi.getter(name="tenancyOcid")
    def tenancy_ocid(self) -> _builtins.str:
        """
        Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        """
        return pulumi.get(self, "tenancy_ocid")

    @_builtins.property
    @pulumi.getter(name="timeConsentSigned")
    def time_consent_signed(self) -> _builtins.str:
        """
        Time when Consent was signed.
        """
        return pulumi.get(self, "time_consent_signed")


class AwaitableGetDomainsOciConsoleSignOnPolicyConsentResult(GetDomainsOciConsoleSignOnPolicyConsentResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDomainsOciConsoleSignOnPolicyConsentResult(
            attribute_sets=self.attribute_sets,
            attributes=self.attributes,
            authorization=self.authorization,
            change_type=self.change_type,
            client_ip=self.client_ip,
            compartment_ocid=self.compartment_ocid,
            consent_signed_bies=self.consent_signed_bies,
            delete_in_progress=self.delete_in_progress,
            domain_ocid=self.domain_ocid,
            id=self.id,
            idcs_created_bies=self.idcs_created_bies,
            idcs_endpoint=self.idcs_endpoint,
            idcs_last_modified_bies=self.idcs_last_modified_bies,
            idcs_last_upgraded_in_release=self.idcs_last_upgraded_in_release,
            idcs_prevented_operations=self.idcs_prevented_operations,
            justification=self.justification,
            metas=self.metas,
            modified_resources=self.modified_resources,
            notification_recipients=self.notification_recipients,
            oci_console_sign_on_policy_consent_id=self.oci_console_sign_on_policy_consent_id,
            ocid=self.ocid,
            policy_resources=self.policy_resources,
            reason=self.reason,
            resource_type_schema_version=self.resource_type_schema_version,
            schemas=self.schemas,
            tags=self.tags,
            tenancy_ocid=self.tenancy_ocid,
            time_consent_signed=self.time_consent_signed)


def get_domains_oci_console_sign_on_policy_consent(attribute_sets: Optional[Sequence[_builtins.str]] = None,
                                                   attributes: Optional[_builtins.str] = None,
                                                   authorization: Optional[_builtins.str] = None,
                                                   idcs_endpoint: Optional[_builtins.str] = None,
                                                   oci_console_sign_on_policy_consent_id: Optional[_builtins.str] = None,
                                                   resource_type_schema_version: Optional[_builtins.str] = None,
                                                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDomainsOciConsoleSignOnPolicyConsentResult:
    """
    This data source provides details about a specific Oci Console Sign On Policy Consent resource in Oracle Cloud Infrastructure Identity Domains service.

    Get a OciConsoleSignOnPolicyConsent Entry.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_oci_console_sign_on_policy_consent = oci.Identity.get_domains_oci_console_sign_on_policy_consent(idcs_endpoint=test_domain["url"],
        oci_console_sign_on_policy_consent_id=test_oci_console_sign_on_policy_consent_oci_identity_domains_oci_console_sign_on_policy_consent["id"],
        attribute_sets=oci_console_sign_on_policy_consent_attribute_sets,
        attributes=oci_console_sign_on_policy_consent_attributes,
        authorization=oci_console_sign_on_policy_consent_authorization,
        resource_type_schema_version=oci_console_sign_on_policy_consent_resource_type_schema_version)
    ```


    :param Sequence[_builtins.str] attribute_sets: A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
    :param _builtins.str attributes: A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
    :param _builtins.str authorization: The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
    :param _builtins.str idcs_endpoint: The basic endpoint for the identity domain
    :param _builtins.str oci_console_sign_on_policy_consent_id: ID of the resource
    :param _builtins.str resource_type_schema_version: An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
    """
    __args__ = dict()
    __args__['attributeSets'] = attribute_sets
    __args__['attributes'] = attributes
    __args__['authorization'] = authorization
    __args__['idcsEndpoint'] = idcs_endpoint
    __args__['ociConsoleSignOnPolicyConsentId'] = oci_console_sign_on_policy_consent_id
    __args__['resourceTypeSchemaVersion'] = resource_type_schema_version
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Identity/getDomainsOciConsoleSignOnPolicyConsent:getDomainsOciConsoleSignOnPolicyConsent', __args__, opts=opts, typ=GetDomainsOciConsoleSignOnPolicyConsentResult).value

    return AwaitableGetDomainsOciConsoleSignOnPolicyConsentResult(
        attribute_sets=pulumi.get(__ret__, 'attribute_sets'),
        attributes=pulumi.get(__ret__, 'attributes'),
        authorization=pulumi.get(__ret__, 'authorization'),
        change_type=pulumi.get(__ret__, 'change_type'),
        client_ip=pulumi.get(__ret__, 'client_ip'),
        compartment_ocid=pulumi.get(__ret__, 'compartment_ocid'),
        consent_signed_bies=pulumi.get(__ret__, 'consent_signed_bies'),
        delete_in_progress=pulumi.get(__ret__, 'delete_in_progress'),
        domain_ocid=pulumi.get(__ret__, 'domain_ocid'),
        id=pulumi.get(__ret__, 'id'),
        idcs_created_bies=pulumi.get(__ret__, 'idcs_created_bies'),
        idcs_endpoint=pulumi.get(__ret__, 'idcs_endpoint'),
        idcs_last_modified_bies=pulumi.get(__ret__, 'idcs_last_modified_bies'),
        idcs_last_upgraded_in_release=pulumi.get(__ret__, 'idcs_last_upgraded_in_release'),
        idcs_prevented_operations=pulumi.get(__ret__, 'idcs_prevented_operations'),
        justification=pulumi.get(__ret__, 'justification'),
        metas=pulumi.get(__ret__, 'metas'),
        modified_resources=pulumi.get(__ret__, 'modified_resources'),
        notification_recipients=pulumi.get(__ret__, 'notification_recipients'),
        oci_console_sign_on_policy_consent_id=pulumi.get(__ret__, 'oci_console_sign_on_policy_consent_id'),
        ocid=pulumi.get(__ret__, 'ocid'),
        policy_resources=pulumi.get(__ret__, 'policy_resources'),
        reason=pulumi.get(__ret__, 'reason'),
        resource_type_schema_version=pulumi.get(__ret__, 'resource_type_schema_version'),
        schemas=pulumi.get(__ret__, 'schemas'),
        tags=pulumi.get(__ret__, 'tags'),
        tenancy_ocid=pulumi.get(__ret__, 'tenancy_ocid'),
        time_consent_signed=pulumi.get(__ret__, 'time_consent_signed'))
def get_domains_oci_console_sign_on_policy_consent_output(attribute_sets: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                          attributes: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                          authorization: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                          idcs_endpoint: Optional[pulumi.Input[_builtins.str]] = None,
                                                          oci_console_sign_on_policy_consent_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                          resource_type_schema_version: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                          opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDomainsOciConsoleSignOnPolicyConsentResult]:
    """
    This data source provides details about a specific Oci Console Sign On Policy Consent resource in Oracle Cloud Infrastructure Identity Domains service.

    Get a OciConsoleSignOnPolicyConsent Entry.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_oci_console_sign_on_policy_consent = oci.Identity.get_domains_oci_console_sign_on_policy_consent(idcs_endpoint=test_domain["url"],
        oci_console_sign_on_policy_consent_id=test_oci_console_sign_on_policy_consent_oci_identity_domains_oci_console_sign_on_policy_consent["id"],
        attribute_sets=oci_console_sign_on_policy_consent_attribute_sets,
        attributes=oci_console_sign_on_policy_consent_attributes,
        authorization=oci_console_sign_on_policy_consent_authorization,
        resource_type_schema_version=oci_console_sign_on_policy_consent_resource_type_schema_version)
    ```


    :param Sequence[_builtins.str] attribute_sets: A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
    :param _builtins.str attributes: A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
    :param _builtins.str authorization: The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
    :param _builtins.str idcs_endpoint: The basic endpoint for the identity domain
    :param _builtins.str oci_console_sign_on_policy_consent_id: ID of the resource
    :param _builtins.str resource_type_schema_version: An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
    """
    __args__ = dict()
    __args__['attributeSets'] = attribute_sets
    __args__['attributes'] = attributes
    __args__['authorization'] = authorization
    __args__['idcsEndpoint'] = idcs_endpoint
    __args__['ociConsoleSignOnPolicyConsentId'] = oci_console_sign_on_policy_consent_id
    __args__['resourceTypeSchemaVersion'] = resource_type_schema_version
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Identity/getDomainsOciConsoleSignOnPolicyConsent:getDomainsOciConsoleSignOnPolicyConsent', __args__, opts=opts, typ=GetDomainsOciConsoleSignOnPolicyConsentResult)
    return __ret__.apply(lambda __response__: GetDomainsOciConsoleSignOnPolicyConsentResult(
        attribute_sets=pulumi.get(__response__, 'attribute_sets'),
        attributes=pulumi.get(__response__, 'attributes'),
        authorization=pulumi.get(__response__, 'authorization'),
        change_type=pulumi.get(__response__, 'change_type'),
        client_ip=pulumi.get(__response__, 'client_ip'),
        compartment_ocid=pulumi.get(__response__, 'compartment_ocid'),
        consent_signed_bies=pulumi.get(__response__, 'consent_signed_bies'),
        delete_in_progress=pulumi.get(__response__, 'delete_in_progress'),
        domain_ocid=pulumi.get(__response__, 'domain_ocid'),
        id=pulumi.get(__response__, 'id'),
        idcs_created_bies=pulumi.get(__response__, 'idcs_created_bies'),
        idcs_endpoint=pulumi.get(__response__, 'idcs_endpoint'),
        idcs_last_modified_bies=pulumi.get(__response__, 'idcs_last_modified_bies'),
        idcs_last_upgraded_in_release=pulumi.get(__response__, 'idcs_last_upgraded_in_release'),
        idcs_prevented_operations=pulumi.get(__response__, 'idcs_prevented_operations'),
        justification=pulumi.get(__response__, 'justification'),
        metas=pulumi.get(__response__, 'metas'),
        modified_resources=pulumi.get(__response__, 'modified_resources'),
        notification_recipients=pulumi.get(__response__, 'notification_recipients'),
        oci_console_sign_on_policy_consent_id=pulumi.get(__response__, 'oci_console_sign_on_policy_consent_id'),
        ocid=pulumi.get(__response__, 'ocid'),
        policy_resources=pulumi.get(__response__, 'policy_resources'),
        reason=pulumi.get(__response__, 'reason'),
        resource_type_schema_version=pulumi.get(__response__, 'resource_type_schema_version'),
        schemas=pulumi.get(__response__, 'schemas'),
        tags=pulumi.get(__response__, 'tags'),
        tenancy_ocid=pulumi.get(__response__, 'tenancy_ocid'),
        time_consent_signed=pulumi.get(__response__, 'time_consent_signed')))
