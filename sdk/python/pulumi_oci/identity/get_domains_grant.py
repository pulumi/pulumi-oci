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
    'GetDomainsGrantResult',
    'AwaitableGetDomainsGrantResult',
    'get_domains_grant',
    'get_domains_grant_output',
]

@pulumi.output_type
class GetDomainsGrantResult:
    """
    A collection of values returned by getDomainsGrant.
    """
    def __init__(__self__, app_entitlement_collections=None, apps=None, attribute_sets=None, attributes=None, authorization=None, compartment_ocid=None, composite_key=None, delete_in_progress=None, domain_ocid=None, entitlements=None, grant_id=None, grant_mechanism=None, granted_attribute_values_json=None, grantees=None, grantors=None, id=None, idcs_created_bies=None, idcs_endpoint=None, idcs_last_modified_bies=None, idcs_last_upgraded_in_release=None, idcs_prevented_operations=None, is_fulfilled=None, metas=None, ocid=None, resource_type_schema_version=None, schemas=None, tags=None, tenancy_ocid=None):
        if app_entitlement_collections and not isinstance(app_entitlement_collections, list):
            raise TypeError("Expected argument 'app_entitlement_collections' to be a list")
        pulumi.set(__self__, "app_entitlement_collections", app_entitlement_collections)
        if apps and not isinstance(apps, list):
            raise TypeError("Expected argument 'apps' to be a list")
        pulumi.set(__self__, "apps", apps)
        if attribute_sets and not isinstance(attribute_sets, list):
            raise TypeError("Expected argument 'attribute_sets' to be a list")
        pulumi.set(__self__, "attribute_sets", attribute_sets)
        if attributes and not isinstance(attributes, str):
            raise TypeError("Expected argument 'attributes' to be a str")
        pulumi.set(__self__, "attributes", attributes)
        if authorization and not isinstance(authorization, str):
            raise TypeError("Expected argument 'authorization' to be a str")
        pulumi.set(__self__, "authorization", authorization)
        if compartment_ocid and not isinstance(compartment_ocid, str):
            raise TypeError("Expected argument 'compartment_ocid' to be a str")
        pulumi.set(__self__, "compartment_ocid", compartment_ocid)
        if composite_key and not isinstance(composite_key, str):
            raise TypeError("Expected argument 'composite_key' to be a str")
        pulumi.set(__self__, "composite_key", composite_key)
        if delete_in_progress and not isinstance(delete_in_progress, bool):
            raise TypeError("Expected argument 'delete_in_progress' to be a bool")
        pulumi.set(__self__, "delete_in_progress", delete_in_progress)
        if domain_ocid and not isinstance(domain_ocid, str):
            raise TypeError("Expected argument 'domain_ocid' to be a str")
        pulumi.set(__self__, "domain_ocid", domain_ocid)
        if entitlements and not isinstance(entitlements, list):
            raise TypeError("Expected argument 'entitlements' to be a list")
        pulumi.set(__self__, "entitlements", entitlements)
        if grant_id and not isinstance(grant_id, str):
            raise TypeError("Expected argument 'grant_id' to be a str")
        pulumi.set(__self__, "grant_id", grant_id)
        if grant_mechanism and not isinstance(grant_mechanism, str):
            raise TypeError("Expected argument 'grant_mechanism' to be a str")
        pulumi.set(__self__, "grant_mechanism", grant_mechanism)
        if granted_attribute_values_json and not isinstance(granted_attribute_values_json, str):
            raise TypeError("Expected argument 'granted_attribute_values_json' to be a str")
        pulumi.set(__self__, "granted_attribute_values_json", granted_attribute_values_json)
        if grantees and not isinstance(grantees, list):
            raise TypeError("Expected argument 'grantees' to be a list")
        pulumi.set(__self__, "grantees", grantees)
        if grantors and not isinstance(grantors, list):
            raise TypeError("Expected argument 'grantors' to be a list")
        pulumi.set(__self__, "grantors", grantors)
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
        if is_fulfilled and not isinstance(is_fulfilled, bool):
            raise TypeError("Expected argument 'is_fulfilled' to be a bool")
        pulumi.set(__self__, "is_fulfilled", is_fulfilled)
        if metas and not isinstance(metas, list):
            raise TypeError("Expected argument 'metas' to be a list")
        pulumi.set(__self__, "metas", metas)
        if ocid and not isinstance(ocid, str):
            raise TypeError("Expected argument 'ocid' to be a str")
        pulumi.set(__self__, "ocid", ocid)
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

    @_builtins.property
    @pulumi.getter(name="appEntitlementCollections")
    def app_entitlement_collections(self) -> Sequence['outputs.GetDomainsGrantAppEntitlementCollectionResult']:
        """
        Application-Entitlement-Collection that is being granted. Each Grant must grant either an App or an App-Entitlement-Collection.
        """
        return pulumi.get(self, "app_entitlement_collections")

    @_builtins.property
    @pulumi.getter
    def apps(self) -> Sequence['outputs.GetDomainsGrantAppResult']:
        """
        Application that is being granted. Each Grant must grant either an App or an App-Entitlement-Collection.
        """
        return pulumi.get(self, "apps")

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
    @pulumi.getter(name="compartmentOcid")
    def compartment_ocid(self) -> _builtins.str:
        """
        Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        """
        return pulumi.get(self, "compartment_ocid")

    @_builtins.property
    @pulumi.getter(name="compositeKey")
    def composite_key(self) -> _builtins.str:
        """
        Unique key of grant, composed by combining a subset of app, entitlement, grantee, grantor and grantMechanism.  Used to prevent duplicate Grants.
        """
        return pulumi.get(self, "composite_key")

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
    def entitlements(self) -> Sequence['outputs.GetDomainsGrantEntitlementResult']:
        """
        The entitlement or privilege that is being granted
        """
        return pulumi.get(self, "entitlements")

    @_builtins.property
    @pulumi.getter(name="grantId")
    def grant_id(self) -> _builtins.str:
        return pulumi.get(self, "grant_id")

    @_builtins.property
    @pulumi.getter(name="grantMechanism")
    def grant_mechanism(self) -> _builtins.str:
        """
        Each value of grantMechanism indicates how (or by what component) some App (or App-Entitlement) was granted. A customer or the UI should use only grantMechanism values that start with 'ADMINISTRATOR':
        * 'ADMINISTRATOR_TO_USER' is for a direct grant to a specific User.
        * 'ADMINISTRATOR_TO_GROUP' is for a grant to a specific Group, which results in indirect grants to Users who are members of that Group.
        * 'ADMINISTRATOR_TO_APP' is for a grant to a specific App.  The grantee (client) App gains access to the granted (server) App.
        """
        return pulumi.get(self, "grant_mechanism")

    @_builtins.property
    @pulumi.getter(name="grantedAttributeValuesJson")
    def granted_attribute_values_json(self) -> _builtins.str:
        """
        Store granted attribute-values as a string in Javascript Object Notation (JSON) format.
        """
        return pulumi.get(self, "granted_attribute_values_json")

    @_builtins.property
    @pulumi.getter
    def grantees(self) -> Sequence['outputs.GetDomainsGrantGranteeResult']:
        """
        Grantee beneficiary. The grantee may be a User, Group, App or DynamicResourceGroup.
        """
        return pulumi.get(self, "grantees")

    @_builtins.property
    @pulumi.getter
    def grantors(self) -> Sequence['outputs.GetDomainsGrantGrantorResult']:
        """
        User conferring the grant to the beneficiary
        """
        return pulumi.get(self, "grantors")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="idcsCreatedBies")
    def idcs_created_bies(self) -> Sequence['outputs.GetDomainsGrantIdcsCreatedByResult']:
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
    def idcs_last_modified_bies(self) -> Sequence['outputs.GetDomainsGrantIdcsLastModifiedByResult']:
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
    @pulumi.getter(name="isFulfilled")
    def is_fulfilled(self) -> _builtins.bool:
        """
        If true, this Grant has been fulfilled successfully.
        """
        return pulumi.get(self, "is_fulfilled")

    @_builtins.property
    @pulumi.getter
    def metas(self) -> Sequence['outputs.GetDomainsGrantMetaResult']:
        """
        A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        """
        return pulumi.get(self, "metas")

    @_builtins.property
    @pulumi.getter
    def ocid(self) -> _builtins.str:
        """
        Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
        """
        return pulumi.get(self, "ocid")

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
    def tags(self) -> Sequence['outputs.GetDomainsGrantTagResult']:
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


class AwaitableGetDomainsGrantResult(GetDomainsGrantResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDomainsGrantResult(
            app_entitlement_collections=self.app_entitlement_collections,
            apps=self.apps,
            attribute_sets=self.attribute_sets,
            attributes=self.attributes,
            authorization=self.authorization,
            compartment_ocid=self.compartment_ocid,
            composite_key=self.composite_key,
            delete_in_progress=self.delete_in_progress,
            domain_ocid=self.domain_ocid,
            entitlements=self.entitlements,
            grant_id=self.grant_id,
            grant_mechanism=self.grant_mechanism,
            granted_attribute_values_json=self.granted_attribute_values_json,
            grantees=self.grantees,
            grantors=self.grantors,
            id=self.id,
            idcs_created_bies=self.idcs_created_bies,
            idcs_endpoint=self.idcs_endpoint,
            idcs_last_modified_bies=self.idcs_last_modified_bies,
            idcs_last_upgraded_in_release=self.idcs_last_upgraded_in_release,
            idcs_prevented_operations=self.idcs_prevented_operations,
            is_fulfilled=self.is_fulfilled,
            metas=self.metas,
            ocid=self.ocid,
            resource_type_schema_version=self.resource_type_schema_version,
            schemas=self.schemas,
            tags=self.tags,
            tenancy_ocid=self.tenancy_ocid)


def get_domains_grant(attribute_sets: Optional[Sequence[_builtins.str]] = None,
                      attributes: Optional[_builtins.str] = None,
                      authorization: Optional[_builtins.str] = None,
                      grant_id: Optional[_builtins.str] = None,
                      idcs_endpoint: Optional[_builtins.str] = None,
                      resource_type_schema_version: Optional[_builtins.str] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDomainsGrantResult:
    """
    This data source provides details about a specific Grant resource in Oracle Cloud Infrastructure Identity Domains service.

    Get a Grant

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_grant = oci.Identity.get_domains_grant(grant_id=test_grant_oci_identity_domains_grant["id"],
        idcs_endpoint=test_domain["url"],
        attribute_sets=["all"],
        attributes="",
        authorization=grant_authorization,
        resource_type_schema_version=grant_resource_type_schema_version)
    ```


    :param Sequence[_builtins.str] attribute_sets: A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
    :param _builtins.str attributes: A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
    :param _builtins.str authorization: The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
    :param _builtins.str grant_id: ID of the resource
    :param _builtins.str idcs_endpoint: The basic endpoint for the identity domain
    :param _builtins.str resource_type_schema_version: An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
    """
    __args__ = dict()
    __args__['attributeSets'] = attribute_sets
    __args__['attributes'] = attributes
    __args__['authorization'] = authorization
    __args__['grantId'] = grant_id
    __args__['idcsEndpoint'] = idcs_endpoint
    __args__['resourceTypeSchemaVersion'] = resource_type_schema_version
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Identity/getDomainsGrant:getDomainsGrant', __args__, opts=opts, typ=GetDomainsGrantResult).value

    return AwaitableGetDomainsGrantResult(
        app_entitlement_collections=pulumi.get(__ret__, 'app_entitlement_collections'),
        apps=pulumi.get(__ret__, 'apps'),
        attribute_sets=pulumi.get(__ret__, 'attribute_sets'),
        attributes=pulumi.get(__ret__, 'attributes'),
        authorization=pulumi.get(__ret__, 'authorization'),
        compartment_ocid=pulumi.get(__ret__, 'compartment_ocid'),
        composite_key=pulumi.get(__ret__, 'composite_key'),
        delete_in_progress=pulumi.get(__ret__, 'delete_in_progress'),
        domain_ocid=pulumi.get(__ret__, 'domain_ocid'),
        entitlements=pulumi.get(__ret__, 'entitlements'),
        grant_id=pulumi.get(__ret__, 'grant_id'),
        grant_mechanism=pulumi.get(__ret__, 'grant_mechanism'),
        granted_attribute_values_json=pulumi.get(__ret__, 'granted_attribute_values_json'),
        grantees=pulumi.get(__ret__, 'grantees'),
        grantors=pulumi.get(__ret__, 'grantors'),
        id=pulumi.get(__ret__, 'id'),
        idcs_created_bies=pulumi.get(__ret__, 'idcs_created_bies'),
        idcs_endpoint=pulumi.get(__ret__, 'idcs_endpoint'),
        idcs_last_modified_bies=pulumi.get(__ret__, 'idcs_last_modified_bies'),
        idcs_last_upgraded_in_release=pulumi.get(__ret__, 'idcs_last_upgraded_in_release'),
        idcs_prevented_operations=pulumi.get(__ret__, 'idcs_prevented_operations'),
        is_fulfilled=pulumi.get(__ret__, 'is_fulfilled'),
        metas=pulumi.get(__ret__, 'metas'),
        ocid=pulumi.get(__ret__, 'ocid'),
        resource_type_schema_version=pulumi.get(__ret__, 'resource_type_schema_version'),
        schemas=pulumi.get(__ret__, 'schemas'),
        tags=pulumi.get(__ret__, 'tags'),
        tenancy_ocid=pulumi.get(__ret__, 'tenancy_ocid'))
def get_domains_grant_output(attribute_sets: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                             attributes: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                             authorization: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                             grant_id: Optional[pulumi.Input[_builtins.str]] = None,
                             idcs_endpoint: Optional[pulumi.Input[_builtins.str]] = None,
                             resource_type_schema_version: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                             opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDomainsGrantResult]:
    """
    This data source provides details about a specific Grant resource in Oracle Cloud Infrastructure Identity Domains service.

    Get a Grant

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_grant = oci.Identity.get_domains_grant(grant_id=test_grant_oci_identity_domains_grant["id"],
        idcs_endpoint=test_domain["url"],
        attribute_sets=["all"],
        attributes="",
        authorization=grant_authorization,
        resource_type_schema_version=grant_resource_type_schema_version)
    ```


    :param Sequence[_builtins.str] attribute_sets: A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
    :param _builtins.str attributes: A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
    :param _builtins.str authorization: The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
    :param _builtins.str grant_id: ID of the resource
    :param _builtins.str idcs_endpoint: The basic endpoint for the identity domain
    :param _builtins.str resource_type_schema_version: An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
    """
    __args__ = dict()
    __args__['attributeSets'] = attribute_sets
    __args__['attributes'] = attributes
    __args__['authorization'] = authorization
    __args__['grantId'] = grant_id
    __args__['idcsEndpoint'] = idcs_endpoint
    __args__['resourceTypeSchemaVersion'] = resource_type_schema_version
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Identity/getDomainsGrant:getDomainsGrant', __args__, opts=opts, typ=GetDomainsGrantResult)
    return __ret__.apply(lambda __response__: GetDomainsGrantResult(
        app_entitlement_collections=pulumi.get(__response__, 'app_entitlement_collections'),
        apps=pulumi.get(__response__, 'apps'),
        attribute_sets=pulumi.get(__response__, 'attribute_sets'),
        attributes=pulumi.get(__response__, 'attributes'),
        authorization=pulumi.get(__response__, 'authorization'),
        compartment_ocid=pulumi.get(__response__, 'compartment_ocid'),
        composite_key=pulumi.get(__response__, 'composite_key'),
        delete_in_progress=pulumi.get(__response__, 'delete_in_progress'),
        domain_ocid=pulumi.get(__response__, 'domain_ocid'),
        entitlements=pulumi.get(__response__, 'entitlements'),
        grant_id=pulumi.get(__response__, 'grant_id'),
        grant_mechanism=pulumi.get(__response__, 'grant_mechanism'),
        granted_attribute_values_json=pulumi.get(__response__, 'granted_attribute_values_json'),
        grantees=pulumi.get(__response__, 'grantees'),
        grantors=pulumi.get(__response__, 'grantors'),
        id=pulumi.get(__response__, 'id'),
        idcs_created_bies=pulumi.get(__response__, 'idcs_created_bies'),
        idcs_endpoint=pulumi.get(__response__, 'idcs_endpoint'),
        idcs_last_modified_bies=pulumi.get(__response__, 'idcs_last_modified_bies'),
        idcs_last_upgraded_in_release=pulumi.get(__response__, 'idcs_last_upgraded_in_release'),
        idcs_prevented_operations=pulumi.get(__response__, 'idcs_prevented_operations'),
        is_fulfilled=pulumi.get(__response__, 'is_fulfilled'),
        metas=pulumi.get(__response__, 'metas'),
        ocid=pulumi.get(__response__, 'ocid'),
        resource_type_schema_version=pulumi.get(__response__, 'resource_type_schema_version'),
        schemas=pulumi.get(__response__, 'schemas'),
        tags=pulumi.get(__response__, 'tags'),
        tenancy_ocid=pulumi.get(__response__, 'tenancy_ocid')))
