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

__all__ = [
    'GetDomainsAccountMgmtInfoResult',
    'AwaitableGetDomainsAccountMgmtInfoResult',
    'get_domains_account_mgmt_info',
    'get_domains_account_mgmt_info_output',
]

@pulumi.output_type
class GetDomainsAccountMgmtInfoResult:
    """
    A collection of values returned by getDomainsAccountMgmtInfo.
    """
    def __init__(__self__, account_mgmt_info_id=None, account_type=None, active=None, apps=None, attribute_sets=None, attributes=None, authorization=None, compartment_ocid=None, composite_key=None, delete_in_progress=None, do_not_back_fill_grants=None, do_not_perform_action_on_target=None, domain_ocid=None, favorite=None, id=None, idcs_created_bies=None, idcs_endpoint=None, idcs_last_modified_bies=None, idcs_last_upgraded_in_release=None, idcs_prevented_operations=None, is_account=None, last_accessed=None, matching_owners=None, metas=None, name=None, object_classes=None, ocid=None, operation_context=None, owners=None, preview_only=None, resource_type_schema_version=None, resource_types=None, schemas=None, sync_response=None, sync_situation=None, sync_timestamp=None, tags=None, tenancy_ocid=None, uid=None, user_wallet_artifacts=None):
        if account_mgmt_info_id and not isinstance(account_mgmt_info_id, str):
            raise TypeError("Expected argument 'account_mgmt_info_id' to be a str")
        pulumi.set(__self__, "account_mgmt_info_id", account_mgmt_info_id)
        if account_type and not isinstance(account_type, str):
            raise TypeError("Expected argument 'account_type' to be a str")
        pulumi.set(__self__, "account_type", account_type)
        if active and not isinstance(active, bool):
            raise TypeError("Expected argument 'active' to be a bool")
        pulumi.set(__self__, "active", active)
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
        if do_not_back_fill_grants and not isinstance(do_not_back_fill_grants, bool):
            raise TypeError("Expected argument 'do_not_back_fill_grants' to be a bool")
        pulumi.set(__self__, "do_not_back_fill_grants", do_not_back_fill_grants)
        if do_not_perform_action_on_target and not isinstance(do_not_perform_action_on_target, bool):
            raise TypeError("Expected argument 'do_not_perform_action_on_target' to be a bool")
        pulumi.set(__self__, "do_not_perform_action_on_target", do_not_perform_action_on_target)
        if domain_ocid and not isinstance(domain_ocid, str):
            raise TypeError("Expected argument 'domain_ocid' to be a str")
        pulumi.set(__self__, "domain_ocid", domain_ocid)
        if favorite and not isinstance(favorite, bool):
            raise TypeError("Expected argument 'favorite' to be a bool")
        pulumi.set(__self__, "favorite", favorite)
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
        if is_account and not isinstance(is_account, bool):
            raise TypeError("Expected argument 'is_account' to be a bool")
        pulumi.set(__self__, "is_account", is_account)
        if last_accessed and not isinstance(last_accessed, str):
            raise TypeError("Expected argument 'last_accessed' to be a str")
        pulumi.set(__self__, "last_accessed", last_accessed)
        if matching_owners and not isinstance(matching_owners, list):
            raise TypeError("Expected argument 'matching_owners' to be a list")
        pulumi.set(__self__, "matching_owners", matching_owners)
        if metas and not isinstance(metas, list):
            raise TypeError("Expected argument 'metas' to be a list")
        pulumi.set(__self__, "metas", metas)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if object_classes and not isinstance(object_classes, list):
            raise TypeError("Expected argument 'object_classes' to be a list")
        pulumi.set(__self__, "object_classes", object_classes)
        if ocid and not isinstance(ocid, str):
            raise TypeError("Expected argument 'ocid' to be a str")
        pulumi.set(__self__, "ocid", ocid)
        if operation_context and not isinstance(operation_context, str):
            raise TypeError("Expected argument 'operation_context' to be a str")
        pulumi.set(__self__, "operation_context", operation_context)
        if owners and not isinstance(owners, list):
            raise TypeError("Expected argument 'owners' to be a list")
        pulumi.set(__self__, "owners", owners)
        if preview_only and not isinstance(preview_only, bool):
            raise TypeError("Expected argument 'preview_only' to be a bool")
        pulumi.set(__self__, "preview_only", preview_only)
        if resource_type_schema_version and not isinstance(resource_type_schema_version, str):
            raise TypeError("Expected argument 'resource_type_schema_version' to be a str")
        pulumi.set(__self__, "resource_type_schema_version", resource_type_schema_version)
        if resource_types and not isinstance(resource_types, list):
            raise TypeError("Expected argument 'resource_types' to be a list")
        pulumi.set(__self__, "resource_types", resource_types)
        if schemas and not isinstance(schemas, list):
            raise TypeError("Expected argument 'schemas' to be a list")
        pulumi.set(__self__, "schemas", schemas)
        if sync_response and not isinstance(sync_response, str):
            raise TypeError("Expected argument 'sync_response' to be a str")
        pulumi.set(__self__, "sync_response", sync_response)
        if sync_situation and not isinstance(sync_situation, str):
            raise TypeError("Expected argument 'sync_situation' to be a str")
        pulumi.set(__self__, "sync_situation", sync_situation)
        if sync_timestamp and not isinstance(sync_timestamp, str):
            raise TypeError("Expected argument 'sync_timestamp' to be a str")
        pulumi.set(__self__, "sync_timestamp", sync_timestamp)
        if tags and not isinstance(tags, list):
            raise TypeError("Expected argument 'tags' to be a list")
        pulumi.set(__self__, "tags", tags)
        if tenancy_ocid and not isinstance(tenancy_ocid, str):
            raise TypeError("Expected argument 'tenancy_ocid' to be a str")
        pulumi.set(__self__, "tenancy_ocid", tenancy_ocid)
        if uid and not isinstance(uid, str):
            raise TypeError("Expected argument 'uid' to be a str")
        pulumi.set(__self__, "uid", uid)
        if user_wallet_artifacts and not isinstance(user_wallet_artifacts, list):
            raise TypeError("Expected argument 'user_wallet_artifacts' to be a list")
        pulumi.set(__self__, "user_wallet_artifacts", user_wallet_artifacts)

    @property
    @pulumi.getter(name="accountMgmtInfoId")
    def account_mgmt_info_id(self) -> str:
        return pulumi.get(self, "account_mgmt_info_id")

    @property
    @pulumi.getter(name="accountType")
    def account_type(self) -> str:
        """
        Type of Account
        """
        return pulumi.get(self, "account_type")

    @property
    @pulumi.getter
    def active(self) -> bool:
        """
        If true, this App is able to participate in runtime services, such as automatic-login, OAuth, and SAML. If false, all runtime services are disabled for this App and only administrative operations can be performed.
        """
        return pulumi.get(self, "active")

    @property
    @pulumi.getter
    def apps(self) -> Sequence['outputs.GetDomainsAccountMgmtInfoAppResult']:
        """
        Application on which the account is based
        """
        return pulumi.get(self, "apps")

    @property
    @pulumi.getter(name="attributeSets")
    def attribute_sets(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "attribute_sets")

    @property
    @pulumi.getter
    def attributes(self) -> Optional[str]:
        return pulumi.get(self, "attributes")

    @property
    @pulumi.getter
    def authorization(self) -> Optional[str]:
        return pulumi.get(self, "authorization")

    @property
    @pulumi.getter(name="compartmentOcid")
    def compartment_ocid(self) -> str:
        """
        Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        """
        return pulumi.get(self, "compartment_ocid")

    @property
    @pulumi.getter(name="compositeKey")
    def composite_key(self) -> str:
        """
        Unique key for this AccountMgmtInfo, which is used to prevent duplicate AccountMgmtInfo resources. Key is composed of a subset of app, owner and accountType.
        """
        return pulumi.get(self, "composite_key")

    @property
    @pulumi.getter(name="deleteInProgress")
    def delete_in_progress(self) -> bool:
        """
        A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
        """
        return pulumi.get(self, "delete_in_progress")

    @property
    @pulumi.getter(name="doNotBackFillGrants")
    def do_not_back_fill_grants(self) -> bool:
        """
        If true, a back-fill grant will not be created for a connected managed app as part of account creation.
        """
        return pulumi.get(self, "do_not_back_fill_grants")

    @property
    @pulumi.getter(name="doNotPerformActionOnTarget")
    def do_not_perform_action_on_target(self) -> bool:
        """
        If true, the operation will not be performed on the target
        """
        return pulumi.get(self, "do_not_perform_action_on_target")

    @property
    @pulumi.getter(name="domainOcid")
    def domain_ocid(self) -> str:
        """
        Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
        """
        return pulumi.get(self, "domain_ocid")

    @property
    @pulumi.getter
    def favorite(self) -> bool:
        """
        If true, this account has been marked as a favorite of the User who owns it
        """
        return pulumi.get(self, "favorite")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="idcsCreatedBies")
    def idcs_created_bies(self) -> Sequence['outputs.GetDomainsAccountMgmtInfoIdcsCreatedByResult']:
        """
        The User or App who created the Resource
        """
        return pulumi.get(self, "idcs_created_bies")

    @property
    @pulumi.getter(name="idcsEndpoint")
    def idcs_endpoint(self) -> str:
        return pulumi.get(self, "idcs_endpoint")

    @property
    @pulumi.getter(name="idcsLastModifiedBies")
    def idcs_last_modified_bies(self) -> Sequence['outputs.GetDomainsAccountMgmtInfoIdcsLastModifiedByResult']:
        """
        The User or App who modified the Resource
        """
        return pulumi.get(self, "idcs_last_modified_bies")

    @property
    @pulumi.getter(name="idcsLastUpgradedInRelease")
    def idcs_last_upgraded_in_release(self) -> str:
        """
        The release number when the resource was upgraded.
        """
        return pulumi.get(self, "idcs_last_upgraded_in_release")

    @property
    @pulumi.getter(name="idcsPreventedOperations")
    def idcs_prevented_operations(self) -> Sequence[str]:
        """
        Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
        """
        return pulumi.get(self, "idcs_prevented_operations")

    @property
    @pulumi.getter(name="isAccount")
    def is_account(self) -> bool:
        """
        If true, indicates that this managed object is an account, which is an identity that represents a user in the context of a specific application
        """
        return pulumi.get(self, "is_account")

    @property
    @pulumi.getter(name="lastAccessed")
    def last_accessed(self) -> str:
        """
        Last accessed timestamp of an application
        """
        return pulumi.get(self, "last_accessed")

    @property
    @pulumi.getter(name="matchingOwners")
    def matching_owners(self) -> Sequence['outputs.GetDomainsAccountMgmtInfoMatchingOwnerResult']:
        """
        Matching owning users of the account
        """
        return pulumi.get(self, "matching_owners")

    @property
    @pulumi.getter
    def metas(self) -> Sequence['outputs.GetDomainsAccountMgmtInfoMetaResult']:
        """
        A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        """
        return pulumi.get(self, "metas")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Name of the Account
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="objectClasses")
    def object_classes(self) -> Sequence['outputs.GetDomainsAccountMgmtInfoObjectClassResult']:
        """
        Object-class of the Account
        """
        return pulumi.get(self, "object_classes")

    @property
    @pulumi.getter
    def ocid(self) -> str:
        """
        Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
        """
        return pulumi.get(self, "ocid")

    @property
    @pulumi.getter(name="operationContext")
    def operation_context(self) -> str:
        """
        The context in which the operation is performed on the account.
        """
        return pulumi.get(self, "operation_context")

    @property
    @pulumi.getter
    def owners(self) -> Sequence['outputs.GetDomainsAccountMgmtInfoOwnerResult']:
        """
        Owning user of the account
        """
        return pulumi.get(self, "owners")

    @property
    @pulumi.getter(name="previewOnly")
    def preview_only(self) -> bool:
        """
        If true, then the response to the account creation operation on a connected managed app returns a preview of the account data that is evaluated by the attribute value generation policy. Note that an account will not be created on the target application when this attribute is set to true.
        """
        return pulumi.get(self, "preview_only")

    @property
    @pulumi.getter(name="resourceTypeSchemaVersion")
    def resource_type_schema_version(self) -> Optional[str]:
        return pulumi.get(self, "resource_type_schema_version")

    @property
    @pulumi.getter(name="resourceTypes")
    def resource_types(self) -> Sequence['outputs.GetDomainsAccountMgmtInfoResourceTypeResult']:
        """
        Resource Type of the Account
        """
        return pulumi.get(self, "resource_types")

    @property
    @pulumi.getter
    def schemas(self) -> Sequence[str]:
        """
        REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \\"enterprise\\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
        """
        return pulumi.get(self, "schemas")

    @property
    @pulumi.getter(name="syncResponse")
    def sync_response(self) -> str:
        """
        Last recorded sync response for the account
        """
        return pulumi.get(self, "sync_response")

    @property
    @pulumi.getter(name="syncSituation")
    def sync_situation(self) -> str:
        """
        Last recorded sync situation for the account
        """
        return pulumi.get(self, "sync_situation")

    @property
    @pulumi.getter(name="syncTimestamp")
    def sync_timestamp(self) -> str:
        """
        Last sync timestamp of the account
        """
        return pulumi.get(self, "sync_timestamp")

    @property
    @pulumi.getter
    def tags(self) -> Sequence['outputs.GetDomainsAccountMgmtInfoTagResult']:
        """
        A list of tags on this resource.
        """
        return pulumi.get(self, "tags")

    @property
    @pulumi.getter(name="tenancyOcid")
    def tenancy_ocid(self) -> str:
        """
        Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        """
        return pulumi.get(self, "tenancy_ocid")

    @property
    @pulumi.getter
    def uid(self) -> str:
        """
        Unique identifier of the Account
        """
        return pulumi.get(self, "uid")

    @property
    @pulumi.getter(name="userWalletArtifacts")
    def user_wallet_artifacts(self) -> Sequence['outputs.GetDomainsAccountMgmtInfoUserWalletArtifactResult']:
        """
        The UserWalletArtifact that contains the credentials that the system will use when performing Secure Form-Fill to log the user in to this application
        """
        return pulumi.get(self, "user_wallet_artifacts")


class AwaitableGetDomainsAccountMgmtInfoResult(GetDomainsAccountMgmtInfoResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDomainsAccountMgmtInfoResult(
            account_mgmt_info_id=self.account_mgmt_info_id,
            account_type=self.account_type,
            active=self.active,
            apps=self.apps,
            attribute_sets=self.attribute_sets,
            attributes=self.attributes,
            authorization=self.authorization,
            compartment_ocid=self.compartment_ocid,
            composite_key=self.composite_key,
            delete_in_progress=self.delete_in_progress,
            do_not_back_fill_grants=self.do_not_back_fill_grants,
            do_not_perform_action_on_target=self.do_not_perform_action_on_target,
            domain_ocid=self.domain_ocid,
            favorite=self.favorite,
            id=self.id,
            idcs_created_bies=self.idcs_created_bies,
            idcs_endpoint=self.idcs_endpoint,
            idcs_last_modified_bies=self.idcs_last_modified_bies,
            idcs_last_upgraded_in_release=self.idcs_last_upgraded_in_release,
            idcs_prevented_operations=self.idcs_prevented_operations,
            is_account=self.is_account,
            last_accessed=self.last_accessed,
            matching_owners=self.matching_owners,
            metas=self.metas,
            name=self.name,
            object_classes=self.object_classes,
            ocid=self.ocid,
            operation_context=self.operation_context,
            owners=self.owners,
            preview_only=self.preview_only,
            resource_type_schema_version=self.resource_type_schema_version,
            resource_types=self.resource_types,
            schemas=self.schemas,
            sync_response=self.sync_response,
            sync_situation=self.sync_situation,
            sync_timestamp=self.sync_timestamp,
            tags=self.tags,
            tenancy_ocid=self.tenancy_ocid,
            uid=self.uid,
            user_wallet_artifacts=self.user_wallet_artifacts)


def get_domains_account_mgmt_info(account_mgmt_info_id: Optional[str] = None,
                                  attribute_sets: Optional[Sequence[str]] = None,
                                  attributes: Optional[str] = None,
                                  authorization: Optional[str] = None,
                                  idcs_endpoint: Optional[str] = None,
                                  resource_type_schema_version: Optional[str] = None,
                                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDomainsAccountMgmtInfoResult:
    """
    This data source provides details about a specific Account Mgmt Info resource in Oracle Cloud Infrastructure Identity Domains service.

    Get Account Mgmt Info

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_account_mgmt_info = oci.Identity.get_domains_account_mgmt_info(account_mgmt_info_id=oci_identity_domains_account_mgmt_info["test_account_mgmt_info"]["id"],
        idcs_endpoint=data["oci_identity_domain"]["test_domain"]["url"],
        attribute_sets=["all"],
        attributes="",
        authorization=var["account_mgmt_info_authorization"],
        resource_type_schema_version=var["account_mgmt_info_resource_type_schema_version"])
    ```


    :param str account_mgmt_info_id: ID of the resource
    :param Sequence[str] attribute_sets: A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
    :param str attributes: A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
    :param str authorization: The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
    :param str idcs_endpoint: The basic endpoint for the identity domain
    :param str resource_type_schema_version: An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
    """
    __args__ = dict()
    __args__['accountMgmtInfoId'] = account_mgmt_info_id
    __args__['attributeSets'] = attribute_sets
    __args__['attributes'] = attributes
    __args__['authorization'] = authorization
    __args__['idcsEndpoint'] = idcs_endpoint
    __args__['resourceTypeSchemaVersion'] = resource_type_schema_version
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Identity/getDomainsAccountMgmtInfo:getDomainsAccountMgmtInfo', __args__, opts=opts, typ=GetDomainsAccountMgmtInfoResult).value

    return AwaitableGetDomainsAccountMgmtInfoResult(
        account_mgmt_info_id=pulumi.get(__ret__, 'account_mgmt_info_id'),
        account_type=pulumi.get(__ret__, 'account_type'),
        active=pulumi.get(__ret__, 'active'),
        apps=pulumi.get(__ret__, 'apps'),
        attribute_sets=pulumi.get(__ret__, 'attribute_sets'),
        attributes=pulumi.get(__ret__, 'attributes'),
        authorization=pulumi.get(__ret__, 'authorization'),
        compartment_ocid=pulumi.get(__ret__, 'compartment_ocid'),
        composite_key=pulumi.get(__ret__, 'composite_key'),
        delete_in_progress=pulumi.get(__ret__, 'delete_in_progress'),
        do_not_back_fill_grants=pulumi.get(__ret__, 'do_not_back_fill_grants'),
        do_not_perform_action_on_target=pulumi.get(__ret__, 'do_not_perform_action_on_target'),
        domain_ocid=pulumi.get(__ret__, 'domain_ocid'),
        favorite=pulumi.get(__ret__, 'favorite'),
        id=pulumi.get(__ret__, 'id'),
        idcs_created_bies=pulumi.get(__ret__, 'idcs_created_bies'),
        idcs_endpoint=pulumi.get(__ret__, 'idcs_endpoint'),
        idcs_last_modified_bies=pulumi.get(__ret__, 'idcs_last_modified_bies'),
        idcs_last_upgraded_in_release=pulumi.get(__ret__, 'idcs_last_upgraded_in_release'),
        idcs_prevented_operations=pulumi.get(__ret__, 'idcs_prevented_operations'),
        is_account=pulumi.get(__ret__, 'is_account'),
        last_accessed=pulumi.get(__ret__, 'last_accessed'),
        matching_owners=pulumi.get(__ret__, 'matching_owners'),
        metas=pulumi.get(__ret__, 'metas'),
        name=pulumi.get(__ret__, 'name'),
        object_classes=pulumi.get(__ret__, 'object_classes'),
        ocid=pulumi.get(__ret__, 'ocid'),
        operation_context=pulumi.get(__ret__, 'operation_context'),
        owners=pulumi.get(__ret__, 'owners'),
        preview_only=pulumi.get(__ret__, 'preview_only'),
        resource_type_schema_version=pulumi.get(__ret__, 'resource_type_schema_version'),
        resource_types=pulumi.get(__ret__, 'resource_types'),
        schemas=pulumi.get(__ret__, 'schemas'),
        sync_response=pulumi.get(__ret__, 'sync_response'),
        sync_situation=pulumi.get(__ret__, 'sync_situation'),
        sync_timestamp=pulumi.get(__ret__, 'sync_timestamp'),
        tags=pulumi.get(__ret__, 'tags'),
        tenancy_ocid=pulumi.get(__ret__, 'tenancy_ocid'),
        uid=pulumi.get(__ret__, 'uid'),
        user_wallet_artifacts=pulumi.get(__ret__, 'user_wallet_artifacts'))


@_utilities.lift_output_func(get_domains_account_mgmt_info)
def get_domains_account_mgmt_info_output(account_mgmt_info_id: Optional[pulumi.Input[str]] = None,
                                         attribute_sets: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                                         attributes: Optional[pulumi.Input[Optional[str]]] = None,
                                         authorization: Optional[pulumi.Input[Optional[str]]] = None,
                                         idcs_endpoint: Optional[pulumi.Input[str]] = None,
                                         resource_type_schema_version: Optional[pulumi.Input[Optional[str]]] = None,
                                         opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetDomainsAccountMgmtInfoResult]:
    """
    This data source provides details about a specific Account Mgmt Info resource in Oracle Cloud Infrastructure Identity Domains service.

    Get Account Mgmt Info

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_account_mgmt_info = oci.Identity.get_domains_account_mgmt_info(account_mgmt_info_id=oci_identity_domains_account_mgmt_info["test_account_mgmt_info"]["id"],
        idcs_endpoint=data["oci_identity_domain"]["test_domain"]["url"],
        attribute_sets=["all"],
        attributes="",
        authorization=var["account_mgmt_info_authorization"],
        resource_type_schema_version=var["account_mgmt_info_resource_type_schema_version"])
    ```


    :param str account_mgmt_info_id: ID of the resource
    :param Sequence[str] attribute_sets: A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
    :param str attributes: A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
    :param str authorization: The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
    :param str idcs_endpoint: The basic endpoint for the identity domain
    :param str resource_type_schema_version: An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
    """
    ...